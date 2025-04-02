#include <gtk/gtk.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <libgen.h>
#include <sys/stat.h>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cerrno>
#include <openssl/md5.h>
#include <algorithm>
#include <stdexcept>
#include <fcntl.h>
#include "encryption.h"
#include "decryption.h"
#include "utils.h"
#include "rsa_core.h"

#define DEFAULT_SERVER_IP "127.0.0.1"
#define PORT 8080
#define CLIENT_PORT 8081
#define BUFFER_SIZE 1024
#define RECEIVED_DIR "received_files"
#define DECRYPTED_DIR "decrypted_files"
#define CHECKSUM_BUFFER_SIZE 8192
#define KEY_MARKER "PUBLIC_KEY_TRANSFER_V2"
#define TRANSMISSION_END_MARKER "END_OF_TRANSMISSION"
#define SOCKET_TIMEOUT_SEC 360

GtkWidget *status_label;
GtkWidget *select_button;
GtkWidget *send_button;
GtkWidget *server_ip_entry;
GtkWidget *log_view;
GtkWidget *file_path_label;
GtkTextBuffer *log_buffer;
std::string selected_file_path;

GtkWidget *listen_button;
GtkWidget *stop_listen_button;
GtkWidget *view_encrypted_button;
GtkWidget *view_encrypted_key_button;
GtkWidget *decrypt_rsa_button;
GtkWidget *decrypt_button;
GtkWidget *view_decrypted_button;
GtkWidget *load_pubkey_button;
GtkWidget *generate_keys_button;
GtkWidget *send_pubkey_button;
GtkWidget *view_pubkey_button;

int client_server_fd = -1;
bool client_server_running = false;
std::thread client_server_thread;
std::string last_encrypted_file;
std::string last_original_filename;
std::string last_decrypted_file;
bool file_received = false;
bool file_decrypted = false;

RSAKey server_public_key;
RSAKey client_public_key;
RSAKey client_private_key;
bool has_server_public_key = false;
bool has_client_keys = false;

std::vector<uint8_t> decrypted_des_key;
bool has_decrypted_des_key = false;

std::string calculateMD5Checksum(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        return "";
    }
    
    MD5_CTX md5Context;
    MD5_Init(&md5Context);
    
    char buffer[CHECKSUM_BUFFER_SIZE];
    while (file.good()) {
        file.read(buffer, sizeof(buffer));
        MD5_Update(&md5Context, buffer, file.gcount());
    }
    
    unsigned char result[MD5_DIGEST_LENGTH];
    MD5_Final(result, &md5Context);
    
    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)result[i];
    }
    
    return ss.str();
}

bool compareVectors(const std::vector<uint8_t>& v1, const std::vector<uint8_t>& v2) {
    if (v1.size() != v2.size()) {
        return false;
    }
    return std::equal(v1.begin(), v1.end(), v2.begin());
}

void setSocketTimeout(int sockfd, int seconds) {
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        throw std::runtime_error("Không thể thiết lập timeout cho socket");
    }
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        throw std::runtime_error("Không thể thiết lập timeout cho socket");
    }
}

void ensure_directory_exists(const std::string& dir) {
    struct stat st = {0};
    if (stat(dir.c_str(), &st) == -1) {
        mkdir(dir.c_str(), 0700);
        std::cout << "📁 Đã tạo thư mục: " << dir << std::endl;
    }
}

static gboolean update_log(gpointer data) {
    const gchar *message = (const gchar*)data;
    GtkTextIter iter;
    gtk_text_buffer_get_end_iter(log_buffer, &iter);
    gtk_text_buffer_insert(log_buffer, &iter, message, -1);
    gtk_text_buffer_insert(log_buffer, &iter, "\n", -1);
    gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(log_view), gtk_text_buffer_get_insert(log_buffer), 0.0, TRUE, 0.5, 0.5);
    g_free((gchar*)data);
    return FALSE;
}

void add_log(const std::string& message) {
    gdk_threads_add_idle(update_log, g_strdup(message.c_str()));
}

void load_server_public_key(const std::string& filename) {
    initRSAKey(server_public_key);
    if (loadRSAPublicKey(server_public_key, filename)) {
        has_server_public_key = true;
        add_log("✅ Đã tải public key của server từ: " + filename);
    } else {
        add_log("❌ Không thể tải public key từ file: " + filename);
    }
}

void generate_client_keys() {
    add_log("🔑 Đang tạo cặp khóa RSA cho client...");
    
    RSAKeyPair keyPair = generateRSAKeyPair(1024);
    
    client_public_key = keyPair.publicKey;
    client_private_key = keyPair.privateKey;
    
    saveRSAPublicKey(client_public_key, "client_public.key");
    saveRSAPrivateKey(client_private_key, "client_private.key");
    
    has_client_keys = true;
    add_log("✅ Đã tạo và lưu cặp khóa RSA cho client");
    add_log("📁 Public key: client_public.key");
    add_log("📁 Private key: client_private.key");
    
    gtk_widget_set_sensitive(send_pubkey_button, TRUE);
    gtk_widget_set_sensitive(view_pubkey_button, TRUE);
}

void load_client_keys() {
    initRSAKey(client_public_key);
    initRSAKey(client_private_key);
    
    bool loaded_public = loadRSAPublicKey(client_public_key, "client_public.key");
    bool loaded_private = loadRSAPrivateKey(client_private_key, "client_private.key");
    
    if (loaded_public && loaded_private) {
        has_client_keys = true;
        add_log("✅ Đã tải cặp khóa RSA của client");
        gtk_widget_set_sensitive(send_pubkey_button, TRUE);
        gtk_widget_set_sensitive(view_pubkey_button, TRUE);
    } else {
        add_log("❌ Không thể tải cặp khóa RSA của client");
    }
}

void send_public_key_thread(const std::string& server_ip) {
    add_log("🔄 Bắt đầu gửi client public key đến server " + server_ip);
    add_log("🔄 Tạo socket để gửi client public key...");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        add_log("❌ Tạo socket thất bại! Lỗi: " + std::string(strerror(errno)));
        return;
    }
    
    try {
        setSocketTimeout(sock, SOCKET_TIMEOUT_SEC);
        
        // Kết nối đến SERVER qua port 8080
        add_log("🔄 Chuẩn bị kết nối đến server " + server_ip + ":" + std::to_string(PORT));
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(PORT);  // PORT = 8080 (server port)
        if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
            add_log("❌ Địa chỉ IP server không hợp lệ! Lỗi: " + std::string(strerror(errno)));
            close(sock);
            return;
        }
        
        add_log("🔄 Đang kết nối đến server...");
        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            add_log("❌ Kết nối đến server thất bại! Lỗi: " + std::string(strerror(errno)));
            add_log("Địa chỉ: " + server_ip + ", Cổng: " + std::to_string(PORT));
            close(sock);
            return;
        }
        
        add_log("✅ Đã kết nối đến server để gửi client public key!");
        
        // Gửi marker - Sử dụng marker riêng cho client public key
        std::string key_marker = "CLIENT_PUBLIC_KEY_TRANSFER";
        if (send(sock, key_marker.c_str(), key_marker.size(), 0) != (ssize_t)key_marker.size()) {
            add_log("❌ Lỗi khi gửi key marker! Lỗi: " + std::string(strerror(errno)));
            close(sock);
            return;
        }
        
        usleep(100000);  // 100ms delay
        
        // Chờ phản hồi READY từ server
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        
        add_log("🔄 Đang chờ phản hồi từ server...");
        if (select(sock + 1, &readfds, NULL, NULL, &tv) <= 0) {
            add_log("❌ Timeout khi chờ phản hồi từ server!");
            close(sock);
            return;
        }
        
        char response[128] = {0};
        if (recv(sock, response, sizeof(response) - 1, 0) <= 0) {
            add_log("❌ Không nhận được phản hồi từ server! Lỗi: " + std::string(strerror(errno)));
            close(sock);
            return;
        }
        
        if (std::string(response) != "READY") {
            add_log("❌ Server không sẵn sàng nhận key! Phản hồi: " + std::string(response));
            close(sock);
            return;
        }
        
        // Đọc file client_public.key
        std::ifstream key_file("client_public.key", std::ios::binary);
        if (!key_file) {
            add_log("❌ Không thể mở file client_public.key!");
            close(sock);
            return;
        }
        
        // Đọc nội dung file vào buffer
        key_file.seekg(0, std::ios::end);
        size_t file_size = key_file.tellg();
        key_file.seekg(0, std::ios::beg);
        
        // Kiểm tra kích thước file
        if (file_size <= 0 || file_size > 10000) {
            add_log("❌ Kích thước file key không hợp lệ: " + std::to_string(file_size) + " bytes");
            close(sock);
            return;
        }
        
        std::string key_content(file_size, '\0');
        key_file.read(&key_content[0], file_size);
        key_file.close();
        
        std::string checksum = calculateMD5Checksum("client_public.key");
        add_log("🔐 MD5 checksum của client public key: " + checksum);
        
        // Gửi kích thước key (network byte order)
        uint32_t key_size = htonl(file_size);
        if (send(sock, &key_size, sizeof(key_size), 0) != sizeof(key_size)) {
            add_log("❌ Lỗi khi gửi kích thước key! Lỗi: " + std::string(strerror(errno)));
            close(sock);
            return;
        }
        
        // Chờ xác nhận kích thước từ server
        memset(response, 0, sizeof(response));
        if (recv(sock, response, sizeof(response) - 1, 0) <= 0) {
            add_log("❌ Không nhận được xác nhận kích thước từ server!");
            close(sock);
            return;
        }
        
        if (std::string(response) != "SIZE_OK") {
            add_log("❌ Server không chấp nhận kích thước key! Phản hồi: " + std::string(response));
            close(sock);
            return;
        }
        
        // Gửi nội dung key
        const char* data = key_content.c_str();
        size_t remaining = key_content.size();
        size_t total_sent = 0;
        
        while (remaining > 0) {
            ssize_t sent = send(sock, data + total_sent, remaining, 0);
            if (sent <= 0) {
                add_log("❌ Lỗi khi gửi nội dung key! Lỗi: " + std::string(strerror(errno)));
                close(sock);
                return;
            }
            total_sent += sent;
            remaining -= sent;
        }
        
        add_log("✅ Đã gửi " + std::to_string(total_sent) + " bytes client public key");
        
        // Gửi checksum
        if (send(sock, checksum.c_str(), checksum.size(), 0) != (ssize_t)checksum.size()) {
            add_log("❌ Lỗi khi gửi checksum! Lỗi: " + std::string(strerror(errno)));
            close(sock);
            return;
        }
        
        // Gửi end marker
        std::string end_marker = TRANSMISSION_END_MARKER;
        if (send(sock, end_marker.c_str(), end_marker.size(), 0) != (ssize_t)end_marker.size()) {
            add_log("❌ Lỗi khi gửi end marker! Lỗi: " + std::string(strerror(errno)));
            close(sock);
            return;
        }
        
        // Chờ xác nhận cuối cùng
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        tv.tv_sec = 5;
        
        add_log("🔄 Đang chờ xác nhận cuối cùng từ server...");
        if (select(sock + 1, &readfds, NULL, NULL, &tv) <= 0) {
            add_log("⚠️ Timeout khi chờ xác nhận từ server!");
            close(sock);
            return;
        }
        
        memset(response, 0, sizeof(response));
        if (recv(sock, response, sizeof(response) - 1, 0) <= 0) {
            add_log("❌ Không nhận được xác nhận từ server! Lỗi: " + std::string(strerror(errno)));
            close(sock);
            return;
        }
        
        if (std::string(response) == "SUCCESS") {
            add_log("✅ Server đã nhận client public key thành công!");
        } else {
            add_log("⚠️ Server báo lỗi: " + std::string(response));
        }
        
        shutdown(sock, SHUT_RDWR);
        close(sock);
        add_log("✅ Kết thúc quá trình gửi client public key!");
    } catch (const std::exception& e) {
        add_log("❌ Lỗi: " + std::string(e.what()));
        close(sock);
    }
}

static void send_public_key(GtkWidget *widget, gpointer data) {
    if (!has_client_keys) {
        add_log("❌ Chưa tạo cặp khóa client!");
        return;
    }
    
    const char *server_ip = gtk_entry_get_text(GTK_ENTRY(server_ip_entry));
    if (strlen(server_ip) == 0) {
        server_ip = DEFAULT_SERVER_IP;
    }
    
    add_log("🔄 Bắt đầu gửi client public key đến server " + std::string(server_ip));
    std::thread(send_public_key_thread, std::string(server_ip)).detach();
}

static void view_public_key(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog;
    GtkWidget *content_area;
    GtkWidget *scrolled_window;
    GtkWidget *text_view;
    GtkTextBuffer *buffer;
    
    std::string key_path = "client_public.key";
    std::ifstream file(key_path);
    if (!file) {
        add_log("❌ Không thể mở file public key!");
        return;
    }
    
    std::string key_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    
    dialog = gtk_dialog_new_with_buttons("Public Key", 
                                        GTK_WINDOW(data),
                                        (GtkDialogFlags)(GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT),
                                        "_OK", GTK_RESPONSE_ACCEPT,
                                        NULL);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 500, 300);
    
    content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    
    scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
                                  GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(content_area), scrolled_window, TRUE, TRUE, 0);
    
    text_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
    buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
    gtk_text_buffer_set_text(buffer, key_content.c_str(), -1);
    
    gtk_container_add(GTK_CONTAINER(scrolled_window), text_view);
    
    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

static void view_encrypted_key(GtkWidget *widget, gpointer data) {
    if (file_received) {
        std::string encrypted_key_file = RECEIVED_DIR + std::string("/") + "encrypted_des_key.bin";
        
        std::ifstream file(encrypted_key_file, std::ios::binary);
        if (!file) {
            add_log("❌ Không thể mở file khóa đã mã hóa!");
            return;
        }
        
        std::vector<uint8_t> key_data((std::istreambuf_iterator<char>(file)), 
                                      std::istreambuf_iterator<char>());
        file.close();
        
        std::stringstream ss;
        ss << "Khóa DES đã mã hóa (hex): ";
        for (size_t i = 0; i < std::min(key_data.size(), size_t(32)); i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)key_data[i] << " ";
        }
        if (key_data.size() > 32) ss << "...";
        
        add_log(ss.str());
        add_log("Kích thước khóa đã mã hóa: " + std::to_string(key_data.size()) + " bytes");
    }
}

void send_file_thread(const std::string& server_ip, const std::string& filename) {
    if (!has_server_public_key) {
        add_log("❌ Chưa có public key của server! Không thể mã hóa.");
        gdk_threads_add_idle([](gpointer data) -> gboolean {
            gtk_label_set_text(GTK_LABEL(status_label), "Lỗi: Không có public key!");
            gtk_widget_set_sensitive(send_button, TRUE);
            return FALSE;
        }, NULL);
        return;
    }

    int sock = 0;
    struct sockaddr_in server_addr;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        add_log("❌ Tạo socket thất bại! Lỗi: " + std::string(strerror(errno)));
        gdk_threads_add_idle([](gpointer data) -> gboolean {
            gtk_label_set_text(GTK_LABEL(status_label), "Lỗi kết nối!");
            gtk_widget_set_sensitive(send_button, TRUE);
            return FALSE;
        }, NULL);
        return;
    }
    
    try {
        setSocketTimeout(sock, SOCKET_TIMEOUT_SEC);
        
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(PORT);
        if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
            add_log("❌ Địa chỉ IP không hợp lệ! Lỗi: " + std::string(strerror(errno)));
            close(sock);
            gdk_threads_add_idle([](gpointer data) -> gboolean {
                gtk_label_set_text(GTK_LABEL(status_label), "Địa chỉ IP không hợp lệ!");
                gtk_widget_set_sensitive(send_button, TRUE);
                return FALSE;
            }, NULL);
            return;
        }
        
        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            add_log("❌ Kết nối thất bại! Lỗi: " + std::string(strerror(errno)));
            add_log("Địa chỉ: " + server_ip + ", Cổng: " + std::to_string(PORT));
            close(sock);
            gdk_threads_add_idle([](gpointer data) -> gboolean {
                gtk_label_set_text(GTK_LABEL(status_label), "Kết nối thất bại!");
                gtk_widget_set_sensitive(send_button, TRUE);
                return FALSE;
            }, NULL);
            return;
        }
        
        add_log("✅ Đã kết nối đến server!");
        
        // Tính checksum của file gốc
        std::string original_checksum = calculateMD5Checksum(filename);
        add_log("🔐 MD5 checksum của file gốc: " + original_checksum);
        
        char *file_path_cstr = strdup(filename.c_str());
        std::string original_file_name = basename(file_path_cstr);
        free(file_path_cstr);
        
        // Thêm checksum vào tên file để xác thực
        std::string file_info = original_file_name + "|" + original_checksum;
        add_log("📤 Đang gửi thông tin file: " + file_info);
        
        if (send(sock, file_info.c_str(), file_info.size() + 1, 0) != (ssize_t)(file_info.size() + 1)) {
            add_log("❌ Lỗi khi gửi thông tin file!");
            close(sock);
            gdk_threads_add_idle([](gpointer data) -> gboolean {
                gtk_label_set_text(GTK_LABEL(status_label), "Lỗi gửi thông tin file!");
                gtk_widget_set_sensitive(send_button, TRUE);
                return FALSE;
            }, NULL);
            return;
        }
        
        // Chờ xác nhận từ server
        char response[128] = {0};
        if (recv(sock, response, sizeof(response) - 1, 0) <= 0) {
            add_log("❌ Không nhận được phản hồi từ server!");
            close(sock);
            gdk_threads_add_idle([](gpointer data) -> gboolean {
                gtk_label_set_text(GTK_LABEL(status_label), "Không nhận được phản hồi!");
                gtk_widget_set_sensitive(send_button, TRUE);
                return FALSE;
            }, NULL);
            return;
        }
        
        if (std::string(response) != "READY") {
            add_log("❌ Server không sẵn sàng nhận file! Phản hồi: " + std::string(response));
            close(sock);
            gdk_threads_add_idle([](gpointer data) -> gboolean {
                gtk_label_set_text(GTK_LABEL(status_label), "Server không sẵn sàng!");
                gtk_widget_set_sensitive(send_button, TRUE);
                return FALSE;
            }, NULL);
            return;
        }
        
        add_log("🔑 Đang tạo khóa DES ngẫu nhiên...");
        std::vector<uint8_t> sessionKey = generateRandomDESKey();
        
        std::stringstream ss;
        ss << "Khóa DES gốc (hex): ";
        for (size_t i = 0; i < sessionKey.size(); i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)sessionKey[i] << " ";
        }
        add_log(ss.str());
        add_log("Kích thước khóa DES: " + std::to_string(sessionKey.size()) + " bytes");
        
        std::vector<uint8_t> binSessionKey = convertByteToBit(sessionKey);
        
        add_log("🔐 Đang mã hóa file với DES session key...");
        std::string encryptedFile = RECEIVED_DIR + std::string("/") + "encrypted.txt";
        encryptFile(filename, encryptedFile, binSessionKey);
        
        // Kiểm tra kết quả mã hóa
        struct stat encrypted_stat;
        if (stat(encryptedFile.c_str(), &encrypted_stat) != 0) {
            add_log("❌ Không thể tạo file mã hóa!");
            close(sock);
            gdk_threads_add_idle([](gpointer data) -> gboolean {
                gtk_label_set_text(GTK_LABEL(status_label), "Lỗi mã hóa file!");
                gtk_widget_set_sensitive(send_button, TRUE);
                return FALSE;
            }, NULL);
            return;
        }
        
        add_log("✅ Mã hóa file thành công!");
        std::string encrypted_checksum = calculateMD5Checksum(encryptedFile);
        add_log("🔐 MD5 checksum của file mã hóa: " + encrypted_checksum);
        
        add_log("🔒 Đang mã hóa DES session key với RSA public key...");
        std::vector<uint8_t> encryptedSessionKey = rsaEncrypt(sessionKey, server_public_key);
        
        if (encryptedSessionKey.empty()) {
            add_log("❌ Mã hóa RSA thất bại!");
            close(sock);
            gdk_threads_add_idle([](gpointer data) -> gboolean {
                gtk_label_set_text(GTK_LABEL(status_label), "Lỗi mã hóa RSA!");
                gtk_widget_set_sensitive(send_button, TRUE);
                return FALSE;
            }, NULL);
            return;
        }
        
        uint32_t keySize = encryptedSessionKey.size();
        add_log("📤 Gửi kích thước khóa đã mã hóa: " + std::to_string(keySize) + " bytes");
        
        if (send(sock, &keySize, sizeof(keySize), 0) != sizeof(keySize)) {
            add_log("❌ Lỗi khi gửi kích thước khóa!");
            close(sock);
            gdk_threads_add_idle([](gpointer data) -> gboolean {
                gtk_label_set_text(GTK_LABEL(status_label), "Lỗi gửi kích thước khóa!");
                gtk_widget_set_sensitive(send_button, TRUE);
                return FALSE;
            }, NULL);
            return;
        }
        
        if (send(sock, encryptedSessionKey.data(), encryptedSessionKey.size(), 0) != (ssize_t)encryptedSessionKey.size()) {
            add_log("❌ Lỗi khi gửi khóa đã mã hóa!");
            close(sock);
            gdk_threads_add_idle([](gpointer data) -> gboolean {
                gtk_label_set_text(GTK_LABEL(status_label), "Lỗi gửi khóa!");
                gtk_widget_set_sensitive(send_button, TRUE);
                return FALSE;
            }, NULL);
            return;
        }
        
        add_log("📤 Đã gửi khóa DES đã mã hóa");
        
        // Gửi checksum của file mã hóa
        if (send(sock, encrypted_checksum.c_str(), encrypted_checksum.size(), 0) != (ssize_t)encrypted_checksum.size()) {
            add_log("❌ Lỗi khi gửi checksum file mã hóa!");
            close(sock);
            gdk_threads_add_idle([](gpointer data) -> gboolean {
                gtk_label_set_text(GTK_LABEL(status_label), "Lỗi gửi checksum!");
                gtk_widget_set_sensitive(send_button, TRUE);
                return FALSE;
            }, NULL);
            return;
        }
        
        std::ifstream file(encryptedFile, std::ios::binary);
        if (!file) {
            add_log("❌ Không thể mở file để gửi!");
            close(sock);
            gdk_threads_add_idle([](gpointer data) -> gboolean {
                gtk_label_set_text(GTK_LABEL(status_label), "Lỗi mở file!");
                gtk_widget_set_sensitive(send_button, TRUE);
                return FALSE;
            }, NULL);
            return;
        }
        
        file.seekg(0, std::ios::end);
        int fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        add_log("📌 Kích thước file mã hóa: " + std::to_string(fileSize) + " bytes");
        
        // Gửi kích thước file
        if (send(sock, &fileSize, sizeof(fileSize), 0) != sizeof(fileSize)) {
            add_log("❌ Lỗi khi gửi kích thước file!");
            file.close();
            close(sock);
            gdk_threads_add_idle([](gpointer data) -> gboolean {
                gtk_label_set_text(GTK_LABEL(status_label), "Lỗi gửi kích thước file!");
                gtk_widget_set_sensitive(send_button, TRUE);
                return FALSE;
            }, NULL);
            return;
        }
        
        // Chờ xác nhận từ server
        memset(response, 0, sizeof(response));
        if (recv(sock, response, sizeof(response) - 1, 0) <= 0) {
            add_log("❌ Không nhận được xác nhận từ server để gửi file!");
            file.close();
            close(sock);
            gdk_threads_add_idle([](gpointer data) -> gboolean {
                gtk_label_set_text(GTK_LABEL(status_label), "Lỗi nhận xác nhận!");
                gtk_widget_set_sensitive(send_button, TRUE);
                return FALSE;
            }, NULL);
            return;
        }
        
        if (std::string(response) != "READY_FOR_FILE") {
            add_log("❌ Server không sẵn sàng nhận file! Phản hồi: " + std::string(response));
            file.close();
            close(sock);
            gdk_threads_add_idle([](gpointer data) -> gboolean {
                gtk_label_set_text(GTK_LABEL(status_label), "Server không sẵn sàng nhận file!");
                gtk_widget_set_sensitive(send_button, TRUE);
                return FALSE;
            }, NULL);
            return;
        }
        
        char buffer[BUFFER_SIZE];
        int totalBytesSent = 0;
        int bytesRead = 0;
        
        while (!file.eof()) {
            file.read(buffer, BUFFER_SIZE);
            bytesRead = file.gcount();
            
            if (bytesRead <= 0) {
                break;
            }
            
            int bytesSent = 0;
            while (bytesSent < bytesRead) {
                int sent = send(sock, buffer + bytesSent, bytesRead - bytesSent, 0);
                if (sent <= 0) {
                    add_log("❌ Lỗi khi gửi dữ liệu! Lỗi: " + std::string(strerror(errno)));
                    file.close();
                    close(sock);
                    gdk_threads_add_idle([](gpointer data) -> gboolean {
                        gtk_label_set_text(GTK_LABEL(status_label), "Lỗi gửi dữ liệu!");
                        gtk_widget_set_sensitive(send_button, TRUE);
                        return FALSE;
                    }, NULL);
                    return;
                }
                bytesSent += sent;
            }
            
            totalBytesSent += bytesRead;
        }
        
        file.close();
        add_log("✅ Đã gửi file mã hóa! Tổng số byte đã gửi: " + std::to_string(totalBytesSent) + " bytes");
        
        // Gửi marker kết thúc
        std::string end_marker = TRANSMISSION_END_MARKER;
        if (send(sock, end_marker.c_str(), end_marker.size(), 0) != (ssize_t)end_marker.size()) {
            add_log("❌ Lỗi khi gửi end marker!");
            close(sock);
            gdk_threads_add_idle([](gpointer data) -> gboolean {
                gtk_label_set_text(GTK_LABEL(status_label), "Lỗi gửi end marker!");
                gtk_widget_set_sensitive(send_button, TRUE);
                return FALSE;
            }, NULL);
            return;
        }
        
        // Nhận xác nhận từ server
        memset(response, 0, sizeof(response));
        if (recv(sock, response, sizeof(response) - 1, 0) <= 0) {
            add_log("❌ Không nhận được xác nhận cuối cùng từ server!");
            close(sock);
            gdk_threads_add_idle([](gpointer data) -> gboolean {
                gtk_label_set_text(GTK_LABEL(status_label), "Không nhận được xác nhận cuối cùng!");
                gtk_widget_set_sensitive(send_button, TRUE);
                return FALSE;
            }, NULL);
            return;
        }
        
        if (std::string(response) == "SUCCESS") {
            add_log("✅ Server đã nhận file thành công!");
        } else {
            add_log("⚠️ Server báo lỗi: " + std::string(response));
        }
        
        shutdown(sock, SHUT_RDWR);
        close(sock);
        
        gdk_threads_add_idle([](gpointer data) -> gboolean {
            gtk_label_set_text(GTK_LABEL(status_label), "Đã gửi file thành công!");
            gtk_widget_set_sensitive(send_button, TRUE);
            return FALSE;
        }, NULL);
    }catch (const std::exception& e) {
    std::string error_msg = std::string(e.what());
    add_log("❌ Lỗi: " + error_msg);
    close(sock);
    
    // Cấp phát bộ nhớ cho message và sao chép vào đó
    gchar* error_copy = g_strdup(("Lỗi: " + error_msg).c_str());
    
    gdk_threads_add_idle([](gpointer data) -> gboolean {
        gchar* msg = static_cast<gchar*>(data);
        gtk_label_set_text(GTK_LABEL(status_label), msg);
        gtk_widget_set_sensitive(send_button, TRUE);
        g_free(msg); // Giải phóng bộ nhớ
        return FALSE;
    }, error_copy);
}
}

void receiveFile(int client_fd) {
    char header[256] = {0};
    recv(client_fd, header, sizeof(header) - 1, 0);
    std::string header_str(header);
    
    if (header_str == KEY_MARKER) {
        add_log("📥 Nhận yêu cầu truyền public key từ server");
        
        // Gửi phản hồi sẵn sàng
        std::string ready_response = "READY";
        if (send(client_fd, ready_response.c_str(), ready_response.size(), 0) != (ssize_t)ready_response.size()) {
            add_log("❌ Lỗi khi gửi phản hồi sẵn sàng!");
            return;
        }
        
        // Nhận kích thước key
        uint32_t key_size;
        if (recv(client_fd, &key_size, sizeof(key_size), 0) != sizeof(key_size)) {
            add_log("❌ Lỗi khi nhận kích thước key!");
            return;
        }
        
        add_log("📥 Kích thước key: " + std::to_string(key_size) + " bytes");
        
        // Kiểm tra kích thước hợp lý
        if (key_size <= 0 || key_size > 10000) {
            add_log("❌ Kích thước key không hợp lý!");
            std::string error_response = "ERROR: Invalid key size";
            send(client_fd, error_response.c_str(), error_response.size(), 0);
            return;
        }
        
        // Nhận nội dung key
        std::vector<char> key_buffer(key_size + 1, 0);
        int total_received = 0;
        int remaining = key_size;
        
        while (total_received < (int)key_size) {
            int bytes = recv(client_fd, key_buffer.data() + total_received, remaining, 0);
            if (bytes <= 0) {
                add_log("❌ Lỗi khi nhận nội dung key!");
                std::string error_response = "ERROR: Failed to receive key content";
                send(client_fd, error_response.c_str(), error_response.size(), 0);
                return;
            }
            total_received += bytes;
            remaining -= bytes;
        }
        
        add_log("📥 Đã nhận " + std::to_string(total_received) + " bytes nội dung key");
        
        // Nhận checksum
        char checksum_buffer[33] = {0};
        if (recv(client_fd, checksum_buffer, 32, 0) != 32) {
            add_log("❌ Lỗi khi nhận checksum!");
            std::string error_response = "ERROR: Failed to receive checksum";
            send(client_fd, error_response.c_str(), error_response.size(), 0);
            return;
        }
        
        std::string received_checksum(checksum_buffer);
        add_log("📥 Đã nhận checksum: " + received_checksum);
        
        // Nhận end marker
        char end_marker[30] = {0};
        if (recv(client_fd, end_marker, sizeof(end_marker) - 1, 0) <= 0) {
            add_log("❌ Lỗi khi nhận end marker!");
            std::string error_response = "ERROR: Failed to receive end marker";
            send(client_fd, error_response.c_str(), error_response.size(), 0);
            return;
        }
        
        if (std::string(end_marker) != TRANSMISSION_END_MARKER) {
            add_log("❌ End marker không đúng!");
            std::string error_response = "ERROR: Invalid end marker";
            send(client_fd, error_response.c_str(), error_response.size(), 0);
            return;
        }
        
        // Lưu key vào file
        std::string server_key_path = RECEIVED_DIR + std::string("/") + "server_public.key";
        std::ofstream key_file(server_key_path);
        if (!key_file) {
            add_log("❌ Không thể tạo file key!");
            std::string error_response = "ERROR: Cannot create key file";
            send(client_fd, error_response.c_str(), error_response.size(), 0);
            return;
        }
        
        key_file.write(key_buffer.data(), total_received);
        key_file.close();
        
        // Tính và kiểm tra checksum
        std::string calculated_checksum = calculateMD5Checksum(server_key_path);
        add_log("🔐 Checksum tính toán: " + calculated_checksum);
        
        if (calculated_checksum != received_checksum) {
            add_log("❌ Checksum không khớp! Dữ liệu có thể bị hỏng.");
            std::string error_response = "ERROR: Checksum mismatch";
            send(client_fd, error_response.c_str(), error_response.size(), 0);
            return;
        }
        
        // Gửi xác nhận thành công
        std::string success_response = "SUCCESS";
        if (send(client_fd, success_response.c_str(), success_response.size(), 0) != (ssize_t)success_response.size()) {
            add_log("❌ Lỗi khi gửi xác nhận thành công!");
            return;
        }
        
        add_log("✅ Đã nhận và lưu public key từ server!");
        add_log("📁 Public key lưu tại: " + server_key_path);
        
        load_server_public_key(server_key_path);
        return;
    }
    
    // Xử lý nhận file
    add_log("📥 Đang nhận file...");
    
    // Parse thông tin file (tên file|checksum)
    size_t separator_pos = header_str.find("|");
    if (separator_pos == std::string::npos) {
        add_log("❌ Định dạng thông tin file không hợp lệ!");
        return;
    }
    
    last_original_filename = header_str.substr(0, separator_pos);
    std::string original_checksum = header_str.substr(separator_pos + 1);
    
    add_log("📥 Tên file nhận được: " + last_original_filename);
    add_log("📥 Checksum file gốc: " + original_checksum);
    
    // Gửi phản hồi sẵn sàng
    std::string ready_response = "READY";
    if (send(client_fd, ready_response.c_str(), ready_response.size(), 0) != (ssize_t)ready_response.size()) {
        add_log("❌ Lỗi khi gửi phản hồi sẵn sàng!");
        return;
    }
    
    // Nhận kích thước khóa DES đã mã hóa
    uint32_t keySize;
    if (recv(client_fd, &keySize, sizeof(keySize), 0) != sizeof(keySize)) {
        add_log("❌ Lỗi khi nhận kích thước khóa DES!");
        return;
    }
    
    add_log("📥 Nhận kích thước khóa DES đã mã hóa: " + std::to_string(keySize) + " bytes");
    
    // Kiểm tra kích thước hợp lý
    if (keySize <= 0 || keySize > 1024) {
        add_log("❌ Kích thước khóa không hợp lý!");
        return;
    }
    
    // Nhận khóa DES đã mã hóa
    std::vector<uint8_t> encryptedKey(keySize);
    int total_key_received = 0;
    
    while (total_key_received < (int)keySize) {
        int bytes = recv(client_fd, encryptedKey.data() + total_key_received, keySize - total_key_received, 0);
        if (bytes <= 0) {
            add_log("❌ Lỗi khi nhận khóa DES!");
            return;
        }
        total_key_received += bytes;
    }
    
    add_log("📥 Đã nhận khóa DES đã mã hóa: " + std::to_string(total_key_received) + " bytes");
    
    // Lưu khóa DES đã mã hóa
    std::string encrypted_key_file = RECEIVED_DIR + std::string("/") + "encrypted_des_key.bin";
    std::ofstream key_file(encrypted_key_file, std::ios::binary);
    if (!key_file) {
        add_log("❌ Không thể tạo file khóa!");
        return;
    }
    
    key_file.write(reinterpret_cast<const char*>(encryptedKey.data()), encryptedKey.size());
    key_file.close();
    add_log("📁 Đã lưu khóa DES đã mã hóa tại: " + encrypted_key_file);
    
   // Nhận checksum của file mã hóa
    char checksum_buffer[33] = {0};
    if (recv(client_fd, checksum_buffer, 32, 0) != 32) {
        add_log("❌ Lỗi khi nhận checksum của file mã hóa!");
        return;
    }
    
    std::string expected_encrypted_checksum(checksum_buffer);
    add_log("📥 Checksum file mã hóa: " + expected_encrypted_checksum);
    
    // Nhận kích thước file mã hóa
    int fileSize;
    if (recv(client_fd, &fileSize, sizeof(fileSize), 0) != sizeof(fileSize)) {
        add_log("❌ Lỗi khi nhận kích thước file!");
        return;
    }
    
    add_log("📥 Kích thước file mã hóa: " + std::to_string(fileSize) + " bytes");
    
    // Kiểm tra kích thước hợp lý
    if (fileSize <= 0) {
        add_log("❌ Kích thước file không hợp lý!");
        return;
    }
    
    // Gửi phản hồi sẵn sàng nhận file
    std::string ready_file_response = "READY_FOR_FILE";
    if (send(client_fd, ready_file_response.c_str(), ready_file_response.size(), 0) != (ssize_t)ready_file_response.size()) {
        add_log("❌ Lỗi khi gửi phản hồi sẵn sàng nhận file!");
        return;
    }
    
    // Chuẩn bị file để lưu dữ liệu mã hóa
    std::string encryptedFile = RECEIVED_DIR + std::string("/") + "received_on_client.txt";
    last_encrypted_file = encryptedFile;
    
    std::ofstream file(encryptedFile, std::ios::binary);
    if (!file) {
        add_log("❌ Không thể tạo file mã hóa!");
        return;
    }
    
    // Nhận dữ liệu file mã hóa
    char buffer[BUFFER_SIZE];
    int totalBytesReceived = 0;
    
    while (totalBytesReceived < fileSize) {
        int bytesToRead = std::min(BUFFER_SIZE, fileSize - totalBytesReceived);
        int bytesReceived = recv(client_fd, buffer, bytesToRead, 0);
        
        if (bytesReceived <= 0) {
            add_log("❌ Lỗi khi nhận dữ liệu file! Đã nhận: " + std::to_string(totalBytesReceived) + "/" + std::to_string(fileSize) + " bytes");
            file.close();
            return;
        }
        
        file.write(buffer, bytesReceived);
        totalBytesReceived += bytesReceived;
    }
    
    file.close();
    add_log("✅ Đã nhận file mã hóa! Tổng số byte nhận được: " + std::to_string(totalBytesReceived) + " bytes");
    
    // Kiểm tra end marker
    char end_marker[30] = {0};
    if (recv(client_fd, end_marker, sizeof(end_marker) - 1, 0) <= 0) {
        add_log("❌ Lỗi khi nhận end marker!");
        return;
    }
    
    if (std::string(end_marker) != TRANSMISSION_END_MARKER) {
        add_log("❌ End marker không đúng!");
        std::string error_response = "ERROR: Invalid end marker";
        send(client_fd, error_response.c_str(), error_response.size(), 0);
        return;
    }
    
    // Kiểm tra checksum của file mã hóa đã nhận
    std::string calculated_encrypted_checksum = calculateMD5Checksum(encryptedFile);
    add_log("🔐 Checksum tính toán của file mã hóa: " + calculated_encrypted_checksum);
    
    if (calculated_encrypted_checksum != expected_encrypted_checksum) {
        add_log("❌ Checksum file mã hóa không khớp! Dữ liệu có thể bị hỏng.");
        std::string error_response = "ERROR: Encrypted file checksum mismatch";
        send(client_fd, error_response.c_str(), error_response.size(), 0);
        return;
    }
    
    add_log("✅ Checksum file mã hóa khớp!");
    add_log("📁 File đã được lưu tại: " + encryptedFile);
    file_received = true;
    
    // Gửi xác nhận thành công
    std::string success_response = "SUCCESS";
    send(client_fd, success_response.c_str(), success_response.size(), 0);
    
    gdk_threads_add_idle([](gpointer data) -> gboolean {
        gtk_label_set_text(GTK_LABEL(status_label), "Đã nhận file mã hóa thành công!");
        gtk_widget_set_sensitive(view_encrypted_button, TRUE);
        gtk_widget_set_sensitive(view_encrypted_key_button, TRUE);
        gtk_widget_set_sensitive(decrypt_rsa_button, TRUE);
        return FALSE;
    }, NULL);
}

static void decrypt_rsa(GtkWidget *widget, gpointer data) {
    if (!file_received) {
        add_log("❌ Không có file để giải mã!");
        return;
    }
    
    if (!has_client_keys) {
        add_log("⚠️ Chưa có cặp khóa RSA. Đang tải khóa...");
        load_client_keys();
        if (!has_client_keys) {
            add_log("❌ Không thể tải khóa RSA! Vui lòng tạo cặp khóa trước.");
            return;
        }
    }
    
    std::string encrypted_key_file = RECEIVED_DIR + std::string("/") + "encrypted_des_key.bin";
    std::ifstream key_file(encrypted_key_file, std::ios::binary);
    if (!key_file) {
        add_log("❌ Không tìm thấy file khóa đã mã hóa!");
        return;
    }
    
    std::vector<uint8_t> encrypted_key((std::istreambuf_iterator<char>(key_file)), 
                                      std::istreambuf_iterator<char>());
    key_file.close();
    
    add_log("🔓 Đang giải mã khóa DES với RSA private key...");
    decrypted_des_key = rsaDecrypt(encrypted_key, client_private_key);
    
    if (decrypted_des_key.empty()) {
        add_log("❌ Giải mã RSA thất bại!");
        return;
    }
    
    std::stringstream ss;
    ss << "Khóa DES đã giải mã (hex): ";
    for (size_t i = 0; i < decrypted_des_key.size(); i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)decrypted_des_key[i] << " ";
    }
    add_log(ss.str());
    add_log("Kích thước khóa DES: " + std::to_string(decrypted_des_key.size()) + " bytes");
    
    std::string des_key_file = RECEIVED_DIR + std::string("/") + "decrypted_des_key.bin";
    std::ofstream des_file(des_key_file, std::ios::binary);
    des_file.write(reinterpret_cast<const char*>(decrypted_des_key.data()), decrypted_des_key.size());
    des_file.close();
    add_log("📁 Khóa DES đã giải mã được lưu tại: " + des_key_file);
    
    has_decrypted_des_key = true;
    add_log("✅ Đã giải mã khóa DES thành công!");
    gtk_widget_set_sensitive(decrypt_button, TRUE);
}

void decrypt_des_thread(GtkWidget *widget) {  // Truyền widget vào hàm
    if (!has_decrypted_des_key || !file_received) {
        add_log("❌ Không thể giải mã DES! Chưa giải mã RSA hoặc không có file.");
        gdk_threads_add_idle([](gpointer data) -> gboolean {
            gtk_widget_set_sensitive(decrypt_button, TRUE);
            return FALSE;
        }, NULL);
        return;
    }

    add_log("🔄 Đang giải mã file với khóa DES...");

    if (decrypted_des_key.size() != 8) {
        add_log("⚠️ Cảnh báo: Kích thước khóa DES không phải 8 bytes!");
    }

     std::vector<uint8_t> binSessionKey = convertByteToBit(decrypted_des_key);
    add_log("Đã chuyển đổi khóa DES thành " + std::to_string(binSessionKey.size()) + " bits");
    add_log("Đang giải mã file: " + last_encrypted_file);
    last_decrypted_file = DECRYPTED_DIR + std::string("/") + "decrypted_" + last_original_filename;
    add_log("Sẽ lưu tại: " + last_decrypted_file);

    try {
        decryptFile(last_encrypted_file, last_decrypted_file, binSessionKey);

        struct stat buffer;
        if (stat(last_decrypted_file.c_str(), &buffer) == 0) {
            file_decrypted = true;
            add_log("✅ Đã giải mã file thành công!");
            add_log("📁 File đã giải mã được lưu tại: " + last_decrypted_file);
            add_log("📌 Kích thước file đã giải mã: " + std::to_string(buffer.st_size) + " bytes");

            std::string decrypted_checksum = calculateMD5Checksum(last_decrypted_file);
            add_log("🔐 Checksum file đã giải mã: " + decrypted_checksum);

            // Cập nhật UI từ luồng chính
            gdk_threads_add_idle([](gpointer data) -> gboolean {
                gtk_widget_set_sensitive(view_decrypted_button, TRUE);
                return FALSE;
            }, NULL);
        } else {
            add_log("❌ Giải mã thất bại: Không tìm thấy file đã giải mã!");
        }
    } catch (const std::exception& e) {
        add_log("❌ Lỗi khi giải mã: " + std::string(e.what()));
    }

    // Kích hoạt lại nút "Giải mã DES" sau khi hoàn tất
    gdk_threads_add_idle([](gpointer data) -> gboolean {
        gtk_widget_set_sensitive(decrypt_button, TRUE);
        return FALSE;
    }, NULL);
}

// Callback cho nút "Giải mã DES"
static void decrypt_des(GtkWidget *widget, gpointer data) {
    gtk_widget_set_sensitive(decrypt_button, FALSE); // Vô hiệu hóa nút trong khi giải mã
    add_log("🔄 Bắt đầu giải mã DES trong luồng riêng...");

    // Chạy giải mã trong luồng riêng, truyền widget vào
    std::thread decrypt_thread(decrypt_des_thread, widget);
    decrypt_thread.detach(); // Tách luồng để nó chạy độc lập
}

void client_server_function() {
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    client_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_server_fd == 0) {
        add_log("❌ Lỗi tạo socket!");
        return;
    }
    
    try {
        setSocketTimeout(client_server_fd, SOCKET_TIMEOUT_SEC);
        
        int opt = 1;
        if (setsockopt(client_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            add_log("❌ Lỗi thiết lập socket!");
            close(client_server_fd);
            return;
        }
        
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(CLIENT_PORT);
        
        if (bind(client_server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
            add_log("❌ Bind thất bại! Lỗi: " + std::string(strerror(errno)));
            close(client_server_fd);
            return;
        }
        
        if (listen(client_server_fd, 3) < 0) {
            add_log("❌ Lỗi khi listen! Lỗi: " + std::string(strerror(errno)));
            close(client_server_fd);
            return;
        }
        
        add_log("Client đang lắng nghe kết nối trên cổng " + std::to_string(CLIENT_PORT));
        
        while (client_server_running) {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(client_server_fd, &readfds);
            
            struct timeval tv;
            tv.tv_sec = 1;  // 1 giây
            tv.tv_usec = 0;
            
            int activity = select(client_server_fd + 1, &readfds, NULL, NULL, &tv);
            
            if (activity < 0 && errno != EINTR) {
                add_log("❌ Lỗi select: " + std::string(strerror(errno)));
                break;
            }
            
            if (!client_server_running) {
                break;
            }
            
            // Kiểm tra xem client_server_fd có sẵn sàng không
            if (activity > 0 && FD_ISSET(client_server_fd, &readfds)) {
                int client_fd = accept(client_server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
                if (client_fd < 0) {
                    if (client_server_running && errno != EAGAIN && errno != EWOULDBLOCK) {
                        add_log("❌ Accept thất bại! Lỗi: " + std::string(strerror(errno)));
                    }
                    continue;
                }
                
                try {
                    setSocketTimeout(client_fd, SOCKET_TIMEOUT_SEC);
                    
                    struct sockaddr_in* pV4Addr = (struct sockaddr_in*)&address;
                    struct in_addr ipAddr = pV4Addr->sin_addr;
                    char str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ipAddr, str, INET_ADDRSTRLEN);
                    
                    add_log("✅ Kết nối từ " + std::string(str) + ":" + std::to_string(ntohs(pV4Addr->sin_port)));
                    receiveFile(client_fd);
                    close(client_fd);
                } catch (const std::exception& e) {
                    add_log("❌ Lỗi xử lý kết nối: " + std::string(e.what()));
                    close(client_fd);
                }
            }
        }
    } catch (const std::exception& e) {
        add_log("❌ Lỗi server: " + std::string(e.what()));
        if (client_server_fd >= 0) {
            close(client_server_fd);
            client_server_fd = -1;
        }
    }
}

static void view_encrypted_file(GtkWidget *widget, gpointer data) {
    if (file_received && !last_encrypted_file.empty()) {
        std::string command = "xdg-open " + last_encrypted_file;
        system(command.c_str());
    }
}

static void view_decrypted_file(GtkWidget *widget, gpointer data) {
    if (file_decrypted && !last_decrypted_file.empty()) {
        std::string command = "xdg-open " + last_decrypted_file;
        system(command.c_str());
    }
}

static void start_listening(GtkWidget *widget, gpointer data) {
    if (!client_server_running) {
        client_server_running = true;
        gtk_widget_set_sensitive(listen_button, FALSE);
        gtk_widget_set_sensitive(stop_listen_button, TRUE);
        add_log("Bắt đầu lắng nghe kết nối...");
        client_server_thread = std::thread(client_server_function);
        client_server_thread.detach();
    }
}

static void stop_listening(GtkWidget *widget, gpointer data) {
    if (client_server_running) {
        client_server_running = false;
        if (client_server_fd >= 0) {
            close(client_server_fd);
            client_server_fd = -1;
        }
        gtk_widget_set_sensitive(listen_button, TRUE);
        gtk_widget_set_sensitive(stop_listen_button, FALSE);
        add_log("Đã dừng lắng nghe kết nối");
    }
}

static void select_file(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog;
    GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
    gint res;
    dialog = gtk_file_chooser_dialog_new("Chọn file", GTK_WINDOW(data), action, "_Hủy", GTK_RESPONSE_CANCEL, "_Mở", GTK_RESPONSE_ACCEPT, NULL);
    res = gtk_dialog_run(GTK_DIALOG(dialog));
    if (res == GTK_RESPONSE_ACCEPT) {
        GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
        char *filename = gtk_file_chooser_get_filename(chooser);
        selected_file_path = filename;
        gtk_label_set_text(GTK_LABEL(file_path_label), filename);
        gtk_widget_set_sensitive(send_button, TRUE);
        g_free(filename);
    }
    gtk_widget_destroy(dialog);
}

static void load_public_key(GtkWidget *widget, gpointer data) {
    const std::string default_key_path = RECEIVED_DIR + std::string("/") + "server_public.key";
    
    struct stat buffer;
    if (stat(default_key_path.c_str(), &buffer) == 0) {
        load_server_public_key(default_key_path);
    } else {
        GtkWidget *dialog;
        GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
        gint res;
        dialog = gtk_file_chooser_dialog_new("Chọn RSA Public Key", 
                                            GTK_WINDOW(data), 
                                            action, 
                                            "_Hủy", GTK_RESPONSE_CANCEL, 
                                            "_Mở", GTK_RESPONSE_ACCEPT, 
                                            NULL);
        res = gtk_dialog_run(GTK_DIALOG(dialog));
        if (res == GTK_RESPONSE_ACCEPT) {
            GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
            char *filename = gtk_file_chooser_get_filename(chooser);
            load_server_public_key(filename);
            g_free(filename);
        }
        gtk_widget_destroy(dialog);
    }
}

static void generate_keys(GtkWidget *widget, gpointer data) {
    generate_client_keys();
}

static void send_file(GtkWidget *widget, gpointer data) {
    if (selected_file_path.empty()) {
        add_log("❌ Chưa chọn file để gửi!");
        return;
    }
    if (!has_server_public_key) {
        add_log("❌ Chưa tải public key của server!");
        return;
    }
    const char *server_ip = gtk_entry_get_text(GTK_ENTRY(server_ip_entry));
    if (strlen(server_ip) == 0) {
        server_ip = DEFAULT_SERVER_IP;
    }
    gtk_widget_set_sensitive(send_button, FALSE);
    gtk_label_set_text(GTK_LABEL(status_label), "Đang gửi file...");
    add_log("🔄 Bắt đầu gửi file đến " + std::string(server_ip) + ":" + std::to_string(PORT));
    std::thread send_thread(send_file_thread, std::string(server_ip), selected_file_path);
    send_thread.detach();
}

static void activate(GtkApplication *app, gpointer user_data) {
    GtkWidget *window;
    GtkWidget *grid;
    GtkWidget *scrolled_window;
    GtkWidget *notebook;
    
    window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "DES-RSA Hybrid Client");
    gtk_window_set_default_size(GTK_WINDOW(window), 800, 600);
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);
    
    notebook = gtk_notebook_new();
    gtk_container_add(GTK_CONTAINER(window), notebook);
    
    // Tab 1: Gửi file
    grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 10);
    
    GtkWidget *send_label = gtk_label_new("Gửi File");
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), grid, send_label);
    
    GtkWidget *header_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(header_label), "<big><b>DES-RSA Hybrid Client - Gửi File</b></big>");
    GtkWidget *ip_label = gtk_label_new("Địa chỉ Server:");
    server_ip_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(server_ip_entry), DEFAULT_SERVER_IP);
    GtkWidget *file_label = gtk_label_new("File đã chọn:");
    file_path_label = gtk_label_new("Chưa chọn file");
    select_button = gtk_button_new_with_label("Chọn File");
    send_button = gtk_button_new_with_label("Gửi File");
    load_pubkey_button = gtk_button_new_with_label("Tải Public Key");
    gtk_widget_set_sensitive(send_button, FALSE);
    status_label = gtk_label_new("Sẵn sàng để gửi file");
    
    scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_hexpand(scrolled_window, TRUE);
    gtk_widget_set_vexpand(scrolled_window, TRUE);
    log_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(log_view), FALSE);
    log_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(log_view));
    gtk_container_add(GTK_CONTAINER(scrolled_window), log_view);
    
    gtk_grid_attach(GTK_GRID(grid), header_label, 0, 0, 3, 1);
    gtk_grid_attach(GTK_GRID(grid), ip_label, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), server_ip_entry, 1, 1, 2, 1);
    gtk_grid_attach(GTK_GRID(grid), file_label, 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), file_path_label, 1, 2, 2, 1);
    gtk_grid_attach(GTK_GRID(grid), select_button, 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), send_button, 1, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), load_pubkey_button, 2, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), status_label, 0, 4, 3, 1);
    gtk_grid_attach(GTK_GRID(grid), scrolled_window, 0, 5, 3, 1);
    
    g_signal_connect(select_button, "clicked", G_CALLBACK(select_file), window);
    g_signal_connect(send_button, "clicked", G_CALLBACK(send_file), NULL);
    g_signal_connect(load_pubkey_button, "clicked", G_CALLBACK(load_public_key), window);
    
    // Tab 2: Nhận file
    GtkWidget *receive_grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(receive_grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(receive_grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(receive_grid), 10);
    
    GtkWidget *receive_label = gtk_label_new("Nhận File");
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), receive_grid, receive_label);
    
    GtkWidget *receive_header = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(receive_header), "<big><b>DES-RSA Hybrid Client - Nhận File</b></big>");
    
    listen_button = gtk_button_new_with_label("Bắt đầu lắng nghe");
    stop_listen_button = gtk_button_new_with_label("Dừng lắng nghe");
    generate_keys_button = gtk_button_new_with_label("Tạo cặp khóa RSA");
    send_pubkey_button = gtk_button_new_with_label("Gửi Public Key");
    view_pubkey_button = gtk_button_new_with_label("Xem Public Key");
    
    gtk_widget_set_sensitive(stop_listen_button, FALSE);
    gtk_widget_set_sensitive(send_pubkey_button, FALSE);
    gtk_widget_set_sensitive(view_pubkey_button, FALSE);
    
    GtkWidget *port_info = gtk_label_new("Đang lắng nghe trên cổng: 8081");
    
    GtkWidget *file_actions_frame = gtk_frame_new("Thao tác với file");
    GtkWidget *file_actions_grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(file_actions_grid), 5);
    gtk_grid_set_column_spacing(GTK_GRID(file_actions_grid), 5);
    gtk_container_set_border_width(GTK_CONTAINER(file_actions_grid), 5);
    gtk_container_add(GTK_CONTAINER(file_actions_frame), file_actions_grid);
    
    view_encrypted_button = gtk_button_new_with_label("Xem file mã hóa");
    view_encrypted_key_button = gtk_button_new_with_label("Xem khóa đã mã hóa");
    decrypt_rsa_button = gtk_button_new_with_label("Giải mã RSA");
    decrypt_button = gtk_button_new_with_label("Giải mã DES");
    view_decrypted_button = gtk_button_new_with_label("Xem file đã giải mã");
    
    gtk_widget_set_sensitive(view_encrypted_button, FALSE);
    gtk_widget_set_sensitive(view_encrypted_key_button, FALSE);
    gtk_widget_set_sensitive(decrypt_rsa_button, FALSE);
    gtk_widget_set_sensitive(decrypt_button, FALSE);
    gtk_widget_set_sensitive(view_decrypted_button, FALSE);
    
    gtk_grid_attach(GTK_GRID(file_actions_grid), view_encrypted_button, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(file_actions_grid), view_encrypted_key_button, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(file_actions_grid), decrypt_rsa_button, 2, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(file_actions_grid), decrypt_button, 3, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(file_actions_grid), view_decrypted_button, 4, 0, 1, 1);
    
    gtk_grid_attach(GTK_GRID(receive_grid), receive_header, 0, 0, 4, 1);
    gtk_grid_attach(GTK_GRID(receive_grid), port_info, 0, 1, 4, 1);
    gtk_grid_attach(GTK_GRID(receive_grid), generate_keys_button, 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(receive_grid), listen_button, 1, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(receive_grid), stop_listen_button, 2, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(receive_grid), view_pubkey_button, 3, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(receive_grid), send_pubkey_button, 0, 3, 4, 1);
    gtk_grid_attach(GTK_GRID(receive_grid), file_actions_frame, 0, 4, 4, 1);
    
    g_signal_connect(generate_keys_button, "clicked", G_CALLBACK(generate_keys), NULL);
    g_signal_connect(listen_button, "clicked", G_CALLBACK(start_listening), NULL);
    g_signal_connect(stop_listen_button, "clicked", G_CALLBACK(stop_listening), NULL);
    g_signal_connect(view_encrypted_button, "clicked", G_CALLBACK(view_encrypted_file), NULL);
    g_signal_connect(view_encrypted_key_button, "clicked", G_CALLBACK(view_encrypted_key), NULL);
    g_signal_connect(decrypt_rsa_button, "clicked", G_CALLBACK(decrypt_rsa), NULL);
    g_signal_connect(decrypt_button, "clicked", G_CALLBACK(decrypt_des), NULL);
    g_signal_connect(view_decrypted_button, "clicked", G_CALLBACK(view_decrypted_file), NULL);
    g_signal_connect(send_pubkey_button, "clicked", G_CALLBACK(send_public_key), NULL);
    g_signal_connect(view_pubkey_button, "clicked", G_CALLBACK(view_public_key), window);
    
    gtk_widget_show_all(window);
}

int main(int argc, char **argv) {
    ensure_directory_exists(RECEIVED_DIR);
    ensure_directory_exists(DECRYPTED_DIR);
    
    initRSAKey(server_public_key);
    initRSAKey(client_public_key);
    initRSAKey(client_private_key);
    
    struct stat buffer;
    if (stat("client_public.key", &buffer) == 0 && stat("client_private.key", &buffer) == 0) {
        load_client_keys();
    }
    
    if (stat(RECEIVED_DIR "/server_public.key", &buffer) == 0) {
        load_server_public_key(RECEIVED_DIR "/server_public.key");
    }
    
    GtkApplication *app;
    int status;
    app = gtk_application_new("org.desproject.client", G_APPLICATION_FLAGS_NONE);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    
    freeRSAKey(server_public_key);
    freeRSAKey(client_public_key);
    freeRSAKey(client_private_key);
    
    g_object_unref(app);
    return status;
}
