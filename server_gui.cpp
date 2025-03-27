#include <gtk/gtk.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <libgen.h>
#include "encryption.h"
#include "decryption.h"
#include "utils.h"

#define PORT 8080
#define CLIENT_PORT 8081
#define BUFFER_SIZE 1024
#define DEFAULT_CLIENT_IP "127.0.0.1"

GtkWidget *status_label;
GtkWidget *start_button;
GtkWidget *stop_button;
GtkWidget *log_view;
GtkTextBuffer *log_buffer;
GtkWidget *view_encrypted_button;
GtkWidget *decrypt_button;
GtkWidget *view_decrypted_button;

GtkWidget *select_button;
GtkWidget *send_button;
GtkWidget *client_ip_entry;
GtkWidget *file_path_label;
std::string selected_file_path;

int server_fd = -1;
bool server_running = false;
std::thread server_thread;
std::string last_encrypted_file;
std::string last_original_filename;
std::string last_decrypted_file;
bool file_received = false;
bool file_decrypted = false;

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

void send_file_thread(const std::string& client_ip, const std::string& filename) {
    int sock = 0;
    struct sockaddr_in client_addr;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        add_log("❌ Tạo socket thất bại!");
        gdk_threads_add_idle([](gpointer data) -> gboolean {
            gtk_label_set_text(GTK_LABEL(status_label), "Lỗi kết nối!");
            gtk_widget_set_sensitive(send_button, TRUE);
            return FALSE;
        }, NULL);
        return;
    }
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(CLIENT_PORT);
    if (inet_pton(AF_INET, client_ip.c_str(), &client_addr.sin_addr) <= 0) {
        add_log("❌ Địa chỉ IP không hợp lệ!");
        close(sock);
        gdk_threads_add_idle([](gpointer data) -> gboolean {
            gtk_label_set_text(GTK_LABEL(status_label), "Địa chỉ IP không hợp lệ!");
            gtk_widget_set_sensitive(send_button, TRUE);
            return FALSE;
        }, NULL);
        return;
    }
    if (connect(sock, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0) {
        add_log("❌ Kết nối thất bại!");
        close(sock);
        gdk_threads_add_idle([](gpointer data) -> gboolean {
            gtk_label_set_text(GTK_LABEL(status_label), "Kết nối thất bại!");
            gtk_widget_set_sensitive(send_button, TRUE);
            return FALSE;
        }, NULL);
        return;
    }
    add_log("✅ Đã kết nối đến client!");
    char *file_path_cstr = strdup(filename.c_str());
    std::string original_file_name = basename(file_path_cstr);
    free(file_path_cstr);
    add_log("📤 Đang gửi tên file: " + original_file_name);
    send(sock, original_file_name.c_str(), original_file_name.size() + 1, 0);
    std::string encryptedFile = "server_encrypted.txt";
    std::vector<uint8_t> key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
    std::vector<uint8_t> binKey = convertByteToBit(key);
    add_log("🔐 Đang mã hóa file...");
    encryptFile(filename, encryptedFile, binKey);
    add_log("✅ Mã hóa file thành công!");
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
    char buffer[BUFFER_SIZE];
    int totalBytesSent = 0;
    while (!file.eof()) {
        file.read(buffer, BUFFER_SIZE);
        int bytesRead = file.gcount();
        send(sock, buffer, bytesRead, 0);
        totalBytesSent += bytesRead;
    }
    file.close();
    add_log("✅ Đã gửi file mã hóa! Tổng số byte đã gửi: " + std::to_string(totalBytesSent) + " bytes");
    shutdown(sock, SHUT_WR);
    close(sock);
    gdk_threads_add_idle([](gpointer data) -> gboolean {
        gtk_label_set_text(GTK_LABEL(status_label), "Đã gửi file thành công!");
        gtk_widget_set_sensitive(send_button, TRUE);
        return FALSE;
    }, NULL);
}

void receiveFile(int client_fd) {
    char original_file_name[BUFFER_SIZE] = {0};
    recv(client_fd, original_file_name, BUFFER_SIZE, 0);
    last_original_filename = original_file_name;
    add_log("📥 Tên file nhận được: " + std::string(original_file_name));
    
    std::string encryptedFile = "received_ciphertext.txt";
    last_encrypted_file = encryptedFile;
    
    std::ofstream file(encryptedFile, std::ios::binary);
    if (!file) {
        add_log("❌ Không thể tạo file mã hóa!");
        return;
    }
    
    char buffer[BUFFER_SIZE];
    int bytesReceived;
    int totalBytes = 0;
    
    while ((bytesReceived = recv(client_fd, buffer, BUFFER_SIZE, 0)) > 0) {
        file.write(buffer, bytesReceived);
        totalBytes += bytesReceived;
    }
    
    file.close();
    add_log("✅ Đã nhận file mã hóa! Tổng số byte nhận được: " + std::to_string(totalBytes) + " bytes");
    file_received = true;
    
    gdk_threads_add_idle([](gpointer data) -> gboolean {
        gtk_label_set_text(GTK_LABEL(status_label), "Đã nhận file mã hóa thành công!");
        gtk_widget_set_sensitive(view_encrypted_button, TRUE);
        gtk_widget_set_sensitive(decrypt_button, TRUE);
        return FALSE;
    }, NULL);
}

void server_function() {
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        add_log("❌ Lỗi tạo socket!");
        return;
    }
    
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        add_log("❌ Lỗi thiết lập socket!");
        close(server_fd);
        return;
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        add_log("❌ Bind thất bại!");
        close(server_fd);
        return;
    }
    if (listen(server_fd, 3) < 0) {
        add_log("❌ Lỗi khi listen!");
        close(server_fd);
        return;
    }
    add_log("Server đang chờ client...");
    while (server_running) {
        int client_fd = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (client_fd < 0) {
            if (server_running) {
                add_log("❌ Accept thất bại!");
            }
            break;
        }
        add_log("✅ Client đã kết nối!");
        receiveFile(client_fd);
        close(client_fd);
    }
}

static void view_encrypted_file(GtkWidget *widget, gpointer data) {
    if (file_received && !last_encrypted_file.empty()) {
        std::string command = "xdg-open " + last_encrypted_file;
        system(command.c_str());
    }
}

static void decrypt_file(GtkWidget *widget, gpointer data) {
    if (file_received && !last_encrypted_file.empty()) {
        add_log("🔄 Đang giải mã file...");
       
       std::vector<uint8_t> key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
        std::vector<uint8_t> binKey = convertByteToBit(key);
        
        last_decrypted_file = "decrypted_" + last_original_filename;
        decryptFile(last_encrypted_file, last_decrypted_file, binKey);
        
        file_decrypted = true;
        add_log("✅ Đã giải mã file thành công! File lưu tại: " + last_decrypted_file);
        
        gtk_label_set_text(GTK_LABEL(status_label), "Đã giải mã file thành công!");
        gtk_widget_set_sensitive(view_decrypted_button, TRUE);
    }
}

static void view_decrypted_file(GtkWidget *widget, gpointer data) {
    if (file_decrypted && !last_decrypted_file.empty()) {
        std::string command = "xdg-open " + last_decrypted_file;
        system(command.c_str());
    }
}

static void start_server(GtkWidget *widget, gpointer data) {
    if (!server_running) {
        server_running = true;
        gtk_widget_set_sensitive(start_button, FALSE);
        gtk_widget_set_sensitive(stop_button, TRUE);
        gtk_label_set_text(GTK_LABEL(status_label), "Server đang chạy...");
        server_thread = std::thread(server_function);
        server_thread.detach();
        add_log("Server đã bắt đầu chạy trên cổng " + std::to_string(PORT));
    }
}

static void stop_server(GtkWidget *widget, gpointer data) {
    if (server_running) {
        server_running = false;
        if (server_fd >= 0) {
            close(server_fd);
            server_fd = -1;
        }
        gtk_widget_set_sensitive(start_button, TRUE);
        gtk_widget_set_sensitive(stop_button, FALSE);
        gtk_label_set_text(GTK_LABEL(status_label), "Server đã dừng");
        add_log("Server đã dừng");
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

static void send_file(GtkWidget *widget, gpointer data) {
    if (selected_file_path.empty()) {
        add_log("❌ Chưa chọn file để gửi!");
        return;
    }
    const char *client_ip = gtk_entry_get_text(GTK_ENTRY(client_ip_entry));
    if (strlen(client_ip) == 0) {
        client_ip = DEFAULT_CLIENT_IP;
    }
    gtk_widget_set_sensitive(send_button, FALSE);
    gtk_label_set_text(GTK_LABEL(status_label), "Đang gửi file...");
    add_log("🔄 Bắt đầu gửi file đến " + std::string(client_ip) + ":" + std::to_string(CLIENT_PORT));
    std::thread send_thread(send_file_thread, std::string(client_ip), selected_file_path);
    send_thread.detach();
}

static void activate(GtkApplication *app, gpointer user_data) {
    GtkWidget *window;
    GtkWidget *notebook;
    
    window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "DES Server");
    gtk_window_set_default_size(GTK_WINDOW(window), 700, 500);
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);
    
    notebook = gtk_notebook_new();
    gtk_container_add(GTK_CONTAINER(window), notebook);
    
    // Tab 1: Nhận file
    GtkWidget *receive_grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(receive_grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(receive_grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(receive_grid), 10);
    
    GtkWidget *receive_label = gtk_label_new("Nhận File");
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), receive_grid, receive_label);
    
    GtkWidget *header_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(header_label), "<big><b>DES Server - Nhận File</b></big>");
    
    status_label = gtk_label_new("Server chưa chạy");
    start_button = gtk_button_new_with_label("Bắt đầu Server");
    stop_button = gtk_button_new_with_label("Dừng Server");
    gtk_widget_set_sensitive(stop_button, FALSE);
    
    GtkWidget *port_info = gtk_label_new("Đang lắng nghe trên cổng: 8080");
    
    GtkWidget *file_actions_frame = gtk_frame_new("Thao tác với file");
    GtkWidget *file_actions_grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(file_actions_grid), 5);
    gtk_grid_set_column_spacing(GTK_GRID(file_actions_grid), 5);
    gtk_container_set_border_width(GTK_CONTAINER(file_actions_grid), 5);
    gtk_container_add(GTK_CONTAINER(file_actions_frame), file_actions_grid);
    
    view_encrypted_button = gtk_button_new_with_label("Xem file mã hóa");
    decrypt_button = gtk_button_new_with_label("Giải mã file");
    view_decrypted_button = gtk_button_new_with_label("Xem file đã giải mã");
    
    gtk_widget_set_sensitive(view_encrypted_button, FALSE);
    gtk_widget_set_sensitive(decrypt_button, FALSE);
    gtk_widget_set_sensitive(view_decrypted_button, FALSE);
    
    gtk_grid_attach(GTK_GRID(file_actions_grid), view_encrypted_button, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(file_actions_grid), decrypt_button, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(file_actions_grid), view_decrypted_button, 2, 0, 1, 1);
    
    GtkWidget *scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_hexpand(scrolled_window, TRUE);
    gtk_widget_set_vexpand(scrolled_window, TRUE);
    log_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(log_view), FALSE);
    log_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(log_view));
    gtk_container_add(GTK_CONTAINER(scrolled_window), log_view);
    
    gtk_grid_attach(GTK_GRID(receive_grid), header_label, 0, 0, 3, 1);
    gtk_grid_attach(GTK_GRID(receive_grid), status_label, 0, 1, 3, 1);
    gtk_grid_attach(GTK_GRID(receive_grid), port_info, 0, 2, 3, 1);
    gtk_grid_attach(GTK_GRID(receive_grid), start_button, 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(receive_grid), stop_button, 1, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(receive_grid), file_actions_frame, 0, 4, 3, 1);
    gtk_grid_attach(GTK_GRID(receive_grid), scrolled_window, 0, 5, 3, 1);
    // Kết nối các signal cho tab nhận file
    g_signal_connect(start_button, "clicked", G_CALLBACK(start_server), NULL);
    g_signal_connect(stop_button, "clicked", G_CALLBACK(stop_server), NULL);
    g_signal_connect(view_encrypted_button, "clicked", G_CALLBACK(view_encrypted_file), NULL);
    g_signal_connect(decrypt_button, "clicked", G_CALLBACK(decrypt_file), NULL);
    g_signal_connect(view_decrypted_button, "clicked", G_CALLBACK(view_decrypted_file), NULL);
    
    // Tab 2: Gửi file
    GtkWidget *send_grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(send_grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(send_grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(send_grid), 10);
    
    GtkWidget *send_label = gtk_label_new("Gửi File");
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), send_grid, send_label);
    
    GtkWidget *send_header = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(send_header), "<big><b>DES Server - Gửi File</b></big>");
    
    GtkWidget *ip_label = gtk_label_new("Địa chỉ Client:");
    client_ip_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(client_ip_entry), DEFAULT_CLIENT_IP);
    
    GtkWidget *file_label = gtk_label_new("File đã chọn:");
    file_path_label = gtk_label_new("Chưa chọn file");
    
    select_button = gtk_button_new_with_label("Chọn File");
    send_button = gtk_button_new_with_label("Gửi File");
    gtk_widget_set_sensitive(send_button, FALSE);
    
    GtkWidget *send_info = gtk_label_new("Gửi file đến client trên cổng: 8081");
    
    GtkWidget *send_scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(send_scrolled_window), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_hexpand(send_scrolled_window, TRUE);
    gtk_widget_set_vexpand(send_scrolled_window, TRUE);
    
    gtk_grid_attach(GTK_GRID(send_grid), send_header, 0, 0, 3, 1);
    gtk_grid_attach(GTK_GRID(send_grid), ip_label, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(send_grid), client_ip_entry, 1, 1, 2, 1);
    gtk_grid_attach(GTK_GRID(send_grid), file_label, 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(send_grid), file_path_label, 1, 2, 2, 1);
    gtk_grid_attach(GTK_GRID(send_grid), select_button, 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(send_grid), send_button, 1, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(send_grid), send_info, 0, 4, 3, 1);
    
    // Kết nối các signal cho tab gửi file
    g_signal_connect(select_button, "clicked", G_CALLBACK(select_file), window);
    g_signal_connect(send_button, "clicked", G_CALLBACK(send_file), NULL);
    
    gtk_widget_show_all(window);
}

int main(int argc, char **argv) {
    GtkApplication *app;
    int status;
    app = gtk_application_new("org.desproject.client", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return status;
}
