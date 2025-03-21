#include <iostream>
#include <fstream>
#include <vector>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "encryption.h"
#include "utils.h"
#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 1024

void sendFile(int sock, const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "❌ Không thể mở file để gửi!\n";
        return;
    }

    // 🔹 Kiểm tra kích thước file
    file.seekg(0, std::ios::end);
    int fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    std::cout << "📌 Kích thước file mã hóa: " << fileSize << " bytes\n";

    char buffer[BUFFER_SIZE];
    int totalBytesSent = 0;

    while (!file.eof()) {
        file.read(buffer, BUFFER_SIZE);
        int bytesRead = file.gcount();
        send(sock, buffer, bytesRead, 0);
        totalBytesSent += bytesRead;
    }

    file.close();
    std::cout << "✅ Đã gửi file mã hóa! Tổng số byte đã gửi: " << totalBytesSent << " bytes\n";

    // 🔹 Đóng socket ngay sau khi gửi xong
    shutdown(sock, SHUT_WR);
}

int main() {
    int sock = 0;
    struct sockaddr_in server_addr;

    // 1. Tạo socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "❌ Tạo socket thất bại!\n";
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    // 2. Chuyển đổi địa chỉ IP
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        std::cerr << "❌ Địa chỉ IP không hợp lệ!\n";
        return 1;
    }

    // 3. Kết nối đến server
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "❌ Kết nối thất bại!\n";
        return 1;
    }

    std::cout << "✅ Đã kết nối đến server!\n";

    // 🔹 Mã hóa file trước khi gửi
    std::string inputFile = "hinh-anime-2.jpg";
    std::string encryptedFile = "encrypted.txt";
    std::vector<uint8_t> key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
    std:: vector<uint8_t> binKey = convertByteToBit(key);

    encryptFile(inputFile, encryptedFile, binKey);

    // Gửi file mã hóa đến server
    sendFile(sock, encryptedFile);

    // 4. Đóng kết nối
    close(sock);

    return 0;
}

