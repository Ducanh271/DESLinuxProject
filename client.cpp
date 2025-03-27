#include <iostream>
#include <fstream>
#include <vector>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include "encryption.h"
#include "utils.h"

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    std::string inputFile = "plaintext.txt";
    std::string encryptedFile = "encrypted.txt";
    std::string serverIP = SERVER_IP;
    
    // Mã hóa file
    std::vector<uint8_t> key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
    std::cout << "🔐 Đang mã hóa file..." << std::endl;
    encryptFile(inputFile, encryptedFile, key);
    std::cout << "✅ Mã hóa file thành công!" << std::endl;
    
    // Kết nối đến server
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "❌ Không thể tạo socket!" << std::endl;
        return -1;
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, serverIP.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "❌ Địa chỉ IP không hợp lệ!" << std::endl;
        close(sock);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "❌ Kết nối thất bại!" << std::endl;
        close(sock);
        return -1;
    }
    
    std::cout << "✅ Đã kết nối đến server!" << std::endl;
    
    // Gửi tên file
    std::string original_file_name = "plaintext.txt";
    std::cout << "📤 Đang gửi tên file: " << original_file_name << std::endl;
    send(sock, original_file_name.c_str(), original_file_name.size() + 1, 0);
    
    // Gửi file đã mã hóa
    std::ifstream file(encryptedFile, std::ios::binary);
    if (!file) {
        std::cerr << "❌ Không thể mở file để gửi!" << std::endl;
        close(sock);
        return -1;
    }
    
    file.seekg(0, std::ios::end);
    int fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::cout << "📌 Kích thước file mã hóa: " << fileSize << " bytes" << std::endl;
    
    char buffer[BUFFER_SIZE];
    int totalBytesSent = 0;
    
    while (!file.eof()) {
        file.read(buffer, BUFFER_SIZE);
        int bytesRead = file.gcount();
        send(sock, buffer, bytesRead, 0);
        totalBytesSent += bytesRead;
    }
    
    file.close();
    std::cout << "✅ Đã gửi file mã hóa! Tổng số byte đã gửi: " << totalBytesSent << " bytes" << std::endl;
    
    shutdown(sock, SHUT_WR);
    close(sock);
    
    return 0;
}
