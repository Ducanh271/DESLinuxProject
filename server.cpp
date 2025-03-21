#include <iostream>
#include <fstream>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "decryption.h"
#include "utils.h"
#define PORT 8080
#define BUFFER_SIZE 1024

void receiveFile(int client_fd, const std::string& encryptedFile) {
    std::ofstream file(encryptedFile, std::ios::binary);
    if (!file) {
        std::cerr << "❌ Không thể tạo file mã hóa!\n";
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
    std::cout << "✅ Đã nhận file mã hóa! Tổng số byte nhận được: " << totalBytes << " bytes\n";

    // 🔹 Kiểm tra kích thước file
    std::ifstream checkFile(encryptedFile, std::ios::binary | std::ios::ate);
    if (checkFile) {
        std::cout << "📌 Kích thước file nhận được: " << checkFile.tellg() << " bytes\n";
    } else {
        std::cerr << "❌ Không thể mở file đã nhận!\n";
    }
    checkFile.close();

    // 🔹 Giải mã file
    std::string decryptedFile = "decrypted.jpg";
    std::vector<uint8_t> key = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
            std:: vector<uint8_t> binKey = convertByteToBit(key);
    decryptFile(encryptedFile, decryptedFile, binKey);
    std::cout << "✅ Đã giải mã file thành công!\n";
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // 1. Tạo socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        std::cerr << "❌ Lỗi tạo socket!\n";
        return 1;
    }

    // 2. Cấu hình địa chỉ server
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // 3. Gán socket với địa chỉ
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "❌ Bind thất bại!\n";
        return 1;
    }

    // 4. Lắng nghe kết nối
    if (listen(server_fd, 3) < 0) {
        std::cerr << "❌ Lỗi khi listen!\n";
        return 1;
    }

    std::cout << "Server đang chờ client...\n";

    // 5. Chấp nhận kết nối từ client
    client_fd = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
    if (client_fd < 0) {
        std::cerr << "❌ Accept thất bại!\n";
        return 1;
    }

    std::cout << "✅ Client đã kết nối!\n";

    // Nhận file từ client
    receiveFile(client_fd, "received_ciphertext.txt");

    // 6. Đóng kết nối
    close(client_fd);
    close(server_fd);

    return 0;
}

