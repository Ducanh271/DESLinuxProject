#include "rsa_core.h"
#include <iostream>

int main() {
    std::cout << "Đang tạo cặp khóa RSA..." << std::endl;
    
    // Tạo cặp khóa 1024-bit
    RSAKeyPair keyPair = generateRSAKeyPair(1024);
    
    // Lưu khóa vào file
    if (saveRSAPublicKey(keyPair.publicKey, "server_public.key") &&
        saveRSAPrivateKey(keyPair.privateKey, "server_private.key")) {
        std::cout << "Đã lưu khóa thành công!" << std::endl;
        std::cout << "Public key: server_public.key" << std::endl;
        std::cout << "Private key: server_private.key" << std::endl;
    } else {
        std::cerr << "Lỗi khi lưu khóa!" << std::endl;
    }
    
    // Giải phóng bộ nhớ
    freeRSAKey(keyPair.publicKey);
    freeRSAKey(keyPair.privateKey);
    
    return 0;
}
