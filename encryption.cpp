#include "encryption.h"
#include "feistel.h"
#include "key_schedule.h"
#include "file_io.h"
#include "utils.h"
#include <iostream>

void encryptFile(const std::string& inputFilename, const std::string& outputFilename, const std::vector<uint8_t>& key) {
    // Kiểm tra kích thước khóa
    if (key.size() != 8) {
        std::cerr << "⚠️ Cảnh báo: Kích thước khóa DES không phải 8 bytes!" << std::endl;
        // Tiếp tục xử lý, không dừng lại
    }
    
    // Đọc file
    std::vector<uint8_t> plaintext = readFile(inputFilename);
    if (plaintext.empty()) {
        std::cerr << "❌ Lỗi: Không có dữ liệu trong file!" << std::endl;
        return;
    }

    // Thêm padding (PKCS7)
    plaintext = addPadding(plaintext);

    // Chuẩn bị khóa DES (đảm bảo sử dụng đúng 8 bytes đầu tiên nếu khóa lớn hơn)
    std::vector<uint8_t> desKey;
    if (key.size() >= 8) {
        desKey.assign(key.begin(), key.begin() + 8);
    } else {
        // Trường hợp khóa nhỏ hơn 8 bytes (hiếm gặp)
        desKey = key;
        desKey.resize(8, 0); // Thêm padding 0 nếu cần
    }
    
    // Chuyển đổi khóa từ dạng byte sang bit
    std::vector<uint8_t> bitKey = convertByteToBit(desKey);
    
    // Sinh các khóa con
    std::vector<std::vector<uint8_t>> subkeys = generateSubkeys(bitKey);

    // Mã hóa từng khối 64-bit
    std::vector<uint8_t> ciphertext;
    for (size_t i = 0; i < plaintext.size(); i += 8) {
        std::vector<uint8_t> block(plaintext.begin() + i, plaintext.begin() + i + 8);
        std::vector<uint8_t> bitBlock = convertByteToBit(block);
        std::vector<uint8_t> encryptedBlock = desEncrypt(bitBlock, subkeys);
        std::vector<uint8_t> encryptedBytes = convertBitToByte(encryptedBlock);
        ciphertext.insert(ciphertext.end(), encryptedBytes.begin(), encryptedBytes.end());
    }

    // Ghi file mã hóa
    writeFile(outputFilename, ciphertext);
    std::cout << "✅ Đã mã hóa file thành công: " << outputFilename << std::endl;
}
