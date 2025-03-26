#include "decryption.h"
#include "feistel.h"
#include "key_schedule.h"
#include "file_io.h"
#include "utils.h"
#include <iostream>

void decryptFile(const std::string& inputFilename, const std::string& outputFilename, const std::vector<uint8_t>& key) {
    // Kiểm tra kích thước khóa
    if (key.size() != 8) {
        std::cerr << "⚠️ Cảnh báo: Kích thước khóa DES không phải 8 bytes!" << std::endl;
        // Tiếp tục xử lý, không dừng lại
    }
    
    // Đọc file mã hóa
    std::vector<uint8_t> ciphertext = readFile(inputFilename);
    if (ciphertext.empty()) {
        std::cerr << "❌ Lỗi: File mã hóa trống hoặc không tồn tại!" << std::endl;
        return;
    }

    // Sinh khóa con từ khóa DES (đảm bảo sử dụng đúng 8 bytes đầu tiên nếu khóa lớn hơn)
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

    // Giải mã từng khối 64-bit
    std::vector<uint8_t> decryptedText;
    for (size_t i = 0; i < ciphertext.size(); i += 8) {
        // Đảm bảo đủ 8 bytes cho mỗi khối
        std::vector<uint8_t> block;
        if (i + 8 <= ciphertext.size()) {
            block.assign(ciphertext.begin() + i, ciphertext.begin() + i + 8);
        } else {
            // Trường hợp khối cuối không đủ 8 bytes (hiếm gặp)
            block.assign(ciphertext.begin() + i, ciphertext.end());
            block.resize(8, 0); // Thêm padding 0
        }
        
        std::vector<uint8_t> bitBlock = convertByteToBit(block);
        std::vector<uint8_t> decryptedBlock = desDecrypt(bitBlock, subkeys);
        std::vector<uint8_t> decryptedBytes = convertBitToByte(decryptedBlock);
        decryptedText.insert(decryptedText.end(), decryptedBytes.begin(), decryptedBytes.end());
    }

    // Loại bỏ padding sau khi giải mã
    decryptedText = removePadding(decryptedText);

    // Ghi file giải mã
    writeFile(outputFilename, decryptedText);
    std::cout << "✅ Đã giải mã file thành công: " << outputFilename << std::endl;
}
