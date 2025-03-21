#include "encryption.h"
#include "feistel.h"
#include "key_schedule.h"
#include "file_io.h"
#include "utils.h"
#include <iostream>

void encryptFile(const std::string& inputFilename, const std::string& outputFilename, const std::vector<uint8_t>& key) {
    // 🔹 Đọc file
    std::vector<uint8_t> plaintext = readFile(inputFilename);
    if (plaintext.empty()) {
        std::cerr << "❌ Lỗi: Không có dữ liệu trong file!" << std::endl;
        return;
    }

    // 🔹 Thêm padding (PKCS7)
    plaintext = addPadding(plaintext);

    // 🔹 Sinh khóa con
    std::vector<std::vector<uint8_t>> subkeys = generateSubkeys(key);

    // 🔹 Mã hóa từng khối 64-bit
    std::vector<uint8_t> ciphertext;
    for (size_t i = 0; i < plaintext.size(); i += 8) {
        std::vector<uint8_t> block(plaintext.begin() + i, plaintext.begin() + i + 8);
        std::vector<uint8_t> bitBlock = convertByteToBit(block);
        std::vector<uint8_t> encryptedBlock = desEncrypt(bitBlock, subkeys);
        std::vector<uint8_t> encryptedBytes = convertBitToByte(encryptedBlock);
        ciphertext.insert(ciphertext.end(), encryptedBytes.begin(), encryptedBytes.end());
    }

    // 🔹 Ghi file mã hóa
    writeFile(outputFilename, ciphertext);
    std::cout << "✅ Đã mã hóa file thành công: " << outputFilename << std::endl;
}

