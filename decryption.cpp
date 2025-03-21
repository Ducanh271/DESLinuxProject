#include "decryption.h"
#include "feistel.h"
#include "key_schedule.h"
#include "file_io.h"
#include "utils.h"
#include <iostream>

void decryptFile(const std::string& inputFilename, const std::string& outputFilename, const std::vector<uint8_t>& key) {
    // 🔹 Đọc file mã hóa
    std::vector<uint8_t> ciphertext = readFile(inputFilename);
    if (ciphertext.empty()) {
        std::cerr << "❌ Lỗi: File mã hóa trống hoặc không tồn tại!" << std::endl;
        return;
    }

    // 🔹 Sinh khóa con
    std::vector<std::vector<uint8_t>> subkeys = generateSubkeys(key);

    // 🔹 Giải mã từng khối 64-bit
    std::vector<uint8_t> decryptedText;
    for (size_t i = 0; i < ciphertext.size(); i += 8) {
        std::vector<uint8_t> block(ciphertext.begin() + i, ciphertext.begin() + i + 8);
        std::vector<uint8_t> bitBlock = convertByteToBit(block);
        std::vector<uint8_t> decryptedBlock = desDecrypt(bitBlock, subkeys);
        std::vector<uint8_t> decryptedBytes = convertBitToByte(decryptedBlock);
        decryptedText.insert(decryptedText.end(), decryptedBytes.begin(), decryptedBytes.end());
    }

    // 🔹 Loại bỏ padding sau khi giải mã
    decryptedText = removePadding(decryptedText);

    // 🔹 Ghi file giải mã
    writeFile(outputFilename, decryptedText);
    std::cout << "✅ Đã giải mã file thành công: " << outputFilename << std::endl;
}

