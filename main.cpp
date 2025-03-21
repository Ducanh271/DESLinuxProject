#include "encryption.h"
#include "decryption.h"
#include <iostream>

int main() {
    std::string inputFile = "plaintext.txt";
    std::string encryptedFile = "ciphertext.txt";
    std::string decryptedFile = "decrypted.txt";

    // 🔹 Khóa 64-bit
    std::vector<uint8_t> key = {
        0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1
    };

    // 🔹 Mã hóa file
    encryptFile(inputFile, encryptedFile, key);

    // 🔹 Giải mã file
    decryptFile(encryptedFile, decryptedFile, key);

    return 0;
}

