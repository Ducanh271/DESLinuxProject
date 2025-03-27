#include "decryption.h"
#include <iostream>

int main() {
    std::string encryptedFile = "ciphertext.run";
    std::string decryptedFile = "decrypted.run";

    // 🔹 Khóa 64-bit
std::vector<uint8_t> key = {
    0, 0, 0, 1, 0, 0, 1, 1,  // 0x13 → 0001 0011
    0, 0, 1, 1, 0, 1, 0, 0,  // 0x34 → 0011 0100
    0, 1, 0, 1, 0, 1, 1, 1,  // 0x57 → 0101 0111
    0, 1, 1, 1, 1, 0, 0, 1,  // 0x79 → 0111 1001
    1, 0, 0, 1, 1, 0, 1, 1,  // 0x9B → 1001 1011
    1, 0, 1, 1, 1, 1, 0, 0,  // 0xBC → 1011 1100
    1, 1, 0, 1, 1, 1, 1, 1,  // 0xDF → 1101 1111
    1, 1, 1, 1, 0, 0, 0, 1   // 0xF1 → 1111 0001
};

    // 🔹 Giải mã file
    decryptFile(encryptedFile, decryptedFile, key);

    return 0;
}

