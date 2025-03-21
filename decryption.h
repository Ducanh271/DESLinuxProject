#ifndef DECRYPTION_H
#define DECRYPTION_H

#include <vector>
#include <string>
#include <cstdint>

// Hàm giải mã file
void decryptFile(const std::string& inputFilename, const std::string& outputFilename, const std::vector<uint8_t>& key);

#endif // DECRYPTION_H

