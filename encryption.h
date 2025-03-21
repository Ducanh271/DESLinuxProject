#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <vector>
#include <string>
#include <cstdint>

// Hàm mã hóa file
void encryptFile(const std::string& inputFilename, const std::string& outputFilename, const std::vector<uint8_t>& key);

#endif // ENCRYPTION_H

