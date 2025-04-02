#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <cstdint>
#include <bitset>
#include <string>

// Chuyển đổi số nguyên sang chuỗi nhị phân
std::string intToBinary(uint64_t value, int bitLength);

// Chuyển chuỗi nhị phân về số nguyên
uint64_t binaryToInt(const std::string& binaryStr);

// Chia một vector bit thành nhiều khối con
std::vector<std::vector<uint8_t>> splitBlocks(const std::vector<uint8_t>& data, int blockSize);

// XOR hai vector bit
std::vector<uint8_t> xorVectors(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

// Chuyển 6 byte sang 48 bit
std::vector<uint8_t> convertByteToBit(const std::vector<uint8_t>& byteVector);

// chuyển bit sang Byte
std::vector<uint8_t> convertBitToByte(const std::vector<uint8_t>& bitBlock);

// thêm padding
std::vector<uint8_t> addPadding(const std::vector<uint8_t>& data);

// bỏ padding khi giải mã
std::vector<uint8_t> removePadding(const std::vector<uint8_t>& data);
// Thêm vào cuối file utils.h
std::vector<uint8_t> normalizeDESKey(const std::vector<uint8_t>& key);
#endif // UTILS_H

