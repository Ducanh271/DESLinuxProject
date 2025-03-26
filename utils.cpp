#include "utils.h"
#include <sstream>
#include <iostream>

std::string intToBinary(uint64_t value, int bitLength) {
    return std::bitset<64>(value).to_string().substr(64 - bitLength);
}

uint64_t binaryToInt(const std::string& binaryStr) {
    return std::bitset<64>(binaryStr).to_ullong();
}

std::vector<std::vector<uint8_t>> splitBlocks(const std::vector<uint8_t>& data, int blockSize) {
    std::vector<std::vector<uint8_t>> blocks;
    for (size_t i = 0; i < data.size(); i += blockSize) {
        blocks.push_back(std::vector<uint8_t>(data.begin() + i, data.begin() + std::min(i + blockSize, data.size())));
    }
    return blocks;
}

std::vector<uint8_t> xorVectors(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("Vector lengths must be equal for XOR operation");
    }
    std::vector<uint8_t> result(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

std::vector<uint8_t> convertByteToBit(const std::vector<uint8_t>& byteVector) {
    if (byteVector.empty()) {
        std::cerr << "Cảnh báo: Vector byte đầu vào rỗng" << std::endl;
        return {};
    }
    
    if (byteVector.size() != 8 && byteVector.size() % 8 != 0) {
        std::cerr << "Cảnh báo: Kích thước không phải bội số của 8 bytes: " 
                  << byteVector.size() << " bytes" << std::endl;
    }
    
    std::vector<uint8_t> bitVector;
    bitVector.reserve(byteVector.size() * 8);

    for (uint8_t byte : byteVector) {
        for (int i = 7; i >= 0; --i) { 
            bitVector.push_back((byte >> i) & 1);
        }
    }
    return bitVector;
}

std::vector<uint8_t> convertBitToByte(const std::vector<uint8_t>& bitBlock) {
    if (bitBlock.empty()) {
        std::cerr << "Cảnh báo: Vector bit đầu vào rỗng" << std::endl;
        return {};
    }
    
    if (bitBlock.size() % 8 != 0) {
        std::cerr << "Cảnh báo: Số lượng bit không phải bội số của 8: " 
                  << bitBlock.size() << " bits" << std::endl;
    }
    
    std::vector<uint8_t> byteBlock;
    byteBlock.reserve(bitBlock.size() / 8);
    
    for (size_t i = 0; i < bitBlock.size(); i += 8) {
        uint8_t byte = 0;
        for (size_t j = 0; j < 8; ++j) {
            byte |= (bitBlock[i + j] << (7 - j));
        }
        byteBlock.push_back(byte);
    }
    return byteBlock;
}

std::vector<uint8_t> addPadding(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> paddedData = data;
    size_t paddingSize = 8 - (data.size() % 8);
    for (size_t i = 0; i < paddingSize; ++i) {
        paddedData.push_back(paddingSize);
    }
    return paddedData;
}

std::vector<uint8_t> removePadding(const std::vector<uint8_t>& data) {
    if (data.empty()) return data;
    uint8_t paddingSize = data.back();
    if (paddingSize > 8 || paddingSize > data.size()) return data;
    return std::vector<uint8_t>(data.begin(), data.end() - paddingSize);
}
