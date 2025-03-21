#include "key_schedule.h"
#include "permutation.h"  // Sử dụng hàm permute()
#include <vector>
#include <array>
#include <iostream>
#include <algorithm>
// Bảng PC-1: Hoán vị khóa ban đầu, bỏ 8 bit chẵn lẻ
const std::array<int, 56> PC1 = {
    57, 49, 41, 33, 25, 17, 9, 
    1,  58, 50, 42, 34, 26, 18, 
    10, 2,  59, 51, 43, 35, 27, 
    19, 11, 3,  60, 52, 44, 36, 
    63, 55, 47, 39, 31, 23, 15, 
    7,  62, 54, 46, 38, 30, 22, 
    14, 6,  61, 53, 45, 37, 29, 
    21, 13, 5,  28, 20, 12, 4
};

// Bảng PC-2: Hoán vị để tạo khóa con 48 bit
const std::array<int, 48> PC2 = {
    14, 17, 11, 24, 1,  5,  
    3,  28, 15, 6,  21, 10, 
    23, 19, 12, 4,  26, 8,  
    16, 7,  27, 20, 13, 2,  
    41, 52, 31, 37, 47, 55, 
    30, 40, 51, 45, 33, 48, 
    44, 49, 39, 56, 34, 53, 
    46, 42, 50, 36, 29, 32
};

// Số bước dịch vòng trái cho từng vòng
const std::array<int, 16> SHIFT_SCHEDULE = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// Hàm dịch vòng trái
void leftShift(std::vector<uint8_t>& key, int shifts) {
    std::rotate(key.begin(), key.begin() + shifts, key.end());
}

// Hàm sinh 16 khóa con
std::vector<std::vector<uint8_t>> generateSubkeys(const std::vector<uint8_t>& key) {
    std::vector<std::vector<uint8_t>> subkeys(16);

    // Bước 1: Áp dụng hoán vị PC-1 lên key
    std::vector<uint8_t> permutedKey = permute(key, PC1);

    // Chia thành hai phần C và D (mỗi phần 28 bit)
    std::vector<uint8_t> C(permutedKey.begin(), permutedKey.begin() + 28);
    std::vector<uint8_t> D(permutedKey.begin() + 28, permutedKey.end());

    // Bước 2: Sinh 16 khóa con
    for (int round = 0; round < 16; ++round) {
        // Dịch vòng trái C và D theo số bước đã cho
        leftShift(C, SHIFT_SCHEDULE[round]);
        leftShift(D, SHIFT_SCHEDULE[round]);

        // Gộp C và D lại thành 56 bit
        std::vector<uint8_t> combined(C.begin(), C.end());
        combined.insert(combined.end(), D.begin(), D.end());

        // Áp dụng PC-2 để tạo khóa con 48 bit
        subkeys[round] = permute(combined, PC2);
    }

    return subkeys;
}

