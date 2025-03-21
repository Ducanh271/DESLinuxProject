#ifndef PERMUTATION_H
#define PERMUTATION_H

#include <vector>
#include <array>
#include <cstdint>
#include <cstddef>
extern const int P_BOX[32];

// Bảng hoán vị khởi tạo (IP)
const std::array<int, 64> IP_TABLE = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

// Bảng hoán vị nghịch đảo (IP⁻¹)
const std::array<int, 64> INVERSE_IP_TABLE = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9,  49, 17, 57, 25
};

// Hàm thực hiện hoán vị chung (template)
// Template hàm permute
template <size_t N>
std::vector<uint8_t> permute(const std::vector<uint8_t>& input, const std::array<int, N>& table) {
    std::vector<uint8_t> output(N);
    for (size_t i = 0; i < N; ++i) {
        output[i] = input[table[i] - 1]; // -1 vì index C++ bắt đầu từ 0
    }
    return output;
}

// Hàm hoán vị khởi tạo (IP)
std::vector<uint8_t> initialPermutation(const std::vector<uint8_t>& input);

// Hàm hoán vị nghịch đảo (IP⁻¹)
std::vector<uint8_t> inverseInitialPermutation(const std::vector<uint8_t>& input);

// Khai báo hàm mở rộng R từ 32-bit lên 48-bit
std::vector<unsigned char> expansion_permutation(const std::vector<unsigned char>& R);

std::vector<uint8_t> pBoxPermutation(const std::vector<uint8_t>& input);

#endif // PERMUTATION_H

