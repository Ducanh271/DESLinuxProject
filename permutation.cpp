#include "permutation.h"

// Cài đặt cụ thể cho IP
std::vector<uint8_t> initialPermutation(const std::vector<uint8_t>& input) {
    return permute(input, IP_TABLE);
}

// Cài đặt cụ thể cho IP⁻¹
std::vector<uint8_t> inverseInitialPermutation(const std::vector<uint8_t>& input) {
    return permute(input, INVERSE_IP_TABLE);
}

// Khai báo template cụ thể để tránh lỗi linker
template std::vector<uint8_t> permute<64>(const std::vector<uint8_t>&, const std::array<int, 64>&);

// Bảng Expansion (E-Box) từ 32-bit lên 48-bit
const int E[48] = { 
    32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9, 
    8, 9, 10, 11, 12, 13,  12, 13, 14, 15, 16, 17, 
    16, 17, 18, 19, 20, 21,  20, 21, 22, 23, 24, 25, 
    24, 25, 26, 27, 28, 29,  28, 29, 30, 31, 32, 1 
};

// Triển khai hàm mở rộng R từ 32-bit lên 48-bit
std::vector<unsigned char> expansion_permutation(const std::vector<unsigned char>& R) {
    std::vector<unsigned char> R_expanded(48);
    for (int i = 0; i < 48; i++) {
        R_expanded[i] = R[E[i] - 1];  // Lấy bit theo bảng E
    }
    return R_expanded;
}
// Bảng P-Box chuẩn DES
const int P_BOX[32] = {
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
};
// Hàm hoán vị P-Box (32-bit → 32-bit)
std::vector<uint8_t> pBoxPermutation(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> output(32);
    for (int i = 0; i < 32; i++) {
        output[i] = input[P_BOX[i] - 1]; // -1 vì index bắt đầu từ 0
    }
    return output;
}
