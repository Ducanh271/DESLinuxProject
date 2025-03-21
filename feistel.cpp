#include "feistel.h"
#include "permutation.h"
#include "utils.h"
#include <iostream>
#include "sbox.h"
std::vector<uint8_t> feistelFunction(const std::vector<uint8_t> &R, const std::vector<uint8_t> &subkey)
{
    // Bước 1: Mở rộng R từ 32-bit lên 48-bit
    std::vector<uint8_t> expandedR = expansion_permutation(R);

    // Bước 2: XOR với khóa con Ki
    std::vector<uint8_t> xorResult = xorVectors(expandedR, subkey);

    // Bước 3: Áp dụng S-Box để giảm từ 48-bit xuống 32-bit
    std::vector<uint8_t> sboxOutput = applySBoxTo48Bit(xorResult);
    
    // Bước 4: Áp dụng P-Box
    std::vector<uint8_t> pBoxOutput = pBoxPermutation(sboxOutput);

    return pBoxOutput;
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> feistelRound(
    const std::vector<uint8_t>& L, 
    const std::vector<uint8_t>& R, 
    const std::vector<uint8_t>& subkey
) {
    // Gọi hàm feistelFunction để xử lý R
    std::vector<uint8_t> feistelOutput = feistelFunction(R, subkey);

    // R_new = L_old XOR Feistel(R_old)
    std::vector<uint8_t> R_new = xorVectors(L, feistelOutput);

    // L_new = R_old (giữ nguyên R cũ làm L mới)
    std::vector<uint8_t> L_new = R;

    return {L_new, R_new};
}

std::vector<uint8_t> desEncrypt(
    const std::vector<uint8_t>& plaintext, 
    const std::vector<std::vector<uint8_t>>& subkeys
) {
    // 🔹 Bước 1: Hoán vị khởi tạo (IP)
    std::vector<uint8_t> permutedText = initialPermutation(plaintext);

    // 🔹 Bước 2: Chia thành L và R (32-bit mỗi phần)
    std::vector<uint8_t> L(permutedText.begin(), permutedText.begin() + 32);
    std::vector<uint8_t> R(permutedText.begin() + 32, permutedText.end());

    // 🔹 Bước 3: Thực hiện 16 vòng Feistel
    for (int i = 0; i < 16; i++) {
        auto [L_new, R_new] = feistelRound(L, R, subkeys[i]);

        // Cập nhật L, R
        L = L_new;
        R = R_new;
    }

    // 🔹 Bước 4: Đảo ngược L và R
    std::vector<uint8_t> combined(R);
    combined.insert(combined.end(), L.begin(), L.end());

    // 🔹 Bước 5: Hoán vị nghịch đảo (IP⁻¹) để lấy kết quả cuối cùng
    std::vector<uint8_t> ciphertext = inverseInitialPermutation(combined);

    return ciphertext;
}

std::vector<uint8_t> desDecrypt(
    const std::vector<uint8_t>& ciphertext, 
    const std::vector<std::vector<uint8_t>>& subkeys
) {
    // 🔹 Bước 1: Hoán vị khởi tạo (IP)
    std::vector<uint8_t> permutedText = initialPermutation(ciphertext);

    // 🔹 Bước 2: Chia thành L và R (32-bit mỗi phần)
    std::vector<uint8_t> L(permutedText.begin(), permutedText.begin() + 32);
    std::vector<uint8_t> R(permutedText.begin() + 32, permutedText.end());

    // 🔹 Bước 3: Thực hiện 16 vòng Feistel (dùng khóa ngược)
    for (int i = 15; i >= 0; i--) {  // 🛠 Đảo ngược thứ tự khóa
        auto [L_new, R_new] = feistelRound(L, R, subkeys[i]);

        // Cập nhật L, R
        L = L_new;
        R = R_new;
    }

    // 🔹 Bước 4: Đảo ngược L và R
    std::vector<uint8_t> combined(R);
    combined.insert(combined.end(), L.begin(), L.end());

    // 🔹 Bước 5: Hoán vị nghịch đảo (IP⁻¹) để lấy plaintext cuối cùng
    std::vector<uint8_t> plaintext = inverseInitialPermutation(combined);

    return plaintext;
}

