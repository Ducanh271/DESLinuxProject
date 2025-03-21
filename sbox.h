#ifndef SBOX_H
#define SBOX_H
#include <vector>
#include <cstdint>

// Khai báo 8 bảng S-box
extern const uint8_t S_BOXES[8][4][16];

// Hàm thay thế S-box cho từng nhóm 6bit
uint8_t applySBox(int sboxIndex, uint8_t input);
// Hàm áp dụng S-Box cho toàn bộ 48-bit -> Trả về 32-bit
std::vector<uint8_t> applySBoxTo48Bit(const std::vector<uint8_t>& input);
#endif // SBOX_H

