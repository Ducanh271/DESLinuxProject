#ifndef FEISTEL_H
#define FEISTEL_H

#include <vector>
#include <cstdint>

std::vector<uint8_t> feistelFunction(const std::vector<uint8_t>& R, const std::vector<uint8_t>& subkey);

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> feistelRound(
    const std::vector<uint8_t>& L, 
    const std::vector<uint8_t>& R, 
    const std::vector<uint8_t>& subkey
);

std::vector<uint8_t> desEncrypt(
    const std::vector<uint8_t>& plaintext, 
    const std::vector<std::vector<uint8_t>>& subkeys
);

std::vector<uint8_t> desDecrypt(
    const std::vector<uint8_t>& ciphertext, 
    const std::vector<std::vector<uint8_t>>& subkeys
);
#endif // FEISTEL_H

