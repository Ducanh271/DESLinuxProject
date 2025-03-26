#ifndef RSA_CORE_H
#define RSA_CORE_H

#include <gmp.h>
#include <vector>
#include <string>

struct RSAKey {
    mpz_t n;  // Modulus
    mpz_t e;  // Public exponent
    mpz_t d;  // Private exponent
    mpz_t p;  // First prime factor
    mpz_t q;  // Second prime factor
};

struct RSAKeyPair {
    RSAKey publicKey;
    RSAKey privateKey;
};

// Khởi tạo khóa RSA
void initRSAKey(RSAKey& key);

// Giải phóng bộ nhớ khóa
void freeRSAKey(RSAKey& key);

// Tạo cặp khóa RSA
RSAKeyPair generateRSAKeyPair(int keySize);

// Lưu khóa công khai vào file
bool saveRSAPublicKey(const RSAKey& key, const std::string& filename);

// Lưu khóa riêng tư vào file
bool saveRSAPrivateKey(const RSAKey& key, const std::string& filename);

// Đọc khóa công khai từ file
bool loadRSAPublicKey(RSAKey& key, const std::string& filename);

// Đọc khóa riêng tư từ file
bool loadRSAPrivateKey(RSAKey& key, const std::string& filename);

// Mã hóa dữ liệu bằng RSA
std::vector<uint8_t> rsaEncrypt(const std::vector<uint8_t>& data, const RSAKey& publicKey);

// Giải mã dữ liệu bằng RSA
std::vector<uint8_t> rsaDecrypt(const std::vector<uint8_t>& data, const RSAKey& privateKey);

// Giải mã khóa DES được mã hóa bằng RSA, đảm bảo kích thước 8 bytes
std::vector<uint8_t> rsaDecryptDESKey(const std::vector<uint8_t>& encryptedKey, const RSAKey& privateKey);

// Tạo khóa DES ngẫu nhiên
std::vector<uint8_t> generateRandomDESKey();

#endif // RSA_CORE_H
