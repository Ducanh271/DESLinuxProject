#ifndef RSA_CORE_H
#define RSA_CORE_H

#include <vector>
#include <string>
#include <cstdint>
#include <gmp.h>  // Sử dụng thư viện GMP để xử lý số nguyên lớn

// Cấu trúc khóa RSA
struct RSAKey {
    mpz_t n;  // Modulus
    mpz_t e;  // Public exponent (cho public key)
    mpz_t d;  // Private exponent (cho private key)
    mpz_t p;  // Prime factor 1 (chỉ cho private key)
    mpz_t q;  // Prime factor 2 (chỉ cho private key)
};

// Cấu trúc cặp khóa
struct RSAKeyPair {
    RSAKey publicKey;
    RSAKey privateKey;
};

// Khởi tạo khóa
void initRSAKey(RSAKey& key);

// Giải phóng bộ nhớ khóa
void freeRSAKey(RSAKey& key);

// Tạo cặp khóa RSA
RSAKeyPair generateRSAKeyPair(int keySize);

// Lưu khóa vào file
bool saveRSAPublicKey(const RSAKey& key, const std::string& filename);
bool saveRSAPrivateKey(const RSAKey& key, const std::string& filename);

// Đọc khóa từ file
bool loadRSAPublicKey(RSAKey& key, const std::string& filename);
bool loadRSAPrivateKey(RSAKey& key, const std::string& filename);

// Mã hóa dữ liệu
std::vector<uint8_t> rsaEncrypt(const std::vector<uint8_t>& data, const RSAKey& publicKey);

// Giải mã dữ liệu
std::vector<uint8_t> rsaDecrypt(const std::vector<uint8_t>& data, const RSAKey& privateKey);

// Tạo khóa DES ngẫu nhiên
std::vector<uint8_t> generateRandomDESKey();

#endif // RSA_CORE_H
