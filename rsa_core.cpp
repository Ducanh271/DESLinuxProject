#include "rsa_core.h"
#include <fstream>
#include <iostream>
#include <random>
#include <ctime>
#include <cstring>

void initRSAKey(RSAKey& key) {
    mpz_init(key.n);
    mpz_init(key.e);
    mpz_init(key.d);
    mpz_init(key.p);
    mpz_init(key.q);
}

void freeRSAKey(RSAKey& key) {
    mpz_clear(key.n);
    mpz_clear(key.e);
    mpz_clear(key.d);
    mpz_clear(key.p);
    mpz_clear(key.q);
}

bool isPrime(const mpz_t n, int iterations = 25) {
    if (mpz_cmp_ui(n, 1) <= 0)
        return false;
    
    if (mpz_cmp_ui(n, 2) == 0 || mpz_cmp_ui(n, 3) == 0)
        return true;
    if (mpz_even_p(n))
        return false;
    
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));
    
    int result = mpz_probab_prime_p(n, iterations);
    
    gmp_randclear(state);
    
    return result > 0;
}

void generatePrime(mpz_t prime, int bits, gmp_randstate_t state) {
    mpz_t temp;
    mpz_init(temp);
    
    do {
        mpz_urandomb(temp, state, bits);
        mpz_setbit(temp, bits - 1);
        mpz_setbit(temp, 0);
    } while (!isPrime(temp));
    
    mpz_set(prime, temp);
    mpz_clear(temp);
}

void extendedGCD(const mpz_t a, const mpz_t b, mpz_t gcd, mpz_t x, mpz_t y) {
    mpz_t a_temp, b_temp, x1, y1, q, r;
    mpz_init_set(a_temp, a);
    mpz_init_set(b_temp, b);
    mpz_init_set_ui(x, 1);
    mpz_init_set_ui(y, 0);
    mpz_init_set_ui(x1, 0);
    mpz_init_set_ui(y1, 1);
    mpz_init(q);
    mpz_init(r);
    
    while (mpz_cmp_ui(b_temp, 0) != 0) {
        mpz_tdiv_qr(q, r, a_temp, b_temp);
        
        mpz_set(a_temp, b_temp);
        mpz_set(b_temp, r);
        
        mpz_t temp;
        mpz_init(temp);
        
        mpz_set(temp, x);
        mpz_mul(x1, x1, q);
        mpz_sub(x, temp, x1);
        mpz_set(x1, temp);
        
        mpz_set(temp, y);
        mpz_mul(y1, y1, q);
        mpz_sub(y, temp, y1);
        mpz_set(y1, temp);
        
        mpz_clear(temp);
    }
    
    mpz_set(gcd, a_temp);
    
    mpz_clear(a_temp);
    mpz_clear(b_temp);
    mpz_clear(x1);
    mpz_clear(y1);
    mpz_clear(q);
    mpz_clear(r);
}

void modInverse(mpz_t result, const mpz_t a, const mpz_t m) {
    mpz_t gcd, x, y;
    mpz_init(gcd);
    mpz_init(x);
    mpz_init(y);
    
    extendedGCD(a, m, gcd, x, y);
    
    if (mpz_cmp_ui(gcd, 1) != 0) {
        std::cerr << "Modular inverse không tồn tại!" << std::endl;
        mpz_set_ui(result, 0);
    } else {
        mpz_mod(result, x, m);
    }
    
    mpz_clear(gcd);
    mpz_clear(x);
    mpz_clear(y);
}

RSAKeyPair generateRSAKeyPair(int keySize) {
    RSAKeyPair keyPair;
    initRSAKey(keyPair.publicKey);
    initRSAKey(keyPair.privateKey);
    
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));
    
    mpz_t p, q, n, phi, e, d;
    mpz_init(p);
    mpz_init(q);
    mpz_init(n);
    mpz_init(phi);
    mpz_init(e);
    mpz_init(d);
    
    generatePrime(p, keySize / 2, state);
    generatePrime(q, keySize / 2, state);
    
    mpz_mul(n, p, q);
    
    mpz_t p_minus_1, q_minus_1;
    mpz_init(p_minus_1);
    mpz_init(q_minus_1);
    mpz_sub_ui(p_minus_1, p, 1);
    mpz_sub_ui(q_minus_1, q, 1);
    mpz_mul(phi, p_minus_1, q_minus_1);
    
    mpz_set_ui(e, 65537);
    
    modInverse(d, e, phi);
    
    mpz_set(keyPair.publicKey.n, n);
    mpz_set(keyPair.publicKey.e, e);
    
    mpz_set(keyPair.privateKey.n, n);
    mpz_set(keyPair.privateKey.d, d);
    mpz_set(keyPair.privateKey.p, p);
    mpz_set(keyPair.privateKey.q, q);
    
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(phi);
    mpz_clear(e);
    mpz_clear(d);
    mpz_clear(p_minus_1);
    mpz_clear(q_minus_1);
    gmp_randclear(state);
    
    return keyPair;
}

bool saveRSAPublicKey(const RSAKey& key, const std::string& filename) {
    std::ofstream file(filename);
    if (!file) {
        return false;
    }
    
    char* n_str = mpz_get_str(NULL, 16, key.n);
    char* e_str = mpz_get_str(NULL, 16, key.e);
    
    file << n_str << std::endl;
    file << e_str << std::endl;
    
    free(n_str);
    free(e_str);
    
    file.close();
    return true;
}

bool saveRSAPrivateKey(const RSAKey& key, const std::string& filename) {
    std::ofstream file(filename);
    if (!file) {
        return false;
    }
    
    char* n_str = mpz_get_str(NULL, 16, key.n);
    char* d_str = mpz_get_str(NULL, 16, key.d);
    char* p_str = mpz_get_str(NULL, 16, key.p);
    char* q_str = mpz_get_str(NULL, 16, key.q);
    
    file << n_str << std::endl;
    file << d_str << std::endl;
    file << p_str << std::endl;
    file << q_str << std::endl;
    
    free(n_str);
    free(d_str);
    free(p_str);
    free(q_str);
    
    file.close();
    return true;
}

bool loadRSAPublicKey(RSAKey& key, const std::string& filename) {
    std::ifstream file(filename);
    if (!file) {
        return false;
    }
    
    std::string n_str, e_str;
    std::getline(file, n_str);
    std::getline(file, e_str);
    
    if (n_str.empty() || e_str.empty()) {
        file.close();
        return false;
    }
    
    mpz_set_str(key.n, n_str.c_str(), 16);
    mpz_set_str(key.e, e_str.c_str(), 16);
    
    file.close();
    return true;
}

bool loadRSAPrivateKey(RSAKey& key, const std::string& filename) {
    std::ifstream file(filename);
    if (!file) {
        return false;
    }
    
    std::string n_str, d_str, p_str, q_str;
    std::getline(file, n_str);
    std::getline(file, d_str);
    std::getline(file, p_str);
    std::getline(file, q_str);
    
    if (n_str.empty() || d_str.empty() || p_str.empty() || q_str.empty()) {
        file.close();
        return false;
    }
    
    mpz_set_str(key.n, n_str.c_str(), 16);
    mpz_set_str(key.d, d_str.c_str(), 16);
    mpz_set_str(key.p, p_str.c_str(), 16);
    mpz_set_str(key.q, q_str.c_str(), 16);
    
    file.close();
    return true;
}

std::vector<uint8_t> rsaEncrypt(const std::vector<uint8_t>& data, const RSAKey& publicKey) {
    std::vector<uint8_t> result;
    
    mpz_t m, c;
    mpz_init(m);
    mpz_init(c);
    
    mpz_import(m, data.size(), 1, sizeof(uint8_t), 0, 0, data.data());
    
    if (mpz_cmp(m, publicKey.n) >= 0) {
        std::cerr << "Dữ liệu quá lớn để mã hóa với khóa này!" << std::endl;
        mpz_clear(m);
        mpz_clear(c);
        return result;
    }
    
    mpz_powm(c, m, publicKey.e, publicKey.n);
    
    size_t count;
    void* buffer = mpz_export(NULL, &count, 1, sizeof(uint8_t), 0, 0, c);
    
    if (buffer) {
        result.resize(count);
        memcpy(result.data(), buffer, count);
        free(buffer);
    }
    
    mpz_clear(m);
    mpz_clear(c);
    
    return result;
}

std::vector<uint8_t> rsaDecrypt(const std::vector<uint8_t>& data, const RSAKey& privateKey) {
    std::vector<uint8_t> result;
    
    mpz_t c, m;
    mpz_init(c);
    mpz_init(m);
    
    mpz_import(c, data.size(), 1, sizeof(uint8_t), 0, 0, data.data());
    
    mpz_powm(m, c, privateKey.d, privateKey.n);
    
    size_t count;
    void* buffer = mpz_export(NULL, &count, 1, sizeof(uint8_t), 0, 0, m);
    
    if (buffer) {
        result.resize(count);
        memcpy(result.data(), buffer, count);
        free(buffer);
    }
    
    mpz_clear(c);
    mpz_clear(m);
    
    return result;
}

std::vector<uint8_t> rsaDecryptDESKey(const std::vector<uint8_t>& encryptedKey, const RSAKey& privateKey) {
    std::vector<uint8_t> decryptedData = rsaDecrypt(encryptedKey, privateKey);
    
    if (decryptedData.size() == 8) {
        return decryptedData;
    } else if (decryptedData.size() > 8) {
        std::vector<uint8_t> desKey(8);
        
        // Lấy 8 bytes cuối cùng nếu kích thước lớn hơn
        if (decryptedData.size() >= 8) {
            for (int i = 0; i < 8; i++) {
                desKey[i] = decryptedData[i];
            }
        }
        
        std::cout << "Đã điều chỉnh kích thước khóa DES từ " << decryptedData.size() 
                  << " bytes xuống 8 bytes" << std::endl;
        return desKey;
    } else {
        std::vector<uint8_t> desKey(8, 0);
        for (size_t i = 0; i < decryptedData.size(); i++) {
            desKey[i] = decryptedData[i];
        }
        
        std::cout << "Đã điều chỉnh kích thước khóa DES từ " << decryptedData.size() 
                  << " bytes lên 8 bytes" << std::endl;
        return desKey;
    }
}

std::vector<uint8_t> generateRandomDESKey() {
    std::vector<uint8_t> key(8);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (int i = 0; i < 8; i++) {
        key[i] = static_cast<uint8_t>(dis(gen));
    }
    
    return key;
}
