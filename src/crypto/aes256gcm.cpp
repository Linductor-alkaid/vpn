#include "crypto/crypto.h"
#include <cstring>
#include <iostream>

namespace sduvpn {
namespace crypto {

// =============================================================================
// AES-256 常量和查找表
// =============================================================================

// AES S-box
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// AES轮常数
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// =============================================================================
// AES-256 核心函数
// =============================================================================

// 字节替换
static void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

// 行位移
static void shift_rows(uint8_t state[16]) {
    uint8_t temp;
    
    // 第二行左移1位
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    // 第三行左移2位
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // 第四行左移3位
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

// Galois域乘法
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            result ^= a;
        }
        bool carry = (a & 0x80) != 0;
        a <<= 1;
        if (carry) {
            a ^= 0x1b; // AES不可约多项式
        }
        b >>= 1;
    }
    return result;
}

// 列混淆
static void mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[c * 4 + 0];
        uint8_t s1 = state[c * 4 + 1];
        uint8_t s2 = state[c * 4 + 2];
        uint8_t s3 = state[c * 4 + 3];
        
        state[c * 4 + 0] = gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3;
        state[c * 4 + 1] = s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3;
        state[c * 4 + 2] = s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3);
        state[c * 4 + 3] = gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2);
    }
}

// 轮密钥加
static void add_round_key(uint8_t state[16], const uint8_t round_key[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

// 密钥扩展
static void key_expansion(const uint8_t key[32], uint8_t round_keys[15][16]) {
    uint8_t temp[4];
    int i = 0;
    
    // 复制原始密钥
    for (int j = 0; j < 32; j++) {
        ((uint8_t*)round_keys)[j] = key[j];
    }
    
    i = 32;
    while (i < 240) { // 15轮 * 16字节 = 240字节
        // 复制前一个字
        for (int j = 0; j < 4; j++) {
            temp[j] = ((uint8_t*)round_keys)[i - 4 + j];
        }
        
        if (i % 32 == 0) {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            
            // SubWord
            for (int j = 0; j < 4; j++) {
                temp[j] = sbox[temp[j]];
            }
            
            // Rcon
            temp[0] ^= rcon[i / 32];
        } else if (i % 32 == 16) {
            // SubWord (仅用于AES-256)
            for (int j = 0; j < 4; j++) {
                temp[j] = sbox[temp[j]];
            }
        }
        
        for (int j = 0; j < 4; j++) {
            ((uint8_t*)round_keys)[i + j] = ((uint8_t*)round_keys)[i - 32 + j] ^ temp[j];
        }
        i += 4;
    }
}

// AES-256 加密一个块
static void aes256_encrypt_block(const uint8_t plaintext[16], const uint8_t key[32], uint8_t ciphertext[16]) {
    uint8_t round_keys[15][16];
    uint8_t state[16];
    
    // 密钥扩展
    key_expansion(key, round_keys);
    
    // 复制明文到状态
    std::memcpy(state, plaintext, 16);
    
    // 初始轮密钥加
    add_round_key(state, round_keys[0]);
    
    // 主轮次 (13轮)
    for (int round = 1; round < 14; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys[round]);
    }
    
    // 最后一轮 (无列混淆)
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys[14]);
    
    // 复制结果
    std::memcpy(ciphertext, state, 16);
}

// =============================================================================
// GCM模式实现
// =============================================================================

// GF(2^128)乘法 (用于GHASH)
static void gf128_mul(const uint8_t a[16], const uint8_t b[16], uint8_t result[16]) {
    uint8_t v[16];
    uint8_t z[16] = {0};
    
    std::memcpy(v, b, 16);
    
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 8; j++) {
            if (a[i] & (0x80 >> j)) {
                // Z = Z ⊕ V
                for (int k = 0; k < 16; k++) {
                    z[k] ^= v[k];
                }
            }
            
            // V = V >> 1
            bool lsb = v[15] & 1;
            for (int k = 15; k > 0; k--) {
                v[k] = (v[k] >> 1) | ((v[k-1] & 1) << 7);
            }
            v[0] >>= 1;
            
            if (lsb) {
                v[0] ^= 0xE1; // GCM约化多项式
            }
        }
    }
    
    std::memcpy(result, z, 16);
}

// GHASH函数
static void ghash(const uint8_t h[16], const uint8_t* data, size_t len, uint8_t result[16]) {
    uint8_t y[16] = {0};
    uint8_t block[16];
    
    size_t full_blocks = len / 16;
    size_t remainder = len % 16;
    
    // 处理完整的16字节块
    for (size_t i = 0; i < full_blocks; i++) {
        // Y = (Y ⊕ Xi) • H
        for (int j = 0; j < 16; j++) {
            y[j] ^= data[i * 16 + j];
        }
        gf128_mul(y, h, y);
    }
    
    // 处理剩余字节
    if (remainder > 0) {
        std::memset(block, 0, 16);
        std::memcpy(block, data + full_blocks * 16, remainder);
        
        for (int j = 0; j < 16; j++) {
            y[j] ^= block[j];
        }
        gf128_mul(y, h, y);
    }
    
    std::memcpy(result, y, 16);
}

// 计数器模式加密
static void ctr_encrypt(const uint8_t key[32], const uint8_t iv[12], 
                       const uint8_t* plaintext, size_t len, uint8_t* ciphertext) {
    uint8_t counter[16];
    uint8_t keystream[16];
    
    // 初始化计数器: IV || 0x00000001
    std::memcpy(counter, iv, 12);
    counter[12] = 0;
    counter[13] = 0;
    counter[14] = 0;
    counter[15] = 1;
    
    size_t full_blocks = len / 16;
    size_t remainder = len % 16;
    
    // 处理完整的16字节块
    for (size_t i = 0; i < full_blocks; i++) {
        aes256_encrypt_block(counter, key, keystream);
        
        for (int j = 0; j < 16; j++) {
            ciphertext[i * 16 + j] = plaintext[i * 16 + j] ^ keystream[j];
        }
        
        // 增加计数器
        for (int j = 15; j >= 12; j--) {
            if (++counter[j] != 0) break;
        }
    }
    
    // 处理剩余字节
    if (remainder > 0) {
        aes256_encrypt_block(counter, key, keystream);
        
        for (size_t j = 0; j < remainder; j++) {
            ciphertext[full_blocks * 16 + j] = plaintext[full_blocks * 16 + j] ^ keystream[j];
        }
    }
}

CryptoError AES256GCM::encrypt(
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len,
    uint8_t* tag) {
    
    if (!key || !iv || !ciphertext || !ciphertext_len || !tag) {
        return CryptoError::INVALID_PARAMETER;
    }
    
    // 允许plaintext为空（长度为0的情况）
    if (plaintext_len > 0 && !plaintext) {
        return CryptoError::INVALID_PARAMETER;
    }
    
    if (*ciphertext_len < plaintext_len) {
        *ciphertext_len = plaintext_len;
        return CryptoError::BUFFER_TOO_SMALL;
    }
    
    try {
        // 1. 生成哈希子密钥H = AES_K(0^128)
        uint8_t zero_block[16] = {0};
        uint8_t h[16];
        aes256_encrypt_block(zero_block, key, h);
        
        // 2. 使用CTR模式加密明文（如果有数据的话）
        if (plaintext_len > 0) {
            ctr_encrypt(key, iv, plaintext, plaintext_len, ciphertext);
        }
        
        // 3. 构造认证数据 (仅密文，无额外认证数据)
        // 计算长度信息：len(A) || len(C) (各64位，大端序)
        uint8_t len_block[16] = {0};
        // len(A) = 0 (无额外认证数据)
        // len(C) = plaintext_len * 8 (转换为位数)
        uint64_t c_len_bits = plaintext_len * 8;
        for (int i = 0; i < 8; i++) {
            len_block[8 + i] = (c_len_bits >> (56 - 8 * i)) & 0xFF;
        }
        
        // 4. 计算GHASH
        uint8_t ghash_result[16];
        
        // 先处理密文（如果有的话）
        if (plaintext_len > 0) {
            ghash(h, ciphertext, plaintext_len, ghash_result);
        } else {
            std::memset(ghash_result, 0, 16);
        }
        
        // 然后处理长度块
        uint8_t temp_result[16];
        for (int i = 0; i < 16; i++) {
            temp_result[i] = ghash_result[i] ^ len_block[i];
        }
        gf128_mul(temp_result, h, ghash_result);
        
        // 5. 计算最终认证标签
        // tag = GHASH_H(C || len(A) || len(C)) ⊕ AES_K(IV || 0^31 || 1)
        uint8_t j0[16];
        std::memcpy(j0, iv, 12);
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
        
        uint8_t auth_key[16];
        aes256_encrypt_block(j0, key, auth_key);
        
        for (int i = 0; i < 16; i++) {
            tag[i] = ghash_result[i] ^ auth_key[i];
        }
        
        *ciphertext_len = plaintext_len;
        return CryptoError::SUCCESS;
        
    } catch (...) {
        return CryptoError::ENCRYPTION_FAILED;
    }
}

CryptoError AES256GCM::decrypt(
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* tag,
    uint8_t* plaintext,
    size_t* plaintext_len) {
    
    if (!key || !iv || !tag || !plaintext || !plaintext_len) {
        return CryptoError::INVALID_PARAMETER;
    }
    
    // 允许ciphertext为空（长度为0的情况）
    if (ciphertext_len > 0 && !ciphertext) {
        return CryptoError::INVALID_PARAMETER;
    }
    
    if (*plaintext_len < ciphertext_len) {
        *plaintext_len = ciphertext_len;
        return CryptoError::BUFFER_TOO_SMALL;
    }
    
    try {
        // 1. 生成哈希子密钥H = AES_K(0^128)
        uint8_t zero_block[16] = {0};
        uint8_t h[16];
        aes256_encrypt_block(zero_block, key, h);
        
        // 2. 验证认证标签
        // 构造长度信息
        uint8_t len_block[16] = {0};
        uint64_t c_len_bits = ciphertext_len * 8;
        for (int i = 0; i < 8; i++) {
            len_block[8 + i] = (c_len_bits >> (56 - 8 * i)) & 0xFF;
        }
        
        // 计算GHASH
        uint8_t ghash_result[16];
        
        // 处理密文（如果有的话）
        if (ciphertext_len > 0) {
            ghash(h, ciphertext, ciphertext_len, ghash_result);
        } else {
            std::memset(ghash_result, 0, 16);
        }
        
        // 处理长度块
        uint8_t temp_result[16];
        for (int i = 0; i < 16; i++) {
            temp_result[i] = ghash_result[i] ^ len_block[i];
        }
        gf128_mul(temp_result, h, ghash_result);
        
        // 计算期望的认证标签
        uint8_t j0[16];
        std::memcpy(j0, iv, 12);
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
        
        uint8_t auth_key[16];
        aes256_encrypt_block(j0, key, auth_key);
        
        uint8_t expected_tag[16];
        for (int i = 0; i < 16; i++) {
            expected_tag[i] = ghash_result[i] ^ auth_key[i];
        }
        
        // 验证标签
        if (!utils::secureCompare(tag, expected_tag, AES_GCM_TAG_SIZE)) {
            // 标签验证失败，清零明文缓冲区
            utils::secureZero(plaintext, ciphertext_len);
            return CryptoError::AUTHENTICATION_FAILED;
        }
        
        // 3. 标签验证通过，解密数据（如果有的话）
        if (ciphertext_len > 0) {
            ctr_encrypt(key, iv, ciphertext, ciphertext_len, plaintext);
        }
        
        *plaintext_len = ciphertext_len;
        return CryptoError::SUCCESS;
        
    } catch (...) {
        // 发生异常，清零明文缓冲区
        utils::secureZero(plaintext, ciphertext_len);
        return CryptoError::DECRYPTION_FAILED;
    }
}

} // namespace crypto
} // namespace sduvpn
