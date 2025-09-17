#include "crypto/crypto.h"
#include <cstring>
#include <iostream>

namespace sduvpn {
namespace crypto {

// SHA-256完整实现
// 符合FIPS 180-4标准的SHA-256安全哈希算法

// SHA-256常量
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA-256内部实现
struct SHA256::Impl {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
    size_t buffer_len;
    
    Impl() {
        reset();
    }
    
    void reset() {
        // SHA-256初始哈希值
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
        
        count = 0;
        buffer_len = 0;
        std::memset(buffer, 0, sizeof(buffer));
    }
    
    // 右旋转
    static uint32_t rotr(uint32_t x, int n) {
        return (x >> n) | (x << (32 - n));
    }
    
    // SHA-256函数
    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }
    
    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    
    static uint32_t sigma0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
    
    static uint32_t sigma1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }
    
    static uint32_t gamma0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }
    
    static uint32_t gamma1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }
    
    void processBlock(const uint8_t* block) {
        uint32_t w[64];
        uint32_t a, b, c, d, e, f, g, h;
        
        // 准备消息调度 - 大端字节序转换
        for (int i = 0; i < 16; ++i) {
            w[i] = ((uint32_t)block[i * 4] << 24) | 
                   ((uint32_t)block[i * 4 + 1] << 16) |
                   ((uint32_t)block[i * 4 + 2] << 8) | 
                   ((uint32_t)block[i * 4 + 3]);
        }
        
        // 扩展消息调度 (符合FIPS 180-4标准)
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = gamma0(w[i - 15]);
            uint32_t s1 = gamma1(w[i - 2]);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        
        // 初始化工作变量
        a = state[0]; b = state[1]; c = state[2]; d = state[3];
        e = state[4]; f = state[5]; g = state[6]; h = state[7];
        
        // 主压缩循环 (64轮)
        for (int i = 0; i < 64; ++i) {
            uint32_t s1 = sigma1(e);
            uint32_t ch_val = ch(e, f, g);
            uint32_t temp1 = h + s1 + ch_val + K[i] + w[i];
            uint32_t s0 = sigma0(a);
            uint32_t maj_val = maj(a, b, c);
            uint32_t temp2 = s0 + maj_val;
            
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        
        // 更新哈希状态 (模2^32加法)
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
        
        // 安全清理工作变量 (防止敏感数据残留)
        utils::secureZero(w, sizeof(w));
        utils::secureZero(&a, sizeof(a));
        utils::secureZero(&b, sizeof(b));
        utils::secureZero(&c, sizeof(c));
        utils::secureZero(&d, sizeof(d));
        utils::secureZero(&e, sizeof(e));
        utils::secureZero(&f, sizeof(f));
        utils::secureZero(&g, sizeof(g));
        utils::secureZero(&h, sizeof(h));
    }
};

SHA256::SHA256() : pImpl(std::make_unique<Impl>()) {}

SHA256::~SHA256() = default;

void SHA256::reset() {
    pImpl->reset();
}

void SHA256::update(const uint8_t* data, size_t len) {
    if (!data || len == 0) return;
    
    pImpl->count += len;
    
    // 处理缓冲区中的数据
    if (pImpl->buffer_len > 0) {
        size_t needed = 64 - pImpl->buffer_len;
        size_t to_copy = (len < needed) ? len : needed;
        
        std::memcpy(pImpl->buffer + pImpl->buffer_len, data, to_copy);
        pImpl->buffer_len += to_copy;
        data += to_copy;
        len -= to_copy;
        
        if (pImpl->buffer_len == 64) {
            pImpl->processBlock(pImpl->buffer);
            pImpl->buffer_len = 0;
        }
    }
    
    // 处理完整的64字节块
    while (len >= 64) {
        pImpl->processBlock(data);
        data += 64;
        len -= 64;
    }
    
    // 保存剩余数据到缓冲区
    if (len > 0) {
        std::memcpy(pImpl->buffer + pImpl->buffer_len, data, len);
        pImpl->buffer_len += len;
    }
}

CryptoError SHA256::finalize(uint8_t* hash) {
    if (!hash) return CryptoError::INVALID_PARAMETER;
    
    // 保存原始消息长度 (以位为单位)
    uint64_t bit_count = pImpl->count * 8;
    
    // 创建填充块
    uint8_t final_block[128];  // 最多需要两个块
    size_t final_len = 0;
    
    // 复制缓冲区中的剩余数据
    if (pImpl->buffer_len > 0) {
        std::memcpy(final_block, pImpl->buffer, pImpl->buffer_len);
        final_len = pImpl->buffer_len;
    }
    
    // 第一步：添加单个'1'位 (0x80字节)
    final_block[final_len++] = 0x80;
    
    // 第二步：添加零填充
    // 如果当前长度 > 55，需要填充到下一个64字节边界，然后再填充到56
    if (final_len > 56) {
        // 填充到64字节边界
        while (final_len % 64 != 0) {
            final_block[final_len++] = 0;
        }
        // 再填充到下一个块的56字节位置
        while ((final_len % 64) != 56) {
            final_block[final_len++] = 0;
        }
    } else {
        // 直接填充到56字节
        while (final_len != 56) {
            final_block[final_len++] = 0;
        }
    }
    
    // 第三步：添加原始消息长度 (64位大端序)
    for (int i = 0; i < 8; ++i) {
        final_block[final_len + i] = (bit_count >> (56 - i * 8)) & 0xff;
    }
    final_len += 8;
    
    // 处理最终块(们)
    for (size_t offset = 0; offset < final_len; offset += 64) {
        pImpl->processBlock(final_block + offset);
    }
    
    // 输出最终哈希值 (大端序)
    for (int i = 0; i < 8; ++i) {
        hash[i * 4] = (pImpl->state[i] >> 24) & 0xff;
        hash[i * 4 + 1] = (pImpl->state[i] >> 16) & 0xff;
        hash[i * 4 + 2] = (pImpl->state[i] >> 8) & 0xff;
        hash[i * 4 + 3] = pImpl->state[i] & 0xff;
    }
    
    // 清理敏感数据
    utils::secureZero(final_block, sizeof(final_block));
    
    return CryptoError::SUCCESS;
}

CryptoError SHA256::hash(const uint8_t* data, size_t len, uint8_t* hash) {
    if (!hash) return CryptoError::INVALID_PARAMETER;
    
    SHA256 hasher;
    if (data && len > 0) {
        hasher.update(data, len);
    }
    return hasher.finalize(hash);
}

CryptoError SHA256::hmac(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t* hmac) {
    
    if (!key || !data || !hmac || key_len == 0 || data_len == 0) {
        return CryptoError::INVALID_PARAMETER;
    }
    
    uint8_t k_pad[64];
    uint8_t temp_key[SHA_256_HASH_SIZE];
    
    // 如果密钥长度大于64字节，先哈希
    if (key_len > 64) {
        CryptoError err = hash(key, key_len, temp_key);
        if (err != CryptoError::SUCCESS) return err;
        key = temp_key;
        key_len = SHA_256_HASH_SIZE;
    }
    
    // 准备内部填充密钥
    std::memset(k_pad, 0x36, 64);
    for (size_t i = 0; i < key_len; ++i) {
        k_pad[i] ^= key[i];
    }
    
    // 计算内部哈希: H(K XOR ipad || message)
    SHA256 inner_hasher;
    inner_hasher.update(k_pad, 64);
    inner_hasher.update(data, data_len);
    
    uint8_t inner_hash[SHA_256_HASH_SIZE];
    CryptoError err = inner_hasher.finalize(inner_hash);
    if (err != CryptoError::SUCCESS) return err;
    
    // 准备外部填充密钥
    std::memset(k_pad, 0x5c, 64);
    for (size_t i = 0; i < key_len; ++i) {
        k_pad[i] ^= key[i];
    }
    
    // 计算外部哈希: H(K XOR opad || inner_hash)
    SHA256 outer_hasher;
    outer_hasher.update(k_pad, 64);
    outer_hasher.update(inner_hash, SHA_256_HASH_SIZE);
    
    err = outer_hasher.finalize(hmac);
    
    // 清理敏感数据
    utils::secureZero(temp_key, sizeof(temp_key));
    utils::secureZero(k_pad, sizeof(k_pad));
    utils::secureZero(inner_hash, sizeof(inner_hash));
    
    return err;
}

} // namespace crypto
} // namespace sduvpn
