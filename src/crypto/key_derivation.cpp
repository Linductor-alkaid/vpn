#include "crypto/crypto.h"
#include <cstring>
#include <iostream>
#include <vector>
#include <algorithm>

namespace sduvpn {
namespace crypto {

// PBKDF2-SHA256完整实现 (符合RFC 2898标准)
CryptoError KeyDerivation::pbkdf2(
    const uint8_t* password, size_t password_len,
    const uint8_t* salt, size_t salt_len,
    uint32_t iterations,
    size_t key_len,
    uint8_t* derived_key) {
    
    // 参数验证
    if (!password || !salt || !derived_key) {
        return CryptoError::INVALID_PARAMETER;
    }
    
    if (password_len == 0 || salt_len == 0 || key_len == 0 || iterations == 0) {
        return CryptoError::INVALID_PARAMETER;
    }
    
    // RFC 2898限制检查
    if (key_len > (0xffffffffUL * SHA_256_HASH_SIZE)) {
        return CryptoError::INVALID_PARAMETER;
    }
    
    if (iterations < 1000) {
        std::cerr << "Warning: PBKDF2 iterations < 1000 is not recommended for security" << std::endl;
    }
    
    const size_t hash_len = SHA_256_HASH_SIZE;
    const size_t blocks_needed = (key_len + hash_len - 1) / hash_len;
    
    // 清零输出缓冲区
    utils::secureZero(derived_key, key_len);
    
    uint8_t* output = derived_key;
    size_t remaining = key_len;
    
    // 为每个块计算PBKDF2
    for (size_t block = 1; block <= blocks_needed; ++block) {
        uint8_t u[SHA_256_HASH_SIZE];
        uint8_t temp[SHA_256_HASH_SIZE];
        
        // 第一次迭代: U1 = HMAC(password, salt || INT(block))
        // 构造 salt || INT(block) - 大端序4字节整数
        std::vector<uint8_t> salt_block;
        salt_block.reserve(salt_len + 4);
        salt_block.assign(salt, salt + salt_len);
        
        // 添加块号 (32位大端序)
        salt_block.push_back((block >> 24) & 0xff);
        salt_block.push_back((block >> 16) & 0xff);
        salt_block.push_back((block >> 8) & 0xff);
        salt_block.push_back(block & 0xff);
        
        CryptoError err = SHA256::hmac(
            password, password_len, 
            salt_block.data(), salt_block.size(), 
            u
        );
        if (err != CryptoError::SUCCESS) {
            // 清理敏感数据
            utils::secureZero(derived_key, key_len);
            return err;
        }
        
        // 初始化累积结果
        std::memcpy(temp, u, hash_len);
        
        // 后续迭代: Ui = HMAC(password, Ui-1)
        for (uint32_t i = 1; i < iterations; ++i) {
            err = SHA256::hmac(password, password_len, u, hash_len, u);
            if (err != CryptoError::SUCCESS) {
                // 清理敏感数据
                utils::secureZero(derived_key, key_len);
                utils::secureZero(u, sizeof(u));
                utils::secureZero(temp, sizeof(temp));
                return err;
            }
            
            // XOR累积: T = U1 XOR U2 XOR ... XOR Uc
            for (size_t j = 0; j < hash_len; ++j) {
                temp[j] ^= u[j];
            }
        }
        
        // 复制到输出缓冲区 (只复制需要的字节数)
        size_t copy_len = std::min(remaining, hash_len);
        std::memcpy(output, temp, copy_len);
        output += copy_len;
        remaining -= copy_len;
        
        // 清理本轮的敏感数据
        utils::secureZero(u, sizeof(u));
        utils::secureZero(temp, sizeof(temp));
    }
    
    return CryptoError::SUCCESS;
}

// HKDF完整实现 (符合RFC 5869标准)
CryptoError KeyDerivation::hkdf(
    const uint8_t* ikm, size_t ikm_len,
    const uint8_t* salt, size_t salt_len,
    const uint8_t* info, size_t info_len,
    size_t okm_len,
    uint8_t* okm) {
    
    // 参数验证
    if (!ikm || !okm) {
        return CryptoError::INVALID_PARAMETER;
    }
    
    if (ikm_len == 0 || okm_len == 0) {
        return CryptoError::INVALID_PARAMETER;
    }
    
    const size_t hash_len = SHA_256_HASH_SIZE;
    
    // RFC 5869限制检查: OKM长度不能超过 255 * HashLen
    if (okm_len > 255 * hash_len) {
        return CryptoError::INVALID_PARAMETER;
    }
    
    // 步骤1: Extract - 提取伪随机密钥
    uint8_t prk[SHA_256_HASH_SIZE];
    CryptoError err;
    
    if (salt && salt_len > 0) {
        // PRK = HMAC-SHA256(salt, IKM)
        err = SHA256::hmac(salt, salt_len, ikm, ikm_len, prk);
    } else {
        // 如果没有盐值，使用零盐 (RFC 5869 Section 2.2)
        uint8_t zero_salt[SHA_256_HASH_SIZE];
        utils::secureZero(zero_salt, hash_len);
        err = SHA256::hmac(zero_salt, hash_len, ikm, ikm_len, prk);
        utils::secureZero(zero_salt, sizeof(zero_salt));
    }
    
    if (err != CryptoError::SUCCESS) {
        utils::secureZero(prk, sizeof(prk));
        return err;
    }
    
    // 步骤2: Expand - 扩展伪随机密钥
    const size_t n = (okm_len + hash_len - 1) / hash_len;
    
    uint8_t t_prev[SHA_256_HASH_SIZE];  // T(i-1)
    uint8_t t_curr[SHA_256_HASH_SIZE];  // T(i)
    uint8_t* output = okm;
    size_t remaining = okm_len;
    
    // 清零输出缓冲区
    utils::secureZero(okm, okm_len);
    
    for (size_t i = 1; i <= n; ++i) {
        // 构建HMAC输入: T(i-1) || info || i
        std::vector<uint8_t> expand_input;
        
        // 第一轮没有T(0)
        if (i > 1) {
            expand_input.insert(expand_input.end(), t_prev, t_prev + hash_len);
        }
        
        // 添加info (可选)
        if (info && info_len > 0) {
            expand_input.insert(expand_input.end(), info, info + info_len);
        }
        
        // 添加计数器 (单字节)
        expand_input.push_back(static_cast<uint8_t>(i));
        
        // T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
        err = SHA256::hmac(
            prk, hash_len, 
            expand_input.data(), expand_input.size(), 
            t_curr
        );
        
        if (err != CryptoError::SUCCESS) {
            // 清理所有敏感数据
            utils::secureZero(prk, sizeof(prk));
            utils::secureZero(t_prev, sizeof(t_prev));
            utils::secureZero(t_curr, sizeof(t_curr));
            utils::secureZero(okm, okm_len);
            return err;
        }
        
        // 复制到输出缓冲区
        size_t copy_len = std::min(remaining, hash_len);
        std::memcpy(output, t_curr, copy_len);
        output += copy_len;
        remaining -= copy_len;
        
        // 保存当前T值作为下一轮的T(i-1)
        std::memcpy(t_prev, t_curr, hash_len);
    }
    
    // 清理所有敏感数据
    utils::secureZero(prk, sizeof(prk));
    utils::secureZero(t_prev, sizeof(t_prev));
    utils::secureZero(t_curr, sizeof(t_curr));
    
    return CryptoError::SUCCESS;
}

// 便利函数：使用密码字符串进行PBKDF2
CryptoError KeyDerivation::pbkdf2_password(
    const std::string& password,
    const uint8_t* salt, size_t salt_len,
    uint32_t iterations,
    size_t key_len,
    uint8_t* derived_key) {
    
    if (password.empty()) {
        return CryptoError::INVALID_PARAMETER;
    }
    
    return pbkdf2(
        reinterpret_cast<const uint8_t*>(password.c_str()),
        password.length(),
        salt, salt_len,
        iterations,
        key_len,
        derived_key
    );
}

// 便利函数：使用字符串信息进行HKDF
CryptoError KeyDerivation::hkdf_info(
    const uint8_t* ikm, size_t ikm_len,
    const uint8_t* salt, size_t salt_len,
    const std::string& info,
    size_t okm_len,
    uint8_t* okm) {
    
    const uint8_t* info_ptr = info.empty() ? nullptr : 
                              reinterpret_cast<const uint8_t*>(info.c_str());
    size_t info_len = info.length();
    
    return hkdf(ikm, ikm_len, salt, salt_len, info_ptr, info_len, okm_len, okm);
}

// 安全的密钥比较函数
bool KeyDerivation::verify_derived_key(
    const uint8_t* derived_key,
    const uint8_t* expected_key,
    size_t key_len) {
    
    if (!derived_key || !expected_key || key_len == 0) {
        return false;
    }
    
    return utils::secureCompare(derived_key, expected_key, key_len);
}

} // namespace crypto
} // namespace sduvpn
