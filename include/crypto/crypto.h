#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>
#include <string>

/**
 * SDUVPN 自研加密库
 * 
 * 提供以下加密功能：
 * - AES-256-GCM 对称加密
 * - SHA-256 哈希算法
 * - ECDH 密钥交换
 * - 安全随机数生成
 * 
 * 设计目标：
 * - 跨平台兼容性
 * - 高性能
 * - 易于使用
 * - 内存安全
 */

namespace sduvpn {
namespace crypto {

// =============================================================================
// 常量定义
// =============================================================================
constexpr size_t AES_256_KEY_SIZE = 32;        // AES-256密钥长度
constexpr size_t AES_GCM_IV_SIZE = 12;         // GCM模式IV长度
constexpr size_t AES_GCM_TAG_SIZE = 16;        // GCM认证标签长度
constexpr size_t SHA_256_HASH_SIZE = 32;       // SHA-256哈希长度
constexpr size_t ECDH_PRIVATE_KEY_SIZE = 32;   // ECDH私钥长度
constexpr size_t ECDH_PUBLIC_KEY_SIZE = 32;    // ECDH公钥长度(Curve25519压缩格式)
constexpr size_t ECDH_SHARED_SECRET_SIZE = 32; // ECDH共享密钥长度

// =============================================================================
// 错误码定义
// =============================================================================
enum class CryptoError {
    SUCCESS = 0,
    INVALID_PARAMETER,
    BUFFER_TOO_SMALL,
    ENCRYPTION_FAILED,
    DECRYPTION_FAILED,
    AUTHENTICATION_FAILED,
    KEY_GENERATION_FAILED,
    RANDOM_GENERATION_FAILED,
    NOT_IMPLEMENTED
};

// =============================================================================
// 安全内存管理
// =============================================================================
class SecureBuffer {
public:
    explicit SecureBuffer(size_t size);
    ~SecureBuffer();
    
    // 禁止拷贝
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    
    // 支持移动
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;
    
    uint8_t* data() noexcept { return data_; }
    const uint8_t* data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }
    
    void clear();  // 安全清零

private:
    uint8_t* data_;
    size_t size_;
};

// =============================================================================
// AES-256-GCM 对称加密
// =============================================================================
class AES256GCM {
public:
    AES256GCM() = default;
    ~AES256GCM() = default;
    
    /**
     * 加密数据
     * @param key 256位密钥
     * @param iv 96位初始化向量
     * @param plaintext 明文数据
     * @param plaintext_len 明文长度
     * @param ciphertext 密文输出缓冲区
     * @param ciphertext_len 密文缓冲区长度(输入)/实际密文长度(输出)
     * @param tag 认证标签输出缓冲区(16字节)
     * @return 错误码
     */
    static CryptoError encrypt(
        const uint8_t* key,
        const uint8_t* iv,
        const uint8_t* plaintext,
        size_t plaintext_len,
        uint8_t* ciphertext,
        size_t* ciphertext_len,
        uint8_t* tag
    );
    
    /**
     * 解密数据
     * @param key 256位密钥
     * @param iv 96位初始化向量
     * @param ciphertext 密文数据
     * @param ciphertext_len 密文长度
     * @param tag 认证标签(16字节)
     * @param plaintext 明文输出缓冲区
     * @param plaintext_len 明文缓冲区长度(输入)/实际明文长度(输出)
     * @return 错误码
     */
    static CryptoError decrypt(
        const uint8_t* key,
        const uint8_t* iv,
        const uint8_t* ciphertext,
        size_t ciphertext_len,
        const uint8_t* tag,
        uint8_t* plaintext,
        size_t* plaintext_len
    );
};

// =============================================================================
// SHA-256 哈希算法
// =============================================================================
class SHA256 {
public:
    SHA256();
    ~SHA256();
    
    // 禁止拷贝
    SHA256(const SHA256&) = delete;
    SHA256& operator=(const SHA256&) = delete;
    
    /**
     * 重置哈希上下文
     */
    void reset();
    
    /**
     * 更新哈希数据
     * @param data 数据指针
     * @param len 数据长度
     */
    void update(const uint8_t* data, size_t len);
    
    /**
     * 完成哈希计算
     * @param hash 哈希值输出缓冲区(32字节)
     * @return 错误码
     */
    CryptoError finalize(uint8_t* hash);
    
    /**
     * 一次性计算哈希
     * @param data 数据指针
     * @param len 数据长度
     * @param hash 哈希值输出缓冲区(32字节)
     * @return 错误码
     */
    static CryptoError hash(const uint8_t* data, size_t len, uint8_t* hash);
    
    /**
     * HMAC-SHA256计算
     * @param key 密钥
     * @param key_len 密钥长度
     * @param data 数据
     * @param data_len 数据长度
     * @param hmac HMAC输出缓冲区(32字节)
     * @return 错误码
     */
    static CryptoError hmac(
        const uint8_t* key, size_t key_len,
        const uint8_t* data, size_t data_len,
        uint8_t* hmac
    );

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
};

// =============================================================================
// ECDH 密钥交换 (使用Curve25519)
// =============================================================================
class ECDH {
public:
    /**
     * 生成密钥对
     * @param private_key 私钥输出缓冲区(32字节)
     * @param public_key 公钥输出缓冲区(32字节，Curve25519压缩格式)
     * @return 错误码
     */
    static CryptoError generateKeyPair(uint8_t* private_key, uint8_t* public_key);
    
    /**
     * 计算共享密钥
     * @param private_key 本方私钥(32字节)
     * @param peer_public_key 对方公钥(32字节)
     * @param shared_secret 共享密钥输出缓冲区(32字节)
     * @return 错误码
     */
    static CryptoError computeSharedSecret(
        const uint8_t* private_key,
        const uint8_t* peer_public_key,
        uint8_t* shared_secret
    );
};

// =============================================================================
// 安全随机数生成
// =============================================================================
class SecureRandom {
public:
    /**
     * 生成安全随机数
     * @param buffer 输出缓冲区
     * @param size 随机数长度
     * @return 错误码
     */
    static CryptoError generate(uint8_t* buffer, size_t size);
    
    /**
     * 生成随机整数
     * @param min 最小值(包含)
     * @param max 最大值(包含)
     * @return 随机整数
     */
    static uint32_t generateInt(uint32_t min, uint32_t max);
};

// =============================================================================
// 密钥派生函数 (PBKDF2-SHA256)
// =============================================================================
class KeyDerivation {
public:
    /**
     * PBKDF2密钥派生
     * @param password 密码
     * @param password_len 密码长度
     * @param salt 盐值
     * @param salt_len 盐值长度
     * @param iterations 迭代次数
     * @param key_len 输出密钥长度
     * @param derived_key 派生密钥输出缓冲区
     * @return 错误码
     */
    static CryptoError pbkdf2(
        const uint8_t* password, size_t password_len,
        const uint8_t* salt, size_t salt_len,
        uint32_t iterations,
        size_t key_len,
        uint8_t* derived_key
    );
    
    /**
     * HKDF密钥派生
     * @param ikm 输入密钥材料
     * @param ikm_len 输入密钥材料长度
     * @param salt 盐值(可选)
     * @param salt_len 盐值长度
     * @param info 信息字符串(可选)
     * @param info_len 信息字符串长度
     * @param okm_len 输出密钥长度
     * @param okm 输出密钥缓冲区
     * @return 错误码
     */
    static CryptoError hkdf(
        const uint8_t* ikm, size_t ikm_len,
        const uint8_t* salt, size_t salt_len,
        const uint8_t* info, size_t info_len,
        size_t okm_len,
        uint8_t* okm
    );
    
    /**
     * 便利函数：使用密码字符串进行PBKDF2
     * @param password 密码字符串
     * @param salt 盐值
     * @param salt_len 盐值长度
     * @param iterations 迭代次数
     * @param key_len 输出密钥长度
     * @param derived_key 派生密钥输出缓冲区
     * @return 错误码
     */
    static CryptoError pbkdf2_password(
        const std::string& password,
        const uint8_t* salt, size_t salt_len,
        uint32_t iterations,
        size_t key_len,
        uint8_t* derived_key
    );
    
    /**
     * 便利函数：使用字符串信息进行HKDF
     * @param ikm 输入密钥材料
     * @param ikm_len 输入密钥材料长度
     * @param salt 盐值(可选)
     * @param salt_len 盐值长度
     * @param info 信息字符串
     * @param okm_len 输出密钥长度
     * @param okm 输出密钥缓冲区
     * @return 错误码
     */
    static CryptoError hkdf_info(
        const uint8_t* ikm, size_t ikm_len,
        const uint8_t* salt, size_t salt_len,
        const std::string& info,
        size_t okm_len,
        uint8_t* okm
    );
    
    /**
     * 安全的密钥比较函数
     * @param derived_key 派生的密钥
     * @param expected_key 期望的密钥
     * @param key_len 密钥长度
     * @return true如果密钥相同
     */
    static bool verify_derived_key(
        const uint8_t* derived_key,
        const uint8_t* expected_key,
        size_t key_len
    );
};

// =============================================================================
// 工具函数
// =============================================================================
namespace utils {

/**
 * 安全比较两个缓冲区
 * @param a 缓冲区A
 * @param b 缓冲区B
 * @param len 长度
 * @return true如果相等
 */
bool secureCompare(const uint8_t* a, const uint8_t* b, size_t len);

/**
 * 安全清零内存
 * @param ptr 内存指针
 * @param len 内存长度
 */
void secureZero(void* ptr, size_t len);

/**
 * 十六进制编码
 * @param data 数据
 * @param len 数据长度
 * @return 十六进制字符串
 */
std::string toHex(const uint8_t* data, size_t len);

/**
 * 十六进制解码
 * @param hex 十六进制字符串
 * @param data 输出数据缓冲区
 * @param max_len 缓冲区最大长度
 * @return 实际解码长度，失败返回0
 */
size_t fromHex(const std::string& hex, uint8_t* data, size_t max_len);

} // namespace utils

// =============================================================================
// 加密上下文类
// =============================================================================

/**
 * @brief 加密上下文类
 * 
 * 提供高级加密/解密接口，封装底层加密操作
 */
class CryptoContext {
public:
    CryptoContext();
    ~CryptoContext();

    // 禁用拷贝构造和赋值
    CryptoContext(const CryptoContext&) = delete;
    CryptoContext& operator=(const CryptoContext&) = delete;

    /**
     * @brief 初始化加密上下文
     * @param key 加密密钥
     * @param key_size 密钥长度
     * @return 是否初始化成功
     */
    bool initialize(const uint8_t* key, size_t key_size);

    /**
     * @brief 加密数据
     * @param plaintext 明文数据
     * @param plaintext_size 明文长度
     * @param ciphertext 密文输出缓冲区
     * @param ciphertext_size 密文缓冲区大小
     * @param actual_size 实际密文长度
     * @return 是否加密成功
     */
    bool encrypt(const uint8_t* plaintext, size_t plaintext_size,
                uint8_t* ciphertext, size_t ciphertext_size, size_t* actual_size);

    /**
     * @brief 解密数据
     * @param ciphertext 密文数据
     * @param ciphertext_size 密文长度
     * @param plaintext 明文输出缓冲区
     * @param plaintext_size 明文缓冲区大小
     * @param actual_size 实际明文长度
     * @return 是否解密成功
     */
    bool decrypt(const uint8_t* ciphertext, size_t ciphertext_size,
                uint8_t* plaintext, size_t plaintext_size, size_t* actual_size);

    /**
     * @brief 检查上下文是否已初始化
     * @return 是否已初始化
     */
    bool isInitialized() const { return initialized_; }

private:
    bool initialized_;
    uint8_t key_[AES_256_KEY_SIZE];
    
    // 内部实现指针（用于隐藏平台特定实现）
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace crypto
} // namespace sduvpn
