#pragma once

#include "crypto/crypto.h"
#include <memory>

namespace sduvpn {
namespace crypto {

/**
 * @brief 密钥交换协议类
 * 
 * 实现基于ECDH的密钥交换协议，支持Perfect Forward Secrecy
 */
class KeyExchangeProtocol {
public:
    /**
     * @brief 密钥交换状态
     */
    enum class State {
        INITIAL,        // 初始状态
        KEY_GENERATED,  // 本地密钥对已生成
        PEER_KEY_SET,   // 对方公钥已设置
        SHARED_DERIVED, // 共享密钥已派生
        SESSION_READY   // 会话密钥已就绪
    };

    /**
     * @brief 会话密钥结构
     */
    struct SessionKeys {
        uint8_t encryption_key[AES_256_KEY_SIZE];  // 加密密钥
        uint8_t mac_key[SHA_256_HASH_SIZE];        // MAC密钥
        uint8_t iv[AES_GCM_IV_SIZE];               // 初始向量
        
        SessionKeys() {
            utils::secureZero(encryption_key, sizeof(encryption_key));
            utils::secureZero(mac_key, sizeof(mac_key));
            utils::secureZero(iv, sizeof(iv));
        }
        
        ~SessionKeys() {
            utils::secureZero(encryption_key, sizeof(encryption_key));
            utils::secureZero(mac_key, sizeof(mac_key));
            utils::secureZero(iv, sizeof(iv));
        }
    };

public:
    KeyExchangeProtocol();
    ~KeyExchangeProtocol();
    
    // 禁用拷贝
    KeyExchangeProtocol(const KeyExchangeProtocol&) = delete;
    KeyExchangeProtocol& operator=(const KeyExchangeProtocol&) = delete;

    /**
     * @brief 生成本地密钥对
     * @return 错误码
     */
    CryptoError generateKeyPair();

    /**
     * @brief 获取本地公钥
     * @param public_key 公钥输出缓冲区
     * @return 错误码
     */
    CryptoError getPublicKey(uint8_t* public_key) const;

    /**
     * @brief 设置对方公钥
     * @param peer_public_key 对方公钥
     * @return 错误码
     */
    CryptoError setPeerPublicKey(const uint8_t* peer_public_key);

    /**
     * @brief 派生会话密钥
     * @param context_info 上下文信息(可选)
     * @param info_len 上下文信息长度
     * @return 错误码
     */
    CryptoError deriveSessionKeys(const uint8_t* context_info = nullptr, size_t info_len = 0);

    /**
     * @brief 获取会话密钥
     * @return 会话密钥指针，失败返回nullptr
     */
    const SessionKeys* getSessionKeys() const;

    /**
     * @brief 获取当前状态
     * @return 当前状态
     */
    State getState() const { return state_; }

    /**
     * @brief 重置协议状态
     */
    void reset();

private:
    State state_;
    uint8_t private_key_[ECDH_PRIVATE_KEY_SIZE];
    uint8_t public_key_[ECDH_PUBLIC_KEY_SIZE];
    uint8_t peer_public_key_[ECDH_PUBLIC_KEY_SIZE];
    std::unique_ptr<SessionKeys> session_keys_;
    
    // 内部方法
    CryptoError computeSharedSecret(uint8_t* shared_secret);
};

} // namespace crypto
} // namespace sduvpn
