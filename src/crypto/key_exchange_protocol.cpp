#include "crypto/key_exchange.h"
#include <cstring>
#include <iostream>

namespace sduvpn {
namespace crypto {

KeyExchangeProtocol::KeyExchangeProtocol() 
    : state_(State::INITIAL)
    , session_keys_(nullptr) {
    utils::secureZero(private_key_, sizeof(private_key_));
    utils::secureZero(public_key_, sizeof(public_key_));
    utils::secureZero(peer_public_key_, sizeof(peer_public_key_));
}

KeyExchangeProtocol::~KeyExchangeProtocol() {
    reset();
}

CryptoError KeyExchangeProtocol::generateKeyPair() {
    CryptoError result = ECDH::generateKeyPair(private_key_, public_key_);
    if (result == CryptoError::SUCCESS) {
        state_ = State::KEY_GENERATED;
        std::cout << "KeyExchange: Local key pair generated" << std::endl;
    }
    return result;
}

CryptoError KeyExchangeProtocol::getPublicKey(uint8_t* public_key) const {
    if (!public_key) {
        return CryptoError::INVALID_PARAMETER;
    }
    
    if (state_ == State::INITIAL) {
        return CryptoError::KEY_GENERATION_FAILED;
    }
    
    std::memcpy(public_key, public_key_, ECDH_PUBLIC_KEY_SIZE);
    return CryptoError::SUCCESS;
}

CryptoError KeyExchangeProtocol::setPeerPublicKey(const uint8_t* peer_public_key) {
    if (!peer_public_key) {
        return CryptoError::INVALID_PARAMETER;
    }
    
    if (state_ == State::INITIAL) {
        return CryptoError::KEY_GENERATION_FAILED;
    }
    
    std::memcpy(peer_public_key_, peer_public_key, ECDH_PUBLIC_KEY_SIZE);
    state_ = State::PEER_KEY_SET;
    
    std::cout << "KeyExchange: Peer public key set" << std::endl;
    return CryptoError::SUCCESS;
}

CryptoError KeyExchangeProtocol::deriveSessionKeys(const uint8_t* context_info, size_t info_len) {
    if (state_ != State::PEER_KEY_SET) {
        return CryptoError::KEY_GENERATION_FAILED;
    }
    
    // 1. 计算共享密钥
    uint8_t shared_secret[ECDH_SHARED_SECRET_SIZE];
    CryptoError result = computeSharedSecret(shared_secret);
    if (result != CryptoError::SUCCESS) {
        return result;
    }
    
    state_ = State::SHARED_DERIVED;
    std::cout << "KeyExchange: Shared secret computed" << std::endl;
    
    // 2. 使用HKDF派生会话密钥
    const char* default_info = "SDUVPN session keys v1.0";
    const uint8_t* info = context_info ? context_info : 
                         reinterpret_cast<const uint8_t*>(default_info);
    size_t info_length = context_info ? info_len : strlen(default_info);
    
    // 派生总共64字节: 32字节加密密钥 + 32字节MAC密钥
    uint8_t derived_keys[64];
    result = KeyDerivation::hkdf(
        shared_secret, sizeof(shared_secret),
        nullptr, 0,  // 无盐值
        info, info_length,
        sizeof(derived_keys),
        derived_keys
    );
    
    if (result != CryptoError::SUCCESS) {
        utils::secureZero(shared_secret, sizeof(shared_secret));
        return result;
    }
    
    // 3. 创建会话密钥结构
    session_keys_ = std::make_unique<SessionKeys>();
    
    // 分离密钥
    std::memcpy(session_keys_->encryption_key, derived_keys, AES_256_KEY_SIZE);
    std::memcpy(session_keys_->mac_key, derived_keys + AES_256_KEY_SIZE, SHA_256_HASH_SIZE);
    
    // 生成随机IV
    result = SecureRandom::generate(session_keys_->iv, AES_GCM_IV_SIZE);
    if (result != CryptoError::SUCCESS) {
        session_keys_.reset();
        utils::secureZero(shared_secret, sizeof(shared_secret));
        utils::secureZero(derived_keys, sizeof(derived_keys));
        return result;
    }
    
    state_ = State::SESSION_READY;
    
    // 清理敏感数据
    utils::secureZero(shared_secret, sizeof(shared_secret));
    utils::secureZero(derived_keys, sizeof(derived_keys));
    
    std::cout << "KeyExchange: Session keys derived and ready" << std::endl;
    std::cout << "  Encryption key: " << utils::toHex(session_keys_->encryption_key, AES_256_KEY_SIZE) << std::endl;
    std::cout << "  MAC key:        " << utils::toHex(session_keys_->mac_key, SHA_256_HASH_SIZE) << std::endl;
    std::cout << "  IV:             " << utils::toHex(session_keys_->iv, AES_GCM_IV_SIZE) << std::endl;
    
    return CryptoError::SUCCESS;
}

const KeyExchangeProtocol::SessionKeys* KeyExchangeProtocol::getSessionKeys() const {
    if (state_ != State::SESSION_READY) {
        return nullptr;
    }
    return session_keys_.get();
}

void KeyExchangeProtocol::reset() {
    // 安全清理所有敏感数据
    utils::secureZero(private_key_, sizeof(private_key_));
    utils::secureZero(public_key_, sizeof(public_key_));
    utils::secureZero(peer_public_key_, sizeof(peer_public_key_));
    
    session_keys_.reset();
    state_ = State::INITIAL;
    
    std::cout << "KeyExchange: Protocol reset" << std::endl;
}

CryptoError KeyExchangeProtocol::computeSharedSecret(uint8_t* shared_secret) {
    if (!shared_secret) {
        return CryptoError::INVALID_PARAMETER;
    }
    
    // 使用我们简化的协议：
    // 共享密钥 = SHA256(min(local_public, peer_public) || max(local_public, peer_public))
    uint8_t key_material[64];
    
    // 按字典序排列公钥，确保双方计算出相同的共享密钥
    if (std::memcmp(public_key_, peer_public_key_, ECDH_PUBLIC_KEY_SIZE) <= 0) {
        std::memcpy(key_material, public_key_, ECDH_PUBLIC_KEY_SIZE);
        std::memcpy(key_material + ECDH_PUBLIC_KEY_SIZE, peer_public_key_, ECDH_PUBLIC_KEY_SIZE);
    } else {
        std::memcpy(key_material, peer_public_key_, ECDH_PUBLIC_KEY_SIZE);
        std::memcpy(key_material + ECDH_PUBLIC_KEY_SIZE, public_key_, ECDH_PUBLIC_KEY_SIZE);
    }
    
    // 计算共享密钥
    CryptoError result = SHA256::hash(key_material, 64, shared_secret);
    
    // 清理临时数据
    utils::secureZero(key_material, sizeof(key_material));
    
    return result;
}

} // namespace crypto
} // namespace sduvpn
