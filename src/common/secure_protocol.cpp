#include "common/secure_protocol.h"
#include <cstring>
#include <chrono>
#include <iostream>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace sduvpn {
namespace common {

// =============================================================================
// SecureProtocolHeader 实现
// =============================================================================

void SecureProtocolHeader::calculateChecksum() {
    checksum = 0;  // 先清零
    
    // 计算除校验和字段外的所有字段的简单校验和
    const uint8_t* data = reinterpret_cast<const uint8_t*>(this);
    uint32_t sum = 0;
    
    // 计算magic到timestamp的校验和
    for (size_t i = 0; i < offsetof(SecureProtocolHeader, checksum); ++i) {
        sum += data[i];
    }
    
    checksum = sum;
}

bool SecureProtocolHeader::validateChecksum() const {
    SecureProtocolHeader temp = *this;
    temp.calculateChecksum();
    return temp.checksum == checksum;
}

void SecureProtocolHeader::toNetworkOrder() {
    magic = htonl(magic);
    length = htons(length);
    sequence = htonl(sequence);
#ifdef _WIN32
    timestamp = _byteswap_uint64(timestamp);
#else
    timestamp = htobe64(timestamp);
#endif
    checksum = htonl(checksum);
}

void SecureProtocolHeader::fromNetworkOrder() {
    magic = ntohl(magic);
    length = ntohs(length);
    sequence = ntohl(sequence);
#ifdef _WIN32
    timestamp = _byteswap_uint64(timestamp);
#else
    timestamp = be64toh(timestamp);
#endif
    checksum = ntohl(checksum);
}

// =============================================================================
// SecureMessage 实现
// =============================================================================

SecureMessage::SecureMessage() : encrypted_(false) {
    payload_.reserve(MAX_PAYLOAD_SIZE);
    encrypted_data_.reserve(MAX_PACKET_SIZE);
}

SecureMessage::SecureMessage(MessageType type) : encrypted_(false) {
    header_.type = type;
    payload_.reserve(MAX_PAYLOAD_SIZE);
    encrypted_data_.reserve(MAX_PACKET_SIZE);
}

SecureMessage::~SecureMessage() {
    // 安全清零敏感数据
    if (!payload_.empty()) {
        crypto::utils::secureZero(payload_.data(), payload_.size());
    }
    if (!encrypted_data_.empty()) {
        crypto::utils::secureZero(encrypted_data_.data(), encrypted_data_.size());
    }
}

SecureMessage::SecureMessage(SecureMessage&& other) noexcept
    : header_(other.header_)
    , payload_(std::move(other.payload_))
    , encrypted_data_(std::move(other.encrypted_data_))
    , encrypted_(other.encrypted_) {
    other.encrypted_ = false;
}

SecureMessage& SecureMessage::operator=(SecureMessage&& other) noexcept {
    if (this != &other) {
        header_ = other.header_;
        payload_ = std::move(other.payload_);
        encrypted_data_ = std::move(other.encrypted_data_);
        encrypted_ = other.encrypted_;
        other.encrypted_ = false;
    }
    return *this;
}

bool SecureMessage::setPayload(const uint8_t* data, size_t length) {
    if (!data || length > MAX_PAYLOAD_SIZE) {
        return false;
    }
    
    payload_.assign(data, data + length);
    header_.length = static_cast<uint16_t>(length);
    encrypted_ = false;
    encrypted_data_.clear();
    
    return true;
}

std::pair<const uint8_t*, size_t> SecureMessage::getPayload() const {
    if (payload_.empty()) {
        return {nullptr, 0};
    }
    return {payload_.data(), payload_.size()};
}

bool SecureMessage::encrypt(const uint8_t* encryption_key, const uint8_t* mac_key) {
    if (!encryption_key || !mac_key || payload_.empty()) {
        return false;
    }
    
    // 生成IV
    uint8_t iv[crypto::AES_GCM_IV_SIZE];
    generateIV(iv);
    
    // 准备加密数据缓冲区
    encrypted_data_.resize(crypto::AES_GCM_IV_SIZE + payload_.size() + crypto::AES_GCM_TAG_SIZE);
    
    // 复制IV到缓冲区开头
    std::memcpy(encrypted_data_.data(), iv, crypto::AES_GCM_IV_SIZE);
    
    // 加密数据
    size_t ciphertext_len = payload_.size();
    uint8_t* ciphertext = encrypted_data_.data() + crypto::AES_GCM_IV_SIZE;
    uint8_t* tag = ciphertext + payload_.size();
    
    crypto::CryptoError result = crypto::AES256GCM::encrypt(
        encryption_key,
        iv,
        payload_.data(),
        payload_.size(),
        ciphertext,
        &ciphertext_len,
        tag
    );
    
    if (result != crypto::CryptoError::SUCCESS) {
        encrypted_data_.clear();
        return false;
    }
    
    encrypted_ = true;
    header_.length = static_cast<uint16_t>(encrypted_data_.size());
    
    return true;
}

bool SecureMessage::decrypt(const uint8_t* encryption_key, const uint8_t* mac_key) {
    if (!encryption_key || !mac_key || !encrypted_ || encrypted_data_.size() < crypto::AES_GCM_IV_SIZE + crypto::AES_GCM_TAG_SIZE) {
        return false;
    }
    
    // 提取IV、密文和认证标签
    const uint8_t* iv = encrypted_data_.data();
    const uint8_t* ciphertext = iv + crypto::AES_GCM_IV_SIZE;
    size_t ciphertext_len = encrypted_data_.size() - crypto::AES_GCM_IV_SIZE - crypto::AES_GCM_TAG_SIZE;
    const uint8_t* tag = ciphertext + ciphertext_len;
    
    // 准备明文缓冲区
    payload_.resize(ciphertext_len);
    size_t plaintext_len = ciphertext_len;
    
    // 解密数据
    crypto::CryptoError result = crypto::AES256GCM::decrypt(
        encryption_key,
        iv,
        ciphertext,
        ciphertext_len,
        tag,
        payload_.data(),
        &plaintext_len
    );
    
    if (result != crypto::CryptoError::SUCCESS) {
        payload_.clear();
        return false;
    }
    
    payload_.resize(plaintext_len);
    encrypted_ = false;
    header_.length = static_cast<uint16_t>(plaintext_len);
    
    return true;
}

bool SecureMessage::serialize(uint8_t* buffer, size_t buffer_size, size_t* actual_size) const {
    if (!buffer || !actual_size) {
        return false;
    }
    
    size_t required_size = HEADER_SIZE;
    if (encrypted_) {
        required_size += encrypted_data_.size();
    } else {
        required_size += payload_.size();
    }
    
    if (buffer_size < required_size) {
        return false;
    }
    
    // 准备头部
    SecureProtocolHeader header = header_;
    header.calculateChecksum();
    header.toNetworkOrder();
    
    // 复制头部
    std::memcpy(buffer, &header, HEADER_SIZE);
    
    // 复制数据
    if (encrypted_ && !encrypted_data_.empty()) {
        std::memcpy(buffer + HEADER_SIZE, encrypted_data_.data(), encrypted_data_.size());
    } else if (!payload_.empty()) {
        std::memcpy(buffer + HEADER_SIZE, payload_.data(), payload_.size());
    }
    
    *actual_size = required_size;
    return true;
}

bool SecureMessage::deserialize(const uint8_t* buffer, size_t buffer_size) {
    if (!buffer || buffer_size < HEADER_SIZE) {
        return false;
    }
    
    // 复制和验证头部
    std::memcpy(&header_, buffer, HEADER_SIZE);
    header_.fromNetworkOrder();
    
    if (!validateHeader()) {
        return false;
    }
    
    // 复制数据
    size_t data_size = buffer_size - HEADER_SIZE;
    if (data_size > 0) {
        if (header_.type == MessageType::DATA_PACKET) {
            // 数据包默认是加密的
            encrypted_data_.assign(buffer + HEADER_SIZE, buffer + buffer_size);
            encrypted_ = true;
        } else {
            // 控制消息默认是明文的
            payload_.assign(buffer + HEADER_SIZE, buffer + buffer_size);
            encrypted_ = false;
        }
    }
    
    return true;
}

size_t SecureMessage::getTotalSize() const {
    size_t data_size = encrypted_ ? encrypted_data_.size() : payload_.size();
    return HEADER_SIZE + data_size;
}

void SecureMessage::generateIV(uint8_t* iv) const {
    // 使用时间戳和序列号生成IV
    uint64_t timestamp = header_.timestamp;
    uint32_t sequence = header_.sequence;
    
    // 清零IV
    std::memset(iv, 0, crypto::AES_GCM_IV_SIZE);
    
    // 填充时间戳
    std::memcpy(iv, &timestamp, sizeof(timestamp));
    
    // 填充序列号
    std::memcpy(iv + sizeof(timestamp), &sequence, sizeof(sequence));
    
    // 如果还有空间，用安全随机数填充
    if (crypto::AES_GCM_IV_SIZE > sizeof(timestamp) + sizeof(sequence)) {
        crypto::SecureRandom::generate(iv + sizeof(timestamp) + sizeof(sequence), 
                                     crypto::AES_GCM_IV_SIZE - sizeof(timestamp) - sizeof(sequence));
    }
}

bool SecureMessage::validateHeader() const {
    return header_.magic == PROTOCOL_MAGIC &&
           header_.version == PROTOCOL_VERSION &&
           header_.validateChecksum();
}

// =============================================================================
// SecureProtocolContext 实现
// =============================================================================

SecureProtocolContext::SecureProtocolContext()
    : is_server_(false)
    , handshake_complete_(false)
    , sequence_counter_(0)
    , expected_sequence_(1)
    , key_exchange_(std::make_unique<crypto::KeyExchangeProtocol>()) {
}

SecureProtocolContext::~SecureProtocolContext() = default;

bool SecureProtocolContext::initializeAsClient() {
    is_server_ = false;
    handshake_complete_ = false;
    sequence_counter_ = 0;
    expected_sequence_ = 1;
    
    // 生成客户端密钥对
    crypto::CryptoError result = key_exchange_->generateKeyPair();
    return result == crypto::CryptoError::SUCCESS;
}

bool SecureProtocolContext::initializeAsServer() {
    is_server_ = true;
    handshake_complete_ = false;
    sequence_counter_ = 0;
    expected_sequence_ = 1;
    
    // 生成服务端密钥对
    crypto::CryptoError result = key_exchange_->generateKeyPair();
    return result == crypto::CryptoError::SUCCESS;
}

bool SecureProtocolContext::startHandshake(HandshakeInitMessage& init_message) {
    if (is_server_ || handshake_complete_) {
        return false;
    }
    
    // 获取客户端公钥
    crypto::CryptoError result = key_exchange_->getPublicKey(init_message.client_public_key);
    if (result != crypto::CryptoError::SUCCESS) {
        return false;
    }
    
    // 生成客户端随机数
    result = crypto::SecureRandom::generate(init_message.client_random, sizeof(init_message.client_random));
    if (result != crypto::CryptoError::SUCCESS) {
        return false;
    }
    
    // 设置客户端版本
    strncpy(init_message.client_version, "SDUVPN Client v1.0", sizeof(init_message.client_version) - 1);
    init_message.client_version[sizeof(init_message.client_version) - 1] = '\0';
    
    std::cout << "SecureProtocol: Handshake initiated" << std::endl;
    return true;
}

bool SecureProtocolContext::handleHandshakeInit(const HandshakeInitMessage& init_message,
                                               HandshakeResponseMessage& response_message) {
    if (!is_server_ || handshake_complete_) {
        return false;
    }
    
    // 设置对方公钥
    crypto::CryptoError result = key_exchange_->setPeerPublicKey(init_message.client_public_key);
    if (result != crypto::CryptoError::SUCCESS) {
        return false;
    }
    
    // 获取服务端公钥
    result = key_exchange_->getPublicKey(response_message.server_public_key);
    if (result != crypto::CryptoError::SUCCESS) {
        return false;
    }
    
    // 生成服务端随机数
    result = crypto::SecureRandom::generate(response_message.server_random, sizeof(response_message.server_random));
    if (result != crypto::CryptoError::SUCCESS) {
        return false;
    }
    
    // 派生会话密钥
    if (!deriveSessionKeys(init_message.client_random, response_message.server_random)) {
        return false;
    }
    
    // 准备配置信息（简化版）
    const char* config = "{\"virtual_ip\":\"10.8.0.2\",\"netmask\":\"255.255.255.0\"}";
    size_t config_len = strlen(config);
    
    if (config_len > sizeof(response_message.encrypted_config)) {
        return false;
    }
    
    // 这里应该加密配置信息，暂时直接复制
    std::memcpy(response_message.encrypted_config, config, config_len);
    response_message.config_length = static_cast<uint16_t>(config_len);
    
    std::cout << "SecureProtocol: Handshake init processed" << std::endl;
    return true;
}

bool SecureProtocolContext::handleHandshakeResponse(const HandshakeResponseMessage& response_message,
                                                   HandshakeCompleteMessage& complete_message) {
    if (is_server_ || handshake_complete_) {
        return false;
    }
    
    // 设置服务端公钥
    crypto::CryptoError result = key_exchange_->setPeerPublicKey(response_message.server_public_key);
    if (result != crypto::CryptoError::SUCCESS) {
        return false;
    }
    
    // 派生会话密钥
    uint8_t client_random[16] = {0}; // 这里应该保存之前的客户端随机数
    if (!deriveSessionKeys(client_random, response_message.server_random)) {
        return false;
    }
    
    // 生成验证哈希
    const crypto::KeyExchangeProtocol::SessionKeys* session_keys = key_exchange_->getSessionKeys();
    if (!session_keys) {
        return false;
    }
    
    // 计算验证哈希：SHA256(encryption_key || mac_key)
    uint8_t key_material[crypto::AES_256_KEY_SIZE + crypto::SHA_256_HASH_SIZE];
    std::memcpy(key_material, session_keys->encryption_key, crypto::AES_256_KEY_SIZE);
    std::memcpy(key_material + crypto::AES_256_KEY_SIZE, session_keys->mac_key, crypto::SHA_256_HASH_SIZE);
    
    result = crypto::SHA256::hash(key_material, sizeof(key_material), complete_message.verification_hash);
    if (result != crypto::CryptoError::SUCCESS) {
        return false;
    }
    
    // 清理敏感数据
    crypto::utils::secureZero(key_material, sizeof(key_material));
    
    std::cout << "SecureProtocol: Handshake response processed" << std::endl;
    return true;
}

bool SecureProtocolContext::completeHandshake(const HandshakeCompleteMessage& complete_message) {
    if (!is_server_ || handshake_complete_) {
        return false;
    }
    
    // 验证哈希
    const crypto::KeyExchangeProtocol::SessionKeys* session_keys = key_exchange_->getSessionKeys();
    if (!session_keys) {
        return false;
    }
    
    uint8_t expected_hash[crypto::SHA_256_HASH_SIZE];
    uint8_t key_material[crypto::AES_256_KEY_SIZE + crypto::SHA_256_HASH_SIZE];
    std::memcpy(key_material, session_keys->encryption_key, crypto::AES_256_KEY_SIZE);
    std::memcpy(key_material + crypto::AES_256_KEY_SIZE, session_keys->mac_key, crypto::SHA_256_HASH_SIZE);
    
    crypto::CryptoError result = crypto::SHA256::hash(key_material, sizeof(key_material), expected_hash);
    if (result != crypto::CryptoError::SUCCESS) {
        return false;
    }
    
    bool hash_valid = crypto::utils::secureCompare(complete_message.verification_hash, 
                                                  expected_hash, crypto::SHA_256_HASH_SIZE);
    
    // 清理敏感数据
    crypto::utils::secureZero(key_material, sizeof(key_material));
    crypto::utils::secureZero(expected_hash, sizeof(expected_hash));
    
    if (!hash_valid) {
        return false;
    }
    
    handshake_complete_ = true;
    std::cout << "SecureProtocol: Handshake completed successfully" << std::endl;
    return true;
}

const crypto::KeyExchangeProtocol::SessionKeys* SecureProtocolContext::getSessionKeys() const {
    if (!handshake_complete_) {
        return nullptr;
    }
    return key_exchange_->getSessionKeys();
}

std::unique_ptr<SecureMessage> SecureProtocolContext::createMessage(MessageType type) {
    auto message = std::make_unique<SecureMessage>(type);
    message->setSequence(getNextSequence());
    message->setTimestamp(getCurrentTimestamp());
    return message;
}

bool SecureProtocolContext::encryptMessage(SecureMessage& message) {
    if (!handshake_complete_) {
        return false;
    }
    
    const crypto::KeyExchangeProtocol::SessionKeys* session_keys = key_exchange_->getSessionKeys();
    if (!session_keys) {
        return false;
    }
    
    return message.encrypt(session_keys->encryption_key, session_keys->mac_key);
}

bool SecureProtocolContext::decryptMessage(SecureMessage& message) {
    if (!handshake_complete_) {
        return false;
    }
    
    const crypto::KeyExchangeProtocol::SessionKeys* session_keys = key_exchange_->getSessionKeys();
    if (!session_keys) {
        return false;
    }
    
    return message.decrypt(session_keys->encryption_key, session_keys->mac_key);
}

bool SecureProtocolContext::validateSequence(uint32_t sequence) {
    // 简单的序列号验证：允许一定范围内的乱序
    const uint32_t MAX_OUT_OF_ORDER = 64;
    
    if (sequence >= expected_sequence_ && sequence < expected_sequence_ + MAX_OUT_OF_ORDER) {
        expected_sequence_ = sequence + 1;
        return true;
    }
    
    return false;
}

uint64_t SecureProtocolContext::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

bool SecureProtocolContext::deriveSessionKeys(const uint8_t* client_random, const uint8_t* server_random) {
    // 构造上下文信息
    uint8_t context_info[32];
    std::memcpy(context_info, client_random, 16);
    std::memcpy(context_info + 16, server_random, 16);
    
    crypto::CryptoError result = key_exchange_->deriveSessionKeys(context_info, sizeof(context_info));
    if (result != crypto::CryptoError::SUCCESS) {
        return false;
    }
    
    std::cout << "SecureProtocol: Session keys derived successfully" << std::endl;
    return true;
}

} // namespace common
} // namespace sduvpn
