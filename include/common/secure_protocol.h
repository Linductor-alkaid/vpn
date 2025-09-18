#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include "crypto/crypto.h"
#include "crypto/key_exchange.h"

namespace sduvpn {
namespace common {

// =============================================================================
// 安全通信协议常量
// =============================================================================
constexpr uint32_t PROTOCOL_MAGIC = 0x53445556;  // "SDUV"
constexpr uint8_t PROTOCOL_VERSION = 1;
constexpr size_t MAX_PACKET_SIZE = 1500;
constexpr size_t HEADER_SIZE = 24;  // 协议头大小
constexpr size_t MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - HEADER_SIZE - crypto::AES_GCM_TAG_SIZE;

// =============================================================================
// 消息类型定义
// =============================================================================
enum class MessageType : uint8_t {
    // 控制消息
    HANDSHAKE_INIT = 0x01,      // 握手初始化
    HANDSHAKE_RESPONSE = 0x02,  // 握手响应
    HANDSHAKE_COMPLETE = 0x03,  // 握手完成
    AUTH_REQUEST = 0x04,        // 认证请求
    AUTH_RESPONSE = 0x05,       // 认证响应
    CONFIG_REQUEST = 0x06,      // 配置请求
    CONFIG_RESPONSE = 0x07,     // 配置响应
    KEEPALIVE = 0x08,          // 心跳保活
    DISCONNECT = 0x09,         // 断开连接
    
    // 数据消息
    DATA_PACKET = 0x10,        // 加密数据包
    
    // 错误消息
    ERROR_RESPONSE = 0xFF      // 错误响应
};

// =============================================================================
// 错误码定义
// =============================================================================
enum class ProtocolError : uint8_t {
    SUCCESS = 0x00,
    INVALID_VERSION = 0x01,
    INVALID_MESSAGE_TYPE = 0x02,
    INVALID_SEQUENCE = 0x03,
    DECRYPTION_FAILED = 0x04,
    AUTHENTICATION_FAILED = 0x05,
    KEY_EXCHANGE_FAILED = 0x06,
    TIMEOUT = 0x07,
    INTERNAL_ERROR = 0xFF
};

// =============================================================================
// 安全协议头结构
// =============================================================================
#pragma pack(push, 1)
struct SecureProtocolHeader {
    uint32_t magic;           // 魔数 (4字节)
    uint8_t version;          // 协议版本 (1字节)
    MessageType type;         // 消息类型 (1字节)
    uint16_t length;          // 数据长度 (2字节)
    uint32_t sequence;        // 序列号 (4字节)
    uint64_t timestamp;       // 时间戳 (8字节)
    uint32_t checksum;        // 头部校验和 (4字节)
    
    SecureProtocolHeader() 
        : magic(PROTOCOL_MAGIC)
        , version(PROTOCOL_VERSION)
        , type(MessageType::DATA_PACKET)
        , length(0)
        , sequence(0)
        , timestamp(0)
        , checksum(0) {}
        
    // 计算头部校验和
    void calculateChecksum();
    
    // 验证头部校验和
    bool validateChecksum() const;
    
    // 网络字节序转换
    void toNetworkOrder();
    void fromNetworkOrder();
};
#pragma pack(pop)

// =============================================================================
// 握手消息结构
// =============================================================================
struct HandshakeInitMessage {
    uint8_t client_public_key[crypto::ECDH_PUBLIC_KEY_SIZE];
    uint8_t client_random[16];
    char client_version[32];
    
    HandshakeInitMessage() {
        crypto::utils::secureZero(client_public_key, sizeof(client_public_key));
        crypto::utils::secureZero(client_random, sizeof(client_random));
        crypto::utils::secureZero(client_version, sizeof(client_version));
    }
};

struct HandshakeResponseMessage {
    uint8_t server_public_key[crypto::ECDH_PUBLIC_KEY_SIZE];
    uint8_t server_random[16];
    uint8_t encrypted_config[256];  // 加密的配置信息
    uint16_t config_length;
    
    HandshakeResponseMessage() {
        crypto::utils::secureZero(server_public_key, sizeof(server_public_key));
        crypto::utils::secureZero(server_random, sizeof(server_random));
        crypto::utils::secureZero(encrypted_config, sizeof(encrypted_config));
        config_length = 0;
    }
};

struct HandshakeCompleteMessage {
    uint8_t verification_hash[crypto::SHA_256_HASH_SIZE];
    
    HandshakeCompleteMessage() {
        crypto::utils::secureZero(verification_hash, sizeof(verification_hash));
    }
};

// =============================================================================
// 安全消息包装器
// =============================================================================
class SecureMessage {
public:
    SecureMessage();
    explicit SecureMessage(MessageType type);
    ~SecureMessage();

    // 禁用拷贝构造和赋值
    SecureMessage(const SecureMessage&) = delete;
    SecureMessage& operator=(const SecureMessage&) = delete;

    // 支持移动构造和赋值
    SecureMessage(SecureMessage&& other) noexcept;
    SecureMessage& operator=(SecureMessage&& other) noexcept;

    /**
     * @brief 设置消息类型
     */
    void setType(MessageType type) { header_.type = type; }

    /**
     * @brief 获取消息类型
     */
    MessageType getType() const { return header_.type; }

    /**
     * @brief 设置序列号
     */
    void setSequence(uint32_t sequence) { header_.sequence = sequence; }

    /**
     * @brief 获取序列号
     */
    uint32_t getSequence() const { return header_.sequence; }

    /**
     * @brief 设置时间戳
     */
    void setTimestamp(uint64_t timestamp) { header_.timestamp = timestamp; }

    /**
     * @brief 获取时间戳
     */
    uint64_t getTimestamp() const { return header_.timestamp; }

    /**
     * @brief 设置明文数据
     * @param data 数据指针
     * @param length 数据长度
     * @return 是否设置成功
     */
    bool setPayload(const uint8_t* data, size_t length);

    /**
     * @brief 获取明文数据
     * @return 数据指针和长度的pair
     */
    std::pair<const uint8_t*, size_t> getPayload() const;

    /**
     * @brief 使用指定密钥加密消息
     * @param encryption_key 加密密钥
     * @param mac_key MAC密钥
     * @return 是否加密成功
     */
    bool encrypt(const uint8_t* encryption_key, const uint8_t* mac_key);

    /**
     * @brief 使用指定密钥解密消息
     * @param encryption_key 加密密钥
     * @param mac_key MAC密钥
     * @return 是否解密成功
     */
    bool decrypt(const uint8_t* encryption_key, const uint8_t* mac_key);

    /**
     * @brief 序列化消息到缓冲区
     * @param buffer 输出缓冲区
     * @param buffer_size 缓冲区大小
     * @param actual_size 实际序列化大小
     * @return 是否序列化成功
     */
    bool serialize(uint8_t* buffer, size_t buffer_size, size_t* actual_size) const;

    /**
     * @brief 从缓冲区反序列化消息
     * @param buffer 输入缓冲区
     * @param buffer_size 缓冲区大小
     * @return 是否反序列化成功
     */
    bool deserialize(const uint8_t* buffer, size_t buffer_size);

    /**
     * @brief 检查消息是否已加密
     */
    bool isEncrypted() const { return encrypted_; }

    /**
     * @brief 获取消息总大小
     */
    size_t getTotalSize() const;

private:
    SecureProtocolHeader header_;
    std::vector<uint8_t> payload_;
    std::vector<uint8_t> encrypted_data_;
    bool encrypted_;
    
    // 内部方法
    void generateIV(uint8_t* iv) const;
    bool validateHeader() const;
};

// =============================================================================
// 安全通信上下文
// =============================================================================
class SecureProtocolContext {
public:
    SecureProtocolContext();
    ~SecureProtocolContext();

    // 禁用拷贝构造和赋值
    SecureProtocolContext(const SecureProtocolContext&) = delete;
    SecureProtocolContext& operator=(const SecureProtocolContext&) = delete;

    /**
     * @brief 初始化为客户端模式
     * @return 是否初始化成功
     */
    bool initializeAsClient();

    /**
     * @brief 初始化为服务端模式
     * @return 是否初始化成功
     */
    bool initializeAsServer();

    /**
     * @brief 开始握手流程(客户端)
     * @param init_message 握手初始化消息
     * @return 是否成功
     */
    bool startHandshake(HandshakeInitMessage& init_message);

    /**
     * @brief 处理握手初始化(服务端)
     * @param init_message 握手初始化消息
     * @param response_message 握手响应消息
     * @return 是否成功
     */
    bool handleHandshakeInit(const HandshakeInitMessage& init_message,
                            HandshakeResponseMessage& response_message);

    /**
     * @brief 处理握手响应(客户端)
     * @param response_message 握手响应消息
     * @param complete_message 握手完成消息
     * @return 是否成功
     */
    bool handleHandshakeResponse(const HandshakeResponseMessage& response_message,
                                HandshakeCompleteMessage& complete_message);

    /**
     * @brief 完成握手流程(服务端)
     * @param complete_message 握手完成消息
     * @return 是否成功
     */
    bool completeHandshake(const HandshakeCompleteMessage& complete_message);

    /**
     * @brief 检查是否已完成握手
     */
    bool isHandshakeComplete() const { return handshake_complete_; }

    /**
     * @brief 获取会话密钥
     */
    const crypto::KeyExchangeProtocol::SessionKeys* getSessionKeys() const;

    /**
     * @brief 创建安全消息
     * @param type 消息类型
     * @return 安全消息智能指针
     */
    std::unique_ptr<SecureMessage> createMessage(MessageType type);

    /**
     * @brief 加密消息
     * @param message 待加密消息
     * @return 是否加密成功
     */
    bool encryptMessage(SecureMessage& message);

    /**
     * @brief 解密消息
     * @param message 待解密消息
     * @return 是否解密成功
     */
    bool decryptMessage(SecureMessage& message);

    /**
     * @brief 获取下一个序列号
     */
    uint32_t getNextSequence() { return ++sequence_counter_; }

    /**
     * @brief 验证序列号
     * @param sequence 收到的序列号
     * @return 是否有效
     */
    bool validateSequence(uint32_t sequence);

private:
    bool is_server_;
    bool handshake_complete_;
    uint32_t sequence_counter_;
    uint32_t expected_sequence_;
    
    std::unique_ptr<crypto::KeyExchangeProtocol> key_exchange_;
    
    // 内部方法
    uint64_t getCurrentTimestamp() const;
    bool deriveSessionKeys(const uint8_t* client_random, const uint8_t* server_random);
};

} // namespace common
} // namespace sduvpn
