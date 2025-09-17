#include "server/client_session.h"
#include <cstring>
#include <iostream>
#include <sstream>

namespace sduvpn {
namespace server {

ClientSession::ClientSession(ClientId client_id) 
    : client_id_(client_id)
    , last_activity_(std::chrono::steady_clock::now())
    , authenticated_(false)
    , crypto_initialized_(false) {
    
    std::memset(&endpoint_, 0, sizeof(endpoint_));
    stats_.created_time = std::chrono::steady_clock::now();
    stats_.last_activity = last_activity_;
}

ClientSession::~ClientSession() {
    // 清理加密上下文
    crypto_context_.reset();
}

void ClientSession::setEndpoint(const struct sockaddr_in& endpoint) {
    endpoint_ = endpoint;
    updateLastActivity();
}

void ClientSession::assignVirtualIP(const std::string& virtual_ip) {
    virtual_ip_ = virtual_ip;
    updateLastActivity();
}

bool ClientSession::authenticate(const std::string& username, 
                                const std::string& password,
                                const std::string& client_info) {
    // 这里应该实现真正的认证逻辑
    // 目前为简化实现，只做基本验证
    
    if (username.empty() || password.empty()) {
        return false;
    }
    
    // 解析客户端信息（格式: "version|device_id"）
    std::string client_version;
    std::string device_id;
    
    size_t delimiter_pos = client_info.find('|');
    if (delimiter_pos != std::string::npos) {
        client_version = client_info.substr(0, delimiter_pos);
        device_id = client_info.substr(delimiter_pos + 1);
    } else {
        client_version = client_info;
        device_id = "unknown";
    }
    
    // 设置认证信息
    auth_info_.username = username;
    auth_info_.client_version = client_version;
    auth_info_.device_id = device_id;
    auth_info_.auth_time = std::chrono::system_clock::now();
    
    authenticated_ = true;
    setState(SessionState::AUTHENTICATED);
    updateLastActivity();
    
    return true;
}

bool ClientSession::initializeCrypto(const std::vector<uint8_t>& shared_key) {
    try {
        // 创建加密上下文
        crypto_context_ = std::make_unique<crypto::CryptoContext>();
        
        // 初始化加密上下文
        // 这里需要根据实际的CryptoContext接口进行调整
        if (shared_key.size() >= 32) {
            // 使用前32字节作为密钥
            std::vector<uint8_t> key(shared_key.begin(), shared_key.begin() + 32);
            
            // 生成初始化向量（这里简化处理，实际应该使用随机值）
            std::vector<uint8_t> iv(16, 0);
            for (size_t i = 0; i < iv.size() && i < shared_key.size() - 32; ++i) {
                iv[i] = shared_key[32 + i];
            }
            
            // 初始化加密上下文（这里需要根据实际接口调整）
            crypto_initialized_ = true;
            updateLastActivity();
            
            return true;
        }
        
        return false;
        
    } catch (const std::exception& e) {
        std::cerr << "Encryption initialization failed: " << e.what() << std::endl;
        crypto_context_.reset();
        crypto_initialized_ = false;
        return false;
    }
}

bool ClientSession::encryptData(const std::vector<uint8_t>& plaintext, 
                               std::vector<uint8_t>& ciphertext) {
    if (!crypto_initialized_ || !crypto_context_) {
        return false;
    }
    
    try {
        // 这里需要根据实际的CryptoContext接口进行加密
        // 目前为简化实现，只是复制数据
        ciphertext = plaintext;
        
        updateSendStats(ciphertext.size());
        updateLastActivity();
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Data encryption failed: " << e.what() << std::endl;
        return false;
    }
}

bool ClientSession::decryptData(const std::vector<uint8_t>& ciphertext, 
                               std::vector<uint8_t>& plaintext) {
    if (!crypto_initialized_ || !crypto_context_) {
        return false;
    }
    
    try {
        // 这里需要根据实际的CryptoContext接口进行解密
        // 目前为简化实现，只是复制数据
        plaintext = ciphertext;
        
        updateReceiveStats(plaintext.size());
        updateLastActivity();
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Data decryption failed: " << e.what() << std::endl;
        return false;
    }
}

void ClientSession::updateLastActivity() {
    last_activity_ = std::chrono::steady_clock::now();
    stats_.last_activity = last_activity_;
}

bool ClientSession::isExpired(int timeout_seconds) const {
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - last_activity_);
    return duration.count() >= timeout_seconds;
}

void ClientSession::updateSendStats(size_t bytes) {
    stats_.bytes_sent += bytes;
    stats_.packets_sent++;
}

void ClientSession::updateReceiveStats(size_t bytes) {
    stats_.bytes_received += bytes;
    stats_.packets_received++;
}

} // namespace server
} // namespace sduvpn
