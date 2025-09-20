#include "server/client_session.h"
#include "server/server_config.h"
#include <cstring>
#include <iostream>
#include <sstream>

namespace sduvpn {
namespace server {

ClientSession::ClientSession(ClientId client_id) 
    : client_id_(client_id)
    , last_activity_(std::chrono::steady_clock::now())
    , authenticated_(false) {
    
    std::memset(&endpoint_, 0, sizeof(endpoint_));
    stats_.created_time = std::chrono::steady_clock::now();
    stats_.last_activity = last_activity_;
}

ClientSession::~ClientSession() {
    // 清理安全协议上下文
    secure_context_.reset();
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
                                const std::string& client_info,
                                const ServerConfig* server_config) {
    if (username.empty() || password.empty()) {
        return false;
    }
    
    // 如果提供了服务器配置，验证用户名和密码
    if (server_config) {
        bool user_found = false;
        const auto& users = server_config->getUsers();
        
        for (const auto& user : users) {
            if (user.first == username && user.second == password) {
                user_found = true;
                break;
            }
        }
        
        if (!user_found) {
            std::cerr << "Authentication failed: Invalid username or password for user: " 
                      << username << std::endl;
            return false;
        }
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
    
    std::cout << "User '" << username << "' authenticated successfully" << std::endl;
    return true;
}

bool ClientSession::initializeSecureProtocol() {
    try {
        secure_context_ = std::make_unique<common::SecureProtocolContext>();
        bool success = secure_context_->initializeAsServer();
        
        if (success) {
            setState(SessionState::HANDSHAKING);
            updateLastActivity();
        }
        
        return success;
        
    } catch (const std::exception& e) {
        std::cerr << "Secure protocol initialization failed: " << e.what() << std::endl;
        secure_context_.reset();
        return false;
    }
}

bool ClientSession::handleHandshakeInit(const common::HandshakeInitMessage& init_message,
                                       common::HandshakeResponseMessage& response_message) {
    if (!secure_context_) {
        return false;
    }
    
    bool success = secure_context_->handleHandshakeInit(init_message, response_message);
    if (success) {
        updateLastActivity();
    }
    
    return success;
}

bool ClientSession::completeHandshake(const common::HandshakeCompleteMessage& complete_message) {
    if (!secure_context_) {
        return false;
    }
    
    bool success = secure_context_->completeHandshake(complete_message);
    if (success) {
        setState(SessionState::ACTIVE);
        updateLastActivity();
    }
    
    return success;
}

bool ClientSession::isHandshakeComplete() const {
    return secure_context_ && secure_context_->isHandshakeComplete();
}

std::unique_ptr<common::SecureMessage> ClientSession::createSecureMessage(common::MessageType type) {
    if (!secure_context_) {
        return nullptr;
    }
    
    return secure_context_->createMessage(type);
}

bool ClientSession::encryptMessage(common::SecureMessage& message) {
    if (!secure_context_) {
        return false;
    }
    
    bool success = secure_context_->encryptMessage(message);
    if (success) {
        updateLastActivity();
    }
    
    return success;
}

bool ClientSession::decryptMessage(common::SecureMessage& message) {
    if (!secure_context_) {
        return false;
    }
    
    bool success = secure_context_->decryptMessage(message);
    if (success) {
        updateLastActivity();
    }
    
    return success;
}

bool ClientSession::processSecureMessage(const uint8_t* buffer, size_t buffer_size,
                                        std::unique_ptr<common::SecureMessage>& message) {
    if (!buffer || buffer_size == 0) {
        return false;
    }
    
    try {
        message = std::make_unique<common::SecureMessage>();
        if (!message->deserialize(buffer, buffer_size)) {
            message.reset();
            return false;
        }
        
        // 如果消息是加密的，尝试解密
        if (message->isEncrypted() && secure_context_) {
            if (!secure_context_->decryptMessage(*message)) {
                std::cerr << "Failed to decrypt message for client " << client_id_ 
                          << ", message type: " << static_cast<int>(message->getType()) << std::endl;
                message.reset();
                return false;
            }
        }
        
        updateReceiveStats(buffer_size);
        updateLastActivity();
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Message processing failed: " << e.what() << std::endl;
        message.reset();
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
