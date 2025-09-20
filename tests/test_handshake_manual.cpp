#include <iostream>
#include <iomanip>
#include <string>
#include <memory>
#include <cstring>
#include "common/secure_protocol.h"
#include "crypto/crypto.h"

using namespace sduvpn;

// 测试辅助函数
void printHex(const char* label, const uint8_t* data, size_t length) {
    std::cout << label << ": ";
    for (size_t i = 0; i < length; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl;
}

bool testResult(const char* test_name, bool result) {
    std::cout << "[" << (result ? "PASS" : "FAIL") << "] " << test_name << std::endl;
    return result;
}

// 模拟网络传输的简单缓冲区
class MessageBuffer {
public:
    bool send(const uint8_t* data, size_t length) {
        if (length > sizeof(buffer_)) {
            return false;
        }
        std::memcpy(buffer_, data, length);
        buffer_size_ = length;
        has_data_ = true;
        return true;
    }
    
    bool receive(uint8_t* data, size_t max_length, size_t* actual_length) {
        if (!has_data_ || max_length < buffer_size_) {
            return false;
        }
        std::memcpy(data, buffer_, buffer_size_);
        *actual_length = buffer_size_;
        has_data_ = false;
        return true;
    }
    
    bool hasData() const { return has_data_; }
    
private:
    uint8_t buffer_[2048];
    size_t buffer_size_ = 0;
    bool has_data_ = false;
};

// Test basic SecureMessage functionality
bool testSecureMessage() {
    std::cout << "\n=== Testing SecureMessage Basic Functionality ===" << std::endl;
    
    // Create message (use control message type for basic test)
    auto message = std::make_unique<common::SecureMessage>(common::MessageType::KEEPALIVE);
    
    // Set test data
    const char* test_data = "Hello, VPN World!";
    bool result = message->setPayload(reinterpret_cast<const uint8_t*>(test_data), strlen(test_data));
    if (!testResult("Set message payload", result)) return false;
    
    // Get data
    auto payload = message->getPayload();
    bool payload_correct = (payload.second == strlen(test_data) && 
                           std::memcmp(payload.first, test_data, strlen(test_data)) == 0);
    if (!testResult("Get message payload", payload_correct)) return false;
    
    // Serialization test
    uint8_t buffer[1024];
    size_t actual_size;
    result = message->serialize(buffer, sizeof(buffer), &actual_size);
    if (!testResult("Message serialization", result)) return false;
    
    // Deserialization test
    auto message2 = std::make_unique<common::SecureMessage>();
    result = message2->deserialize(buffer, actual_size);
    if (!testResult("Message deserialization", result)) return false;
    
    // Verify deserialized data
    auto payload2 = message2->getPayload();
    bool deserialize_correct = (payload2.second == strlen(test_data) && 
                               std::memcmp(payload2.first, test_data, strlen(test_data)) == 0);
    if (!testResult("Deserialized data correctness", deserialize_correct)) return false;
    
    return true;
}

// Test complete handshake flow
bool testHandshakeFlow() {
    std::cout << "\n=== Testing Complete Handshake Flow ===" << std::endl;
    
    // Create client and server contexts
    auto client_context = std::make_unique<common::SecureProtocolContext>();
    auto server_context = std::make_unique<common::SecureProtocolContext>();
    
    // Create message buffers
    MessageBuffer client_to_server;
    MessageBuffer server_to_client;
    
    // Initialize
    bool result = client_context->initializeAsClient();
    if (!testResult("Client initialization", result)) return false;
    
    result = server_context->initializeAsServer();
    if (!testResult("Server initialization", result)) return false;
    
    // Step 1: Client starts handshake
    std::cout << "\n--- Step 1: Client Handshake Initialization ---" << std::endl;
    common::HandshakeInitMessage init_message;
    result = client_context->startHandshake(init_message);
    if (!testResult("Client starts handshake", result)) return false;
    
    printHex("Client public key", init_message.client_public_key, 32);
    printHex("Client random", init_message.client_random, 16);
    std::cout << "Client version: " << init_message.client_version << std::endl;
    
    // Create handshake init message
    auto init_msg = client_context->createMessage(common::MessageType::HANDSHAKE_INIT);
    init_msg->setPayload(reinterpret_cast<const uint8_t*>(&init_message), sizeof(init_message));
    
    // Serialize and send
    uint8_t buffer[2048];
    size_t buffer_size;
    result = init_msg->serialize(buffer, sizeof(buffer), &buffer_size);
    if (!testResult("Serialize handshake init message", result)) return false;
    
    result = client_to_server.send(buffer, buffer_size);
    if (!testResult("Send handshake init message", result)) return false;
    
    // Step 2: Server processes handshake init
    std::cout << "\n--- Step 2: Server Processes Handshake Init ---" << std::endl;
    size_t received_size;
    result = client_to_server.receive(buffer, sizeof(buffer), &received_size);
    if (!testResult("Server receives handshake init", result)) return false;
    
    // Deserialize message
    auto received_init_msg = std::make_unique<common::SecureMessage>();
    result = received_init_msg->deserialize(buffer, received_size);
    if (!testResult("Deserialize handshake init message", result)) return false;
    
    // Extract handshake data
    auto init_payload = received_init_msg->getPayload();
    if (init_payload.second != sizeof(common::HandshakeInitMessage)) {
        testResult("Handshake init message size check", false);
        return false;
    }
    
    const common::HandshakeInitMessage* received_init = 
        reinterpret_cast<const common::HandshakeInitMessage*>(init_payload.first);
    
    // Server processes handshake init
    common::HandshakeResponseMessage response_message;
    result = server_context->handleHandshakeInit(*received_init, response_message);
    if (!testResult("Server processes handshake init", result)) return false;
    
    printHex("Server public key", response_message.server_public_key, 32);
    printHex("Server random", response_message.server_random, 16);
    std::cout << "Config length: " << response_message.config_length << std::endl;
    
    // Create handshake response message
    auto response_msg = server_context->createMessage(common::MessageType::HANDSHAKE_RESPONSE);
    response_msg->setPayload(reinterpret_cast<const uint8_t*>(&response_message), sizeof(response_message));
    
    // Serialize and send
    result = response_msg->serialize(buffer, sizeof(buffer), &buffer_size);
    if (!testResult("Serialize handshake response message", result)) return false;
    
    result = server_to_client.send(buffer, buffer_size);
    if (!testResult("Send handshake response message", result)) return false;
    
    // Step 3: Client processes handshake response
    std::cout << "\n--- Step 3: Client Processes Handshake Response ---" << std::endl;
    result = server_to_client.receive(buffer, sizeof(buffer), &received_size);
    if (!testResult("Client receives handshake response", result)) return false;
    
    // Deserialize response message
    auto received_response_msg = std::make_unique<common::SecureMessage>();
    result = received_response_msg->deserialize(buffer, received_size);
    if (!testResult("Deserialize handshake response message", result)) return false;
    
    // Extract response data
    auto response_payload = received_response_msg->getPayload();
    if (response_payload.second != sizeof(common::HandshakeResponseMessage)) {
        testResult("Handshake response message size check", false);
        return false;
    }
    
    const common::HandshakeResponseMessage* received_response = 
        reinterpret_cast<const common::HandshakeResponseMessage*>(response_payload.first);
    
    // Client processes handshake response
    common::HandshakeCompleteMessage complete_message;
    result = client_context->handleHandshakeResponse(*received_response, complete_message);
    if (!testResult("Client processes handshake response", result)) return false;
    
    printHex("Verification hash", complete_message.verification_hash, 32);
    
    // Check if client handshake is complete
    result = client_context->isHandshakeComplete();
    if (!testResult("Client handshake complete flag", result)) return false;
    
    // Create handshake complete message
    auto complete_msg = client_context->createMessage(common::MessageType::HANDSHAKE_COMPLETE);
    complete_msg->setPayload(reinterpret_cast<const uint8_t*>(&complete_message), sizeof(complete_message));
    
    // Serialize and send
    result = complete_msg->serialize(buffer, sizeof(buffer), &buffer_size);
    if (!testResult("Serialize handshake complete message", result)) return false;
    
    result = client_to_server.send(buffer, buffer_size);
    if (!testResult("Send handshake complete message", result)) return false;
    
    // Step 4: Server completes handshake
    std::cout << "\n--- Step 4: Server Completes Handshake ---" << std::endl;
    result = client_to_server.receive(buffer, sizeof(buffer), &received_size);
    if (!testResult("Server receives handshake complete", result)) return false;
    
    // Deserialize complete message
    auto received_complete_msg = std::make_unique<common::SecureMessage>();
    result = received_complete_msg->deserialize(buffer, received_size);
    if (!testResult("Deserialize handshake complete message", result)) return false;
    
    // Extract complete data
    auto complete_payload = received_complete_msg->getPayload();
    if (complete_payload.second != sizeof(common::HandshakeCompleteMessage)) {
        testResult("Handshake complete message size check", false);
        return false;
    }
    
    const common::HandshakeCompleteMessage* received_complete = 
        reinterpret_cast<const common::HandshakeCompleteMessage*>(complete_payload.first);
    
    // Server completes handshake
    result = server_context->completeHandshake(*received_complete);
    if (!testResult("Server completes handshake", result)) return false;
    
    // Check if server handshake is complete
    result = server_context->isHandshakeComplete();
    if (!testResult("Server handshake complete flag", result)) return false;
    
    // Step 5: Verify session keys
    std::cout << "\n--- Step 5: Verify Session Keys ---" << std::endl;
    const auto* client_keys = client_context->getSessionKeys();
    const auto* server_keys = server_context->getSessionKeys();
    
    if (!client_keys || !server_keys) {
        testResult("Get session keys", false);
        return false;
    }
    
    // Compare encryption keys
    bool keys_match = (std::memcmp(client_keys->encryption_key, server_keys->encryption_key, 
                                  crypto::AES_256_KEY_SIZE) == 0);
    if (!testResult("Encryption keys match", keys_match)) {
        printHex("Client encryption key", client_keys->encryption_key, crypto::AES_256_KEY_SIZE);
        printHex("Server encryption key", server_keys->encryption_key, crypto::AES_256_KEY_SIZE);
        return false;
    }
    
    // Compare MAC keys
    bool mac_keys_match = (std::memcmp(client_keys->mac_key, server_keys->mac_key, 
                                      crypto::SHA_256_HASH_SIZE) == 0);
    if (!testResult("MAC keys match", mac_keys_match)) {
        printHex("Client MAC key", client_keys->mac_key, crypto::SHA_256_HASH_SIZE);
        printHex("Server MAC key", server_keys->mac_key, crypto::SHA_256_HASH_SIZE);
        return false;
    }
    
    std::cout << "\nHandshake successful! Keys match!" << std::endl;
    printHex("Encryption key", client_keys->encryption_key, crypto::AES_256_KEY_SIZE);
    printHex("MAC key", client_keys->mac_key, crypto::SHA_256_HASH_SIZE);
    
    return true;
}

// Test encrypted communication
bool testEncryptedCommunication() {
    std::cout << "\n=== Testing Encrypted Communication ===" << std::endl;
    
    // Recreate contexts with completed handshake (simplified version)
    auto client_context = std::make_unique<common::SecureProtocolContext>();
    auto server_context = std::make_unique<common::SecureProtocolContext>();
    
    // Initialize and complete handshake (simplified flow)
    client_context->initializeAsClient();
    server_context->initializeAsServer();
    
    // Execute quick handshake
    common::HandshakeInitMessage init_msg;
    client_context->startHandshake(init_msg);
    
    common::HandshakeResponseMessage response_msg;
    server_context->handleHandshakeInit(init_msg, response_msg);
    
    common::HandshakeCompleteMessage complete_msg;
    client_context->handleHandshakeResponse(response_msg, complete_msg);
    server_context->completeHandshake(complete_msg);
    
    if (!client_context->isHandshakeComplete() || !server_context->isHandshakeComplete()) {
        testResult("Quick handshake completion", false);
        return false;
    }
    
    // Test encrypted data transmission
    const char* test_data = "This is an encrypted test message!";
    
    // Client creates encrypted message
    auto encrypted_msg = client_context->createMessage(common::MessageType::DATA_PACKET);
    encrypted_msg->setPayload(reinterpret_cast<const uint8_t*>(test_data), strlen(test_data));
    
    bool result = client_context->encryptMessage(*encrypted_msg);
    if (!testResult("Client encrypts message", result)) return false;
    
    // Serialize encrypted message
    uint8_t buffer[2048];
    size_t buffer_size;
    result = encrypted_msg->serialize(buffer, sizeof(buffer), &buffer_size);
    if (!testResult("Serialize encrypted message", result)) return false;
    
    // Server receives and decrypts
    auto received_msg = std::make_unique<common::SecureMessage>();
    result = received_msg->deserialize(buffer, buffer_size);
    if (!testResult("Deserialize encrypted message", result)) return false;
    
    result = server_context->decryptMessage(*received_msg);
    if (!testResult("Server decrypts message", result)) return false;
    
    // Verify decrypted data
    auto decrypted_payload = received_msg->getPayload();
    bool data_correct = (decrypted_payload.second == strlen(test_data) && 
                        std::memcmp(decrypted_payload.first, test_data, strlen(test_data)) == 0);
    if (!testResult("Decrypted data correctness", data_correct)) return false;
    
    std::cout << "Original data: " << test_data << std::endl;
    std::cout << "Decrypted data: " << std::string(reinterpret_cast<const char*>(decrypted_payload.first), 
                                           decrypted_payload.second) << std::endl;
    
    return true;
}

int main() {
    std::cout << "=== SDUVPN Handshake Test Program ===" << std::endl;
    std::cout << "Test environment: Windows" << std::endl;
    std::cout << "Compile time: " << __DATE__ << " " << __TIME__ << std::endl;
    
    int passed = 0;
    int total = 0;
    
    // Run tests
    total++;
    if (testSecureMessage()) passed++;
    
    total++;
    if (testHandshakeFlow()) passed++;
    
    total++;
    if (testEncryptedCommunication()) passed++;
    
    // Output results
    std::cout << "\n=== Test Results ===" << std::endl;
    std::cout << "Passed: " << passed << "/" << total << std::endl;
    
    if (passed == total) {
        std::cout << "🎉 All tests passed! Handshake protocol working correctly." << std::endl;
        return 0;
    } else {
        std::cout << "❌ Some tests failed, implementation needs to be checked." << std::endl;
        return 1;
    }
}
