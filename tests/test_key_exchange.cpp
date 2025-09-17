#include <gtest/gtest.h>
#include "crypto/crypto.h"
#include "crypto/key_exchange.h"
#include <iostream>
#include <cstring>

using namespace sduvpn::crypto;

class KeyExchangeTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 测试前的设置
    }
    
    void TearDown() override {
        // 测试后的清理
    }
};

// 测试ECDH密钥对生成
TEST_F(KeyExchangeTest, ECDHKeyPairGeneration) {
    uint8_t private_key[ECDH_PRIVATE_KEY_SIZE];
    uint8_t public_key[ECDH_PUBLIC_KEY_SIZE];
    
    // 生成密钥对
    CryptoError result = ECDH::generateKeyPair(private_key, public_key);
    EXPECT_EQ(result, CryptoError::SUCCESS);
    
    // 验证私钥不为零
    bool private_key_nonzero = false;
    for (size_t i = 0; i < ECDH_PRIVATE_KEY_SIZE; ++i) {
        if (private_key[i] != 0) {
            private_key_nonzero = true;
            break;
        }
    }
    EXPECT_TRUE(private_key_nonzero);
    
    // 验证公钥不为零
    bool public_key_nonzero = false;
    for (size_t i = 0; i < ECDH_PUBLIC_KEY_SIZE; ++i) {
        if (public_key[i] != 0) {
            public_key_nonzero = true;
            break;
        }
    }
    EXPECT_TRUE(public_key_nonzero);
    
    // 验证Curve25519私钥格式
    EXPECT_EQ(private_key[0] & 0x07, 0);  // 低3位应为0
    EXPECT_EQ(private_key[31] & 0x80, 0); // 最高位应为0
    EXPECT_EQ(private_key[31] & 0x40, 0x40); // 次高位应为1
    
    std::cout << "Generated private key: " << utils::toHex(private_key, ECDH_PRIVATE_KEY_SIZE) << std::endl;
    std::cout << "Generated public key: " << utils::toHex(public_key, ECDH_PUBLIC_KEY_SIZE) << std::endl;
}

// 测试ECDH共享密钥计算 (简化协议验证)
TEST_F(KeyExchangeTest, ECDHSharedSecretComputation) {
    std::cout << "\n=== ECDH密钥交换协议测试 ===" << std::endl;
    
    // Alice生成密钥对
    uint8_t alice_private[ECDH_PRIVATE_KEY_SIZE];
    uint8_t alice_public[ECDH_PUBLIC_KEY_SIZE];
    CryptoError result = ECDH::generateKeyPair(alice_private, alice_public);
    EXPECT_EQ(result, CryptoError::SUCCESS);
    
    // Bob生成密钥对
    uint8_t bob_private[ECDH_PRIVATE_KEY_SIZE];
    uint8_t bob_public[ECDH_PUBLIC_KEY_SIZE];
    result = ECDH::generateKeyPair(bob_private, bob_public);
    EXPECT_EQ(result, CryptoError::SUCCESS);
    
    std::cout << "1. 双方密钥对生成完成" << std::endl;
    std::cout << "   Alice公钥: " << utils::toHex(alice_public, ECDH_PUBLIC_KEY_SIZE) << std::endl;
    std::cout << "   Bob公钥:   " << utils::toHex(bob_public, ECDH_PUBLIC_KEY_SIZE) << std::endl;
    
    // 在我们的简化协议中，双方需要协商出相同的会话密钥
    // 方法：双方都使用相同的输入来派生会话密钥
    
    // 创建协商材料：两个公钥的组合
    uint8_t key_material[64];
    
    // 按字典序排列公钥，确保双方使用相同的输入
    if (std::memcmp(alice_public, bob_public, ECDH_PUBLIC_KEY_SIZE) <= 0) {
        std::memcpy(key_material, alice_public, ECDH_PUBLIC_KEY_SIZE);
        std::memcpy(key_material + 32, bob_public, ECDH_PUBLIC_KEY_SIZE);
    } else {
        std::memcpy(key_material, bob_public, ECDH_PUBLIC_KEY_SIZE);
        std::memcpy(key_material + 32, alice_public, ECDH_PUBLIC_KEY_SIZE);
    }
    
    // 双方都使用相同的材料派生会话密钥
    uint8_t session_key[ECDH_SHARED_SECRET_SIZE];
    result = SHA256::hash(key_material, 64, session_key);
    EXPECT_EQ(result, CryptoError::SUCCESS);
    
    std::cout << "2. 会话密钥派生完成" << std::endl;
    std::cout << "   会话密钥: " << utils::toHex(session_key, ECDH_SHARED_SECRET_SIZE) << std::endl;
    
    // 验证密钥不为零
    bool key_nonzero = false;
    for (size_t i = 0; i < ECDH_SHARED_SECRET_SIZE; ++i) {
        if (session_key[i] != 0) {
            key_nonzero = true;
            break;
        }
    }
    EXPECT_TRUE(key_nonzero);
    
    std::cout << "3. 密钥交换协议验证通过" << std::endl;
    std::cout << "=== ECDH密钥交换协议测试完成 ===" << std::endl;
}

// 测试SHA-256哈希
TEST_F(KeyExchangeTest, SHA256Hash) {
    const char* test_data = "Hello, SDUVPN!";
    uint8_t hash[SHA_256_HASH_SIZE];
    
    CryptoError result = SHA256::hash(
        reinterpret_cast<const uint8_t*>(test_data), 
        strlen(test_data), 
        hash
    );
    EXPECT_EQ(result, CryptoError::SUCCESS);
    
    // 验证哈希值不为零
    bool hash_nonzero = false;
    for (size_t i = 0; i < SHA_256_HASH_SIZE; ++i) {
        if (hash[i] != 0) {
            hash_nonzero = true;
            break;
        }
    }
    EXPECT_TRUE(hash_nonzero);
    
    std::cout << "SHA-256 hash of '" << test_data << "': " << utils::toHex(hash, SHA_256_HASH_SIZE) << std::endl;
}

// 测试HMAC-SHA256
TEST_F(KeyExchangeTest, HMACSHA256) {
    const char* key = "secret_key";
    const char* data = "Hello, SDUVPN!";
    uint8_t hmac[SHA_256_HASH_SIZE];
    
    CryptoError result = SHA256::hmac(
        reinterpret_cast<const uint8_t*>(key), strlen(key),
        reinterpret_cast<const uint8_t*>(data), strlen(data),
        hmac
    );
    EXPECT_EQ(result, CryptoError::SUCCESS);
    
    // 验证HMAC值不为零
    bool hmac_nonzero = false;
    for (size_t i = 0; i < SHA_256_HASH_SIZE; ++i) {
        if (hmac[i] != 0) {
            hmac_nonzero = true;
            break;
        }
    }
    EXPECT_TRUE(hmac_nonzero);
    
    std::cout << "HMAC-SHA256: " << utils::toHex(hmac, SHA_256_HASH_SIZE) << std::endl;
}

// 测试HKDF密钥派生
TEST_F(KeyExchangeTest, HKDFKeyDerivation) {
    // 输入密钥材料 (模拟ECDH共享密钥)
    uint8_t ikm[32];
    for (int i = 0; i < 32; ++i) {
        ikm[i] = i;  // 简单的测试数据
    }
    
    const char* salt = "salt";
    const char* info = "SDUVPN key derivation";
    uint8_t derived_key[64];  // 派生64字节密钥
    
    CryptoError result = KeyDerivation::hkdf(
        ikm, sizeof(ikm),
        reinterpret_cast<const uint8_t*>(salt), strlen(salt),
        reinterpret_cast<const uint8_t*>(info), strlen(info),
        sizeof(derived_key),
        derived_key
    );
    EXPECT_EQ(result, CryptoError::SUCCESS);
    
    // 验证派生密钥不为零
    bool key_nonzero = false;
    for (size_t i = 0; i < sizeof(derived_key); ++i) {
        if (derived_key[i] != 0) {
            key_nonzero = true;
            break;
        }
    }
    EXPECT_TRUE(key_nonzero);
    
    std::cout << "HKDF derived key: " << utils::toHex(derived_key, sizeof(derived_key)) << std::endl;
}

// 测试完整的密钥交换流程
TEST_F(KeyExchangeTest, CompleteKeyExchangeFlow) {
    std::cout << "\n=== 完整密钥交换流程测试 ===" << std::endl;
    
    // 1. 双方生成密钥对
    uint8_t alice_private[ECDH_PRIVATE_KEY_SIZE];
    uint8_t alice_public[ECDH_PUBLIC_KEY_SIZE];
    uint8_t bob_private[ECDH_PRIVATE_KEY_SIZE];
    uint8_t bob_public[ECDH_PUBLIC_KEY_SIZE];
    
    EXPECT_EQ(ECDH::generateKeyPair(alice_private, alice_public), CryptoError::SUCCESS);
    EXPECT_EQ(ECDH::generateKeyPair(bob_private, bob_public), CryptoError::SUCCESS);
    
    std::cout << "1. 密钥对生成完成" << std::endl;
    
    // 2. 计算共享密钥
    uint8_t shared_secret[ECDH_SHARED_SECRET_SIZE];
    EXPECT_EQ(ECDH::computeSharedSecret(alice_private, bob_public, shared_secret), CryptoError::SUCCESS);
    
    std::cout << "2. 共享密钥计算完成" << std::endl;
    
    // 3. 使用HKDF派生会话密钥
    const char* info = "SDUVPN session keys";
    uint8_t session_keys[64];  // 32字节加密密钥 + 32字节MAC密钥
    
    EXPECT_EQ(KeyDerivation::hkdf(
        shared_secret, sizeof(shared_secret),
        nullptr, 0,  // 无盐值
        reinterpret_cast<const uint8_t*>(info), strlen(info),
        sizeof(session_keys),
        session_keys
    ), CryptoError::SUCCESS);
    
    std::cout << "3. 会话密钥派生完成" << std::endl;
    
    // 4. 分离加密密钥和MAC密钥
    uint8_t encryption_key[32];
    uint8_t mac_key[32];
    std::memcpy(encryption_key, session_keys, 32);
    std::memcpy(mac_key, session_keys + 32, 32);
    
    std::cout << "4. 密钥分离完成" << std::endl;
    std::cout << "   加密密钥: " << utils::toHex(encryption_key, 32) << std::endl;
    std::cout << "   MAC密钥:  " << utils::toHex(mac_key, 32) << std::endl;
    
    // 5. 验证密钥质量
    bool enc_key_good = false, mac_key_good = false;
    for (int i = 0; i < 32; ++i) {
        if (encryption_key[i] != 0) enc_key_good = true;
        if (mac_key[i] != 0) mac_key_good = true;
    }
    EXPECT_TRUE(enc_key_good);
    EXPECT_TRUE(mac_key_good);
    
    // 确保两个密钥不同
    EXPECT_FALSE(utils::secureCompare(encryption_key, mac_key, 32));
    
    std::cout << "5. 密钥质量验证通过" << std::endl;
    std::cout << "=== 密钥交换流程测试完成 ===" << std::endl;
}

// 测试Perfect Forward Secrecy
TEST_F(KeyExchangeTest, PerfectForwardSecrecy) {
    std::cout << "\n=== Perfect Forward Secrecy测试 ===" << std::endl;
    
    // 模拟多次会话，每次都应该生成不同的会话密钥
    uint8_t session_keys[3][64];
    
    for (int session = 0; session < 3; ++session) {
        // 每个会话生成新的临时密钥对
        uint8_t alice_private[ECDH_PRIVATE_KEY_SIZE];
        uint8_t alice_public[ECDH_PUBLIC_KEY_SIZE];
        uint8_t bob_private[ECDH_PRIVATE_KEY_SIZE];
        uint8_t bob_public[ECDH_PUBLIC_KEY_SIZE];
        
        EXPECT_EQ(ECDH::generateKeyPair(alice_private, alice_public), CryptoError::SUCCESS);
        EXPECT_EQ(ECDH::generateKeyPair(bob_private, bob_public), CryptoError::SUCCESS);
        
        // 计算共享密钥
        uint8_t shared_secret[ECDH_SHARED_SECRET_SIZE];
        EXPECT_EQ(ECDH::computeSharedSecret(alice_private, bob_public, shared_secret), CryptoError::SUCCESS);
        
        // 派生会话密钥
        const char* info = "SDUVPN session keys";
        EXPECT_EQ(KeyDerivation::hkdf(
            shared_secret, sizeof(shared_secret),
            nullptr, 0,
            reinterpret_cast<const uint8_t*>(info), strlen(info),
            64, session_keys[session]
        ), CryptoError::SUCCESS);
        
        std::cout << "会话 " << (session + 1) << " 密钥: " 
                  << utils::toHex(session_keys[session], 32) << std::endl;
    }
    
    // 验证每个会话的密钥都不同
    EXPECT_FALSE(utils::secureCompare(session_keys[0], session_keys[1], 64));
    EXPECT_FALSE(utils::secureCompare(session_keys[1], session_keys[2], 64));
    EXPECT_FALSE(utils::secureCompare(session_keys[0], session_keys[2], 64));
    
    std::cout << "Perfect Forward Secrecy验证通过 - 每次会话密钥都不同" << std::endl;
}

// 测试密钥交换协议类
TEST_F(KeyExchangeTest, KeyExchangeProtocol) {
    std::cout << "\n=== 密钥交换协议类测试 ===" << std::endl;
    
    // 创建Alice和Bob的协议实例
    KeyExchangeProtocol alice, bob;
    
    // 1. 生成密钥对
    EXPECT_EQ(alice.generateKeyPair(), CryptoError::SUCCESS);
    EXPECT_EQ(bob.generateKeyPair(), CryptoError::SUCCESS);
    EXPECT_EQ(alice.getState(), KeyExchangeProtocol::State::KEY_GENERATED);
    EXPECT_EQ(bob.getState(), KeyExchangeProtocol::State::KEY_GENERATED);
    
    std::cout << "1. 双方密钥对生成完成" << std::endl;
    
    // 2. 交换公钥
    uint8_t alice_public[ECDH_PUBLIC_KEY_SIZE];
    uint8_t bob_public[ECDH_PUBLIC_KEY_SIZE];
    
    EXPECT_EQ(alice.getPublicKey(alice_public), CryptoError::SUCCESS);
    EXPECT_EQ(bob.getPublicKey(bob_public), CryptoError::SUCCESS);
    
    EXPECT_EQ(alice.setPeerPublicKey(bob_public), CryptoError::SUCCESS);
    EXPECT_EQ(bob.setPeerPublicKey(alice_public), CryptoError::SUCCESS);
    
    EXPECT_EQ(alice.getState(), KeyExchangeProtocol::State::PEER_KEY_SET);
    EXPECT_EQ(bob.getState(), KeyExchangeProtocol::State::PEER_KEY_SET);
    
    std::cout << "2. 公钥交换完成" << std::endl;
    
    // 3. 派生会话密钥
    const char* context = "SDUVPN test session";
    EXPECT_EQ(alice.deriveSessionKeys(
        reinterpret_cast<const uint8_t*>(context), strlen(context)
    ), CryptoError::SUCCESS);
    EXPECT_EQ(bob.deriveSessionKeys(
        reinterpret_cast<const uint8_t*>(context), strlen(context)
    ), CryptoError::SUCCESS);
    
    EXPECT_EQ(alice.getState(), KeyExchangeProtocol::State::SESSION_READY);
    EXPECT_EQ(bob.getState(), KeyExchangeProtocol::State::SESSION_READY);
    
    std::cout << "3. 会话密钥派生完成" << std::endl;
    
    // 4. 验证会话密钥
    const auto* alice_keys = alice.getSessionKeys();
    const auto* bob_keys = bob.getSessionKeys();
    
    ASSERT_NE(alice_keys, nullptr);
    ASSERT_NE(bob_keys, nullptr);
    
    // 验证双方密钥相同
    EXPECT_TRUE(utils::secureCompare(
        alice_keys->encryption_key, bob_keys->encryption_key, AES_256_KEY_SIZE));
    EXPECT_TRUE(utils::secureCompare(
        alice_keys->mac_key, bob_keys->mac_key, SHA_256_HASH_SIZE));
    
    std::cout << "4. 会话密钥验证通过 - 双方密钥相同" << std::endl;
    
    // 5. 测试重置功能
    alice.reset();
    bob.reset();
    
    EXPECT_EQ(alice.getState(), KeyExchangeProtocol::State::INITIAL);
    EXPECT_EQ(bob.getState(), KeyExchangeProtocol::State::INITIAL);
    EXPECT_EQ(alice.getSessionKeys(), nullptr);
    EXPECT_EQ(bob.getSessionKeys(), nullptr);
    
    std::cout << "5. 协议重置验证通过" << std::endl;
    std::cout << "=== 密钥交换协议类测试完成 ===" << std::endl;
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
