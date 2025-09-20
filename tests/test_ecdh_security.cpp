#include <gtest/gtest.h>
#include "crypto/crypto.h"
#include <cstring>
#include <vector>
#include <iostream>
#include <chrono>

using namespace sduvpn::crypto;

class ECDHSecurityTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 每个测试前的设置
    }
    
    void TearDown() override {
        // 每个测试后的清理
    }
};

// 测试基本ECDH密钥交换
TEST_F(ECDHSecurityTest, BasicKeyExchange) {
    uint8_t alice_private[ECDH_PRIVATE_KEY_SIZE];
    uint8_t alice_public[ECDH_PUBLIC_KEY_SIZE];
    uint8_t bob_private[ECDH_PRIVATE_KEY_SIZE];
    uint8_t bob_public[ECDH_PUBLIC_KEY_SIZE];
    
    // 生成Alice的密钥对
    EXPECT_EQ(ECDH::generateKeyPair(alice_private, alice_public), CryptoError::SUCCESS);
    
    // 生成Bob的密钥对
    EXPECT_EQ(ECDH::generateKeyPair(bob_private, bob_public), CryptoError::SUCCESS);
    
    // 计算共享密钥
    uint8_t alice_shared[ECDH_SHARED_SECRET_SIZE];
    uint8_t bob_shared[ECDH_SHARED_SECRET_SIZE];
    
    EXPECT_EQ(ECDH::computeSharedSecret(alice_private, bob_public, alice_shared), CryptoError::SUCCESS);
    EXPECT_EQ(ECDH::computeSharedSecret(bob_private, alice_public, bob_shared), CryptoError::SUCCESS);
    
    // 验证共享密钥相同
    EXPECT_EQ(memcmp(alice_shared, bob_shared, ECDH_SHARED_SECRET_SIZE), 0);
    
    std::cout << "Alice shared: " << utils::toHex(alice_shared, 32) << std::endl;
    std::cout << "Bob shared:   " << utils::toHex(bob_shared, 32) << std::endl;
}

// 测试低阶点攻击防护
TEST_F(ECDHSecurityTest, LowOrderPointAttack) {
    uint8_t private_key[ECDH_PRIVATE_KEY_SIZE];
    uint8_t public_key[ECDH_PUBLIC_KEY_SIZE];
    
    // 生成正常密钥对
    EXPECT_EQ(ECDH::generateKeyPair(private_key, public_key), CryptoError::SUCCESS);
    
    // 测试零点攻击
    uint8_t zero_point[ECDH_PUBLIC_KEY_SIZE] = {0};
    uint8_t shared_secret[ECDH_SHARED_SECRET_SIZE];
    
    EXPECT_EQ(ECDH::computeSharedSecret(private_key, zero_point, shared_secret), 
              CryptoError::INVALID_PARAMETER);
    
    // 测试点1攻击
    uint8_t one_point[ECDH_PUBLIC_KEY_SIZE] = {1};
    EXPECT_EQ(ECDH::computeSharedSecret(private_key, one_point, shared_secret), 
              CryptoError::INVALID_PARAMETER);
    
    // 测试p-1点攻击
    uint8_t p_minus_one[ECDH_PUBLIC_KEY_SIZE] = {
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
    };
    EXPECT_EQ(ECDH::computeSharedSecret(private_key, p_minus_one, shared_secret), 
              CryptoError::INVALID_PARAMETER);
}

// 测试私钥格式验证
TEST_F(ECDHSecurityTest, PrivateKeyFormat) {
    uint8_t private_key[ECDH_PRIVATE_KEY_SIZE];
    uint8_t public_key[ECDH_PUBLIC_KEY_SIZE];
    
    // 生成正常密钥对
    EXPECT_EQ(ECDH::generateKeyPair(private_key, public_key), CryptoError::SUCCESS);
    
    // 验证私钥格式
    EXPECT_EQ(private_key[0] & 0x07, 0);      // 低3位应该为0
    EXPECT_EQ(private_key[31] & 0x80, 0);     // 最高位应该为0
    EXPECT_NE(private_key[31] & 0x40, 0);     // 次高位应该为1
}

// 测试公钥唯一性
TEST_F(ECDHSecurityTest, PublicKeyUniqueness) {
    const int num_keys = 100;
    std::vector<std::vector<uint8_t>> public_keys;
    
    for (int i = 0; i < num_keys; ++i) {
        uint8_t private_key[ECDH_PRIVATE_KEY_SIZE];
        uint8_t public_key[ECDH_PUBLIC_KEY_SIZE];
        
        EXPECT_EQ(ECDH::generateKeyPair(private_key, public_key), CryptoError::SUCCESS);
        
        // 检查是否与之前生成的公钥重复
        std::vector<uint8_t> current_key(public_key, public_key + ECDH_PUBLIC_KEY_SIZE);
        
        for (const auto& existing_key : public_keys) {
            EXPECT_NE(current_key, existing_key) << "Generated duplicate public key at iteration " << i;
        }
        
        public_keys.push_back(current_key);
    }
    
    std::cout << "Generated " << num_keys << " unique public keys" << std::endl;
}

// 测试共享密钥唯一性
TEST_F(ECDHSecurityTest, SharedSecretUniqueness) {
    const int num_pairs = 50;
    std::vector<std::vector<uint8_t>> shared_secrets;
    
    for (int i = 0; i < num_pairs; ++i) {
        uint8_t alice_private[ECDH_PRIVATE_KEY_SIZE];
        uint8_t alice_public[ECDH_PUBLIC_KEY_SIZE];
        uint8_t bob_private[ECDH_PRIVATE_KEY_SIZE];
        uint8_t bob_public[ECDH_PUBLIC_KEY_SIZE];
        
        EXPECT_EQ(ECDH::generateKeyPair(alice_private, alice_public), CryptoError::SUCCESS);
        EXPECT_EQ(ECDH::generateKeyPair(bob_private, bob_public), CryptoError::SUCCESS);
        
        uint8_t shared_secret[ECDH_SHARED_SECRET_SIZE];
        EXPECT_EQ(ECDH::computeSharedSecret(alice_private, bob_public, shared_secret), CryptoError::SUCCESS);
        
        // 检查是否与之前生成的共享密钥重复
        std::vector<uint8_t> current_secret(shared_secret, shared_secret + ECDH_SHARED_SECRET_SIZE);
        
        for (const auto& existing_secret : shared_secrets) {
            EXPECT_NE(current_secret, existing_secret) << "Generated duplicate shared secret at iteration " << i;
        }
        
        shared_secrets.push_back(current_secret);
    }
    
    std::cout << "Generated " << num_pairs << " unique shared secrets" << std::endl;
}

// 测试ECDH的交换律性质
TEST_F(ECDHSecurityTest, CommutativeProperty) {
    uint8_t alice_private[ECDH_PRIVATE_KEY_SIZE];
    uint8_t alice_public[ECDH_PUBLIC_KEY_SIZE];
    uint8_t bob_private[ECDH_PRIVATE_KEY_SIZE];
    uint8_t bob_public[ECDH_PUBLIC_KEY_SIZE];
    uint8_t charlie_private[ECDH_PRIVATE_KEY_SIZE];
    uint8_t charlie_public[ECDH_PUBLIC_KEY_SIZE];
    
    // 生成三方密钥对
    EXPECT_EQ(ECDH::generateKeyPair(alice_private, alice_public), CryptoError::SUCCESS);
    EXPECT_EQ(ECDH::generateKeyPair(bob_private, bob_public), CryptoError::SUCCESS);
    EXPECT_EQ(ECDH::generateKeyPair(charlie_private, charlie_public), CryptoError::SUCCESS);
    
    // 测试Alice和Bob的密钥交换
    uint8_t alice_bob_shared[ECDH_SHARED_SECRET_SIZE];
    uint8_t bob_alice_shared[ECDH_SHARED_SECRET_SIZE];
    
    EXPECT_EQ(ECDH::computeSharedSecret(alice_private, bob_public, alice_bob_shared), CryptoError::SUCCESS);
    EXPECT_EQ(ECDH::computeSharedSecret(bob_private, alice_public, bob_alice_shared), CryptoError::SUCCESS);
    
    EXPECT_EQ(memcmp(alice_bob_shared, bob_alice_shared, ECDH_SHARED_SECRET_SIZE), 0);
    
    // 测试Alice和Charlie的密钥交换
    uint8_t alice_charlie_shared[ECDH_SHARED_SECRET_SIZE];
    uint8_t charlie_alice_shared[ECDH_SHARED_SECRET_SIZE];
    
    EXPECT_EQ(ECDH::computeSharedSecret(alice_private, charlie_public, alice_charlie_shared), CryptoError::SUCCESS);
    EXPECT_EQ(ECDH::computeSharedSecret(charlie_private, alice_public, charlie_alice_shared), CryptoError::SUCCESS);
    
    EXPECT_EQ(memcmp(alice_charlie_shared, charlie_alice_shared, ECDH_SHARED_SECRET_SIZE), 0);
    
    // 验证不同密钥对产生不同的共享密钥
    EXPECT_NE(memcmp(alice_bob_shared, alice_charlie_shared, ECDH_SHARED_SECRET_SIZE), 0);
}

// 测试无效参数处理
TEST_F(ECDHSecurityTest, InvalidParameterHandling) {
    uint8_t private_key[ECDH_PRIVATE_KEY_SIZE];
    uint8_t public_key[ECDH_PUBLIC_KEY_SIZE];
    uint8_t shared_secret[ECDH_SHARED_SECRET_SIZE];
    
    // 测试空指针参数
    EXPECT_EQ(ECDH::generateKeyPair(nullptr, public_key), CryptoError::INVALID_PARAMETER);
    EXPECT_EQ(ECDH::generateKeyPair(private_key, nullptr), CryptoError::INVALID_PARAMETER);
    EXPECT_EQ(ECDH::generateKeyPair(nullptr, nullptr), CryptoError::INVALID_PARAMETER);
    
    EXPECT_EQ(ECDH::computeSharedSecret(nullptr, public_key, shared_secret), CryptoError::INVALID_PARAMETER);
    EXPECT_EQ(ECDH::computeSharedSecret(private_key, nullptr, shared_secret), CryptoError::INVALID_PARAMETER);
    EXPECT_EQ(ECDH::computeSharedSecret(private_key, public_key, nullptr), CryptoError::INVALID_PARAMETER);
}

// 性能基准测试
TEST_F(ECDHSecurityTest, PerformanceBenchmark) {
    const int iterations = 100;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        uint8_t private_key[ECDH_PRIVATE_KEY_SIZE];
        uint8_t public_key[ECDH_PUBLIC_KEY_SIZE];
        
        EXPECT_EQ(ECDH::generateKeyPair(private_key, public_key), CryptoError::SUCCESS);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double avg_time = static_cast<double>(duration.count()) / iterations;
    std::cout << "Average key generation time: " << avg_time << " microseconds" << std::endl;
    std::cout << "Key generation rate: " << (1000000.0 / avg_time) << " keys/second" << std::endl;
    
    // 测试共享密钥计算性能
    uint8_t alice_private[ECDH_PRIVATE_KEY_SIZE];
    uint8_t alice_public[ECDH_PUBLIC_KEY_SIZE];
    uint8_t bob_private[ECDH_PRIVATE_KEY_SIZE];
    uint8_t bob_public[ECDH_PUBLIC_KEY_SIZE];
    
    EXPECT_EQ(ECDH::generateKeyPair(alice_private, alice_public), CryptoError::SUCCESS);
    EXPECT_EQ(ECDH::generateKeyPair(bob_private, bob_public), CryptoError::SUCCESS);
    
    start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        uint8_t shared_secret[ECDH_SHARED_SECRET_SIZE];
        EXPECT_EQ(ECDH::computeSharedSecret(alice_private, bob_public, shared_secret), CryptoError::SUCCESS);
    }
    
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    avg_time = static_cast<double>(duration.count()) / iterations;
    std::cout << "Average shared secret computation time: " << avg_time << " microseconds" << std::endl;
    std::cout << "Shared secret computation rate: " << (1000000.0 / avg_time) << " computations/second" << std::endl;
}
