#include <gtest/gtest.h>
#include "crypto/crypto.h"
#include "crypto/key_exchange.h"
#include <chrono>
#include <iostream>

using namespace sduvpn::crypto;

class ECDHPerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// 测试ECDH密钥生成性能
TEST_F(ECDHPerformanceTest, KeyGenerationPerformance) {
    std::cout << "\n=== ECDH密钥生成性能测试 ===" << std::endl;
    
    const int iterations = 100;
    uint8_t private_key[ECDH_PRIVATE_KEY_SIZE];
    uint8_t public_key[ECDH_PUBLIC_KEY_SIZE];
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        CryptoError result = ECDH::generateKeyPair(private_key, public_key);
        EXPECT_EQ(result, CryptoError::SUCCESS);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double avg_time = duration.count() / (double)iterations;
    double keys_per_second = 1000000.0 / avg_time;
    
    std::cout << "生成 " << iterations << " 个密钥对:" << std::endl;
    std::cout << "  总时间: " << duration.count() << " 微秒" << std::endl;
    std::cout << "  平均时间: " << avg_time << " 微秒/密钥对" << std::endl;
    std::cout << "  生成速度: " << keys_per_second << " 密钥对/秒" << std::endl;
    
    // 性能基准：应该能在1秒内生成至少10个密钥对
    EXPECT_GT(keys_per_second, 10.0);
}

// 测试ECDH共享密钥计算性能
TEST_F(ECDHPerformanceTest, SharedSecretPerformance) {
    std::cout << "\n=== ECDH共享密钥计算性能测试 ===" << std::endl;
    
    const int iterations = 100;
    
    // 预生成密钥对
    uint8_t alice_private[ECDH_PRIVATE_KEY_SIZE];
    uint8_t alice_public[ECDH_PUBLIC_KEY_SIZE];
    uint8_t bob_private[ECDH_PRIVATE_KEY_SIZE];
    uint8_t bob_public[ECDH_PUBLIC_KEY_SIZE];
    
    EXPECT_EQ(ECDH::generateKeyPair(alice_private, alice_public), CryptoError::SUCCESS);
    EXPECT_EQ(ECDH::generateKeyPair(bob_private, bob_public), CryptoError::SUCCESS);
    
    uint8_t shared_secret[ECDH_SHARED_SECRET_SIZE];
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        CryptoError result = ECDH::computeSharedSecret(alice_private, bob_public, shared_secret);
        EXPECT_EQ(result, CryptoError::SUCCESS);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double avg_time = duration.count() / (double)iterations;
    double computations_per_second = 1000000.0 / avg_time;
    
    std::cout << "计算 " << iterations << " 个共享密钥:" << std::endl;
    std::cout << "  总时间: " << duration.count() << " 微秒" << std::endl;
    std::cout << "  平均时间: " << avg_time << " 微秒/计算" << std::endl;
    std::cout << "  计算速度: " << computations_per_second << " 计算/秒" << std::endl;
    
    // 性能基准：应该能在1秒内完成至少10次计算
    EXPECT_GT(computations_per_second, 10.0);
}

// 测试完整密钥交换协议性能
TEST_F(ECDHPerformanceTest, FullProtocolPerformance) {
    std::cout << "\n=== 完整密钥交换协议性能测试 ===" << std::endl;
    
    const int iterations = 50;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        KeyExchangeProtocol alice, bob;
        
        // 生成密钥对
        EXPECT_EQ(alice.generateKeyPair(), CryptoError::SUCCESS);
        EXPECT_EQ(bob.generateKeyPair(), CryptoError::SUCCESS);
        
        // 交换公钥
        uint8_t alice_public[ECDH_PUBLIC_KEY_SIZE];
        uint8_t bob_public[ECDH_PUBLIC_KEY_SIZE];
        
        EXPECT_EQ(alice.getPublicKey(alice_public), CryptoError::SUCCESS);
        EXPECT_EQ(bob.getPublicKey(bob_public), CryptoError::SUCCESS);
        
        EXPECT_EQ(alice.setPeerPublicKey(bob_public), CryptoError::SUCCESS);
        EXPECT_EQ(bob.setPeerPublicKey(alice_public), CryptoError::SUCCESS);
        
        // 派生会话密钥
        const char* context = "SDUVPN performance test";
        EXPECT_EQ(alice.deriveSessionKeys(
            reinterpret_cast<const uint8_t*>(context), strlen(context)
        ), CryptoError::SUCCESS);
        EXPECT_EQ(bob.deriveSessionKeys(
            reinterpret_cast<const uint8_t*>(context), strlen(context)
        ), CryptoError::SUCCESS);
        
        // 验证会话密钥
        const auto* alice_keys = alice.getSessionKeys();
        const auto* bob_keys = bob.getSessionKeys();
        
        ASSERT_NE(alice_keys, nullptr);
        ASSERT_NE(bob_keys, nullptr);
        
        EXPECT_TRUE(utils::secureCompare(
            alice_keys->encryption_key, bob_keys->encryption_key, AES_256_KEY_SIZE));
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    double avg_time = duration.count() / (double)iterations;
    double protocols_per_second = 1000.0 / avg_time;
    
    std::cout << "完成 " << iterations << " 个完整协议交换:" << std::endl;
    std::cout << "  总时间: " << duration.count() << " 毫秒" << std::endl;
    std::cout << "  平均时间: " << avg_time << " 毫秒/协议" << std::endl;
    std::cout << "  协议速度: " << protocols_per_second << " 协议/秒" << std::endl;
    
    // 性能基准：应该能在1秒内完成至少5个完整协议
    EXPECT_GT(protocols_per_second, 5.0);
}

// 测试内存使用情况
TEST_F(ECDHPerformanceTest, MemoryUsage) {
    std::cout << "\n=== ECDH内存使用测试 ===" << std::endl;
    
    // 测试KeyExchangeProtocol的内存占用
    KeyExchangeProtocol protocol;
    
    std::cout << "KeyExchangeProtocol对象大小: " << sizeof(protocol) << " 字节" << std::endl;
    std::cout << "私钥大小: " << ECDH_PRIVATE_KEY_SIZE << " 字节" << std::endl;
    std::cout << "公钥大小: " << ECDH_PUBLIC_KEY_SIZE << " 字节" << std::endl;
    std::cout << "共享密钥大小: " << ECDH_SHARED_SECRET_SIZE << " 字节" << std::endl;
    std::cout << "会话密钥大小: " << (AES_256_KEY_SIZE + SHA_256_HASH_SIZE + AES_GCM_IV_SIZE) << " 字节" << std::endl;
    
    // 验证内存占用合理
    EXPECT_LT(sizeof(protocol), 1024);  // 应该小于1KB
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
