#include <gtest/gtest.h>
#include "crypto/crypto.h"
#include <iostream>
#include <string>
#include <chrono>

using namespace sduvpn::crypto;

class KeyDerivationVectorTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
    
    // 辅助函数：将十六进制字符串转换为字节数组
    std::vector<uint8_t> hexToBytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }
    
    // 辅助函数：将字节数组转换为十六进制字符串
    std::string bytesToHex(const uint8_t* bytes, size_t len) {
        return utils::toHex(bytes, len);
    }
};

// 测试PBKDF2标准测试向量
TEST_F(KeyDerivationVectorTest, PBKDF2TestVectors) {
    std::cout << "\n=== PBKDF2-SHA256标准测试向量 ===" << std::endl;
    
    struct PBKDF2Vector {
        std::string password;
        std::string salt;
        uint32_t iterations;
        size_t key_len;
        std::string expected;
        std::string description;
    };
    
    // RFC 6070 PBKDF2测试向量 (适配SHA-256)
    std::vector<PBKDF2Vector> vectors = {
        {
            "password",
            "salt",
            1,
            32,
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
            "基础测试 - 1次迭代"
        },
        {
            "password",
            "salt", 
            2,
            32,
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
            "基础测试 - 2次迭代"
        },
        {
            "password",
            "salt",
            4096,
            32,
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
            "标准安全级别 - 4096次迭代"
        },
        {
            "passwordPASSWORDpassword",
            "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            40,
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9",
            "长密码和盐值测试"
        }
    };
    
    for (size_t i = 0; i < vectors.size(); ++i) {
        const auto& vec = vectors[i];
        std::cout << "\n测试向量 " << (i + 1) << ": " << vec.description << std::endl;
        
        std::vector<uint8_t> derived_key(vec.key_len);
        
        auto start = std::chrono::high_resolution_clock::now();
        
        CryptoError result = KeyDerivation::pbkdf2_password(
            vec.password,
            reinterpret_cast<const uint8_t*>(vec.salt.c_str()),
            vec.salt.length(),
            vec.iterations,
            vec.key_len,
            derived_key.data()
        );
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        EXPECT_EQ(result, CryptoError::SUCCESS);
        
        std::string actual_hex = bytesToHex(derived_key.data(), vec.key_len);
        std::cout << "  密码: " << vec.password << std::endl;
        std::cout << "  盐值: " << vec.salt << std::endl;
        std::cout << "  迭代: " << vec.iterations << std::endl;
        std::cout << "  时间: " << duration.count() << " ms" << std::endl;
        std::cout << "  期望: " << vec.expected << std::endl;
        std::cout << "  实际: " << actual_hex << std::endl;
        
        EXPECT_EQ(actual_hex, vec.expected) << "PBKDF2测试向量 " << (i + 1) << " 失败";
        
        if (actual_hex == vec.expected) {
            std::cout << "  ✅ 通过" << std::endl;
        } else {
            std::cout << "  ❌ 失败" << std::endl;
        }
    }
}

// 测试HKDF标准测试向量
TEST_F(KeyDerivationVectorTest, HKDFTestVectors) {
    std::cout << "\n=== HKDF-SHA256标准测试向量 ===" << std::endl;
    
    struct HKDFVector {
        std::string ikm;
        std::string salt;
        std::string info;
        size_t okm_len;
        std::string expected;
        std::string description;
    };
    
    // RFC 5869 HKDF测试向量
    std::vector<HKDFVector> vectors = {
        {
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",  // 22字节的0x0b
            "000102030405060708090a0b0c",  // 13字节盐值
            "f0f1f2f3f4f5f6f7f8f9",  // 10字节info
            42,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            "RFC 5869 测试用例1"
        },
        {
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaab",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            82,
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
            "RFC 5869 测试用例2"
        },
        {
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",  // 22字节的0x0b
            "",  // 空盐值
            "",  // 空info
            42,
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            "RFC 5869 测试用例3 - 无盐无info"
        }
    };
    
    for (size_t i = 0; i < vectors.size(); ++i) {
        const auto& vec = vectors[i];
        std::cout << "\n测试向量 " << (i + 1) << ": " << vec.description << std::endl;
        
        // 转换输入
        std::vector<uint8_t> ikm_bytes = hexToBytes(vec.ikm);
        std::vector<uint8_t> salt_bytes = hexToBytes(vec.salt);
        
        std::vector<uint8_t> derived_key(vec.okm_len);
        
        // 转换info为字节数组
        std::vector<uint8_t> info_bytes = hexToBytes(vec.info);
        
        CryptoError result = KeyDerivation::hkdf(
            ikm_bytes.data(), ikm_bytes.size(),
            salt_bytes.empty() ? nullptr : salt_bytes.data(),
            salt_bytes.size(),
            info_bytes.empty() ? nullptr : info_bytes.data(),
            info_bytes.size(),
            vec.okm_len,
            derived_key.data()
        );
        
        EXPECT_EQ(result, CryptoError::SUCCESS);
        
        std::string actual_hex = bytesToHex(derived_key.data(), vec.okm_len);
        std::cout << "  IKM长度: " << ikm_bytes.size() << " 字节" << std::endl;
        std::cout << "  盐值长度: " << salt_bytes.size() << " 字节" << std::endl;
        std::cout << "  Info长度: " << vec.info.length() << " 字节" << std::endl;
        std::cout << "  输出长度: " << vec.okm_len << " 字节" << std::endl;
        std::cout << "  期望: " << vec.expected << std::endl;
        std::cout << "  实际: " << actual_hex << std::endl;
        
        EXPECT_EQ(actual_hex, vec.expected) << "HKDF测试向量 " << (i + 1) << " 失败";
        
        if (actual_hex == vec.expected) {
            std::cout << "  ✅ 通过" << std::endl;
        } else {
            std::cout << "  ❌ 失败" << std::endl;
        }
    }
}

// 测试密钥派生性能
TEST_F(KeyDerivationVectorTest, PerformanceTest) {
    std::cout << "\n=== 密钥派生性能测试 ===" << std::endl;
    
    const std::string password = "test_password_123";
    const std::string salt_str = "random_salt_456";
    const uint8_t* salt = reinterpret_cast<const uint8_t*>(salt_str.c_str());
    const size_t salt_len = salt_str.length();
    
    // 测试不同迭代次数的PBKDF2性能
    std::vector<uint32_t> iteration_counts = {1000, 4096, 10000, 100000};
    
    for (uint32_t iterations : iteration_counts) {
        uint8_t derived_key[32];
        
        auto start = std::chrono::high_resolution_clock::now();
        
        CryptoError result = KeyDerivation::pbkdf2_password(
            password, salt, salt_len, iterations, 32, derived_key
        );
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        EXPECT_EQ(result, CryptoError::SUCCESS);
        
        std::cout << "PBKDF2 " << iterations << " 次迭代: " << duration.count() << " ms" << std::endl;
        
        // 清理敏感数据
        utils::secureZero(derived_key, sizeof(derived_key));
    }
    
    // 测试HKDF性能
    uint8_t ikm[32];
    SecureRandom::generate(ikm, sizeof(ikm));
    
    const int hkdf_iterations = 1000;
    uint8_t okm[64];
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < hkdf_iterations; ++i) {
        CryptoError result = KeyDerivation::hkdf_info(
            ikm, sizeof(ikm),
            salt, salt_len,
            "SDUVPN HKDF test",
            sizeof(okm),
            okm
        );
        EXPECT_EQ(result, CryptoError::SUCCESS);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double avg_time = duration.count() / (double)hkdf_iterations;
    double hkdf_per_second = 1000000.0 / avg_time;
    
    std::cout << "HKDF " << hkdf_iterations << " 次计算: " << duration.count() << " 微秒" << std::endl;
    std::cout << "  平均时间: " << avg_time << " 微秒/次" << std::endl;
    std::cout << "  计算速度: " << hkdf_per_second << " 次/秒" << std::endl;
    
    // 性能基准：HKDF应该很快
    EXPECT_GT(hkdf_per_second, 1000.0);
    
    // 清理敏感数据
    utils::secureZero(ikm, sizeof(ikm));
    utils::secureZero(okm, sizeof(okm));
}

// 测试安全特性
TEST_F(KeyDerivationVectorTest, SecurityFeatures) {
    std::cout << "\n=== 密钥派生安全特性测试 ===" << std::endl;
    
    const std::string password = "secure_password";
    const std::string salt_str = "random_salt";
    const uint8_t* salt = reinterpret_cast<const uint8_t*>(salt_str.c_str());
    const size_t salt_len = salt_str.length();
    
    // 测试1: 相同输入产生相同输出
    uint8_t key1[32], key2[32];
    
    CryptoError result1 = KeyDerivation::pbkdf2_password(
        password, salt, salt_len, 4096, 32, key1
    );
    CryptoError result2 = KeyDerivation::pbkdf2_password(
        password, salt, salt_len, 4096, 32, key2
    );
    
    EXPECT_EQ(result1, CryptoError::SUCCESS);
    EXPECT_EQ(result2, CryptoError::SUCCESS);
    EXPECT_TRUE(KeyDerivation::verify_derived_key(key1, key2, 32));
    
    std::cout << "1. ✅ 相同输入产生相同输出" << std::endl;
    
    // 测试2: 不同密码产生不同输出
    uint8_t key3[32];
    CryptoError result3 = KeyDerivation::pbkdf2_password(
        "different_password", salt, salt_len, 4096, 32, key3
    );
    
    EXPECT_EQ(result3, CryptoError::SUCCESS);
    EXPECT_FALSE(KeyDerivation::verify_derived_key(key1, key3, 32));
    
    std::cout << "2. ✅ 不同密码产生不同输出" << std::endl;
    
    // 测试3: 不同盐值产生不同输出
    uint8_t key4[32];
    const std::string salt2_str = "different_salt";
    CryptoError result4 = KeyDerivation::pbkdf2_password(
        password, 
        reinterpret_cast<const uint8_t*>(salt2_str.c_str()),
        salt2_str.length(),
        4096, 32, key4
    );
    
    EXPECT_EQ(result4, CryptoError::SUCCESS);
    EXPECT_FALSE(KeyDerivation::verify_derived_key(key1, key4, 32));
    
    std::cout << "3. ✅ 不同盐值产生不同输出" << std::endl;
    
    // 测试4: 不同迭代次数产生不同输出
    uint8_t key5[32];
    CryptoError result5 = KeyDerivation::pbkdf2_password(
        password, salt, salt_len, 8192, 32, key5  // 不同迭代次数
    );
    
    EXPECT_EQ(result5, CryptoError::SUCCESS);
    EXPECT_FALSE(KeyDerivation::verify_derived_key(key1, key5, 32));
    
    std::cout << "4. ✅ 不同迭代次数产生不同输出" << std::endl;
    
    // 清理所有敏感数据
    utils::secureZero(key1, sizeof(key1));
    utils::secureZero(key2, sizeof(key2));
    utils::secureZero(key3, sizeof(key3));
    utils::secureZero(key4, sizeof(key4));
    utils::secureZero(key5, sizeof(key5));
    
    std::cout << "✅ 所有安全特性验证通过" << std::endl;
}

// 测试错误处理
TEST_F(KeyDerivationVectorTest, ErrorHandling) {
    std::cout << "\n=== 密钥派生错误处理测试 ===" << std::endl;
    
    uint8_t output[32];
    uint8_t salt[16];
    SecureRandom::generate(salt, sizeof(salt));
    
    // 测试无效参数
    EXPECT_EQ(KeyDerivation::pbkdf2(nullptr, 0, salt, 16, 1000, 32, output), 
              CryptoError::INVALID_PARAMETER);
    EXPECT_EQ(KeyDerivation::pbkdf2(salt, 16, nullptr, 0, 1000, 32, output), 
              CryptoError::INVALID_PARAMETER);
    EXPECT_EQ(KeyDerivation::pbkdf2(salt, 16, salt, 16, 0, 32, output), 
              CryptoError::INVALID_PARAMETER);
    EXPECT_EQ(KeyDerivation::pbkdf2(salt, 16, salt, 16, 1000, 0, output), 
              CryptoError::INVALID_PARAMETER);
    EXPECT_EQ(KeyDerivation::pbkdf2(salt, 16, salt, 16, 1000, 32, nullptr), 
              CryptoError::INVALID_PARAMETER);
    
    std::cout << "1. ✅ PBKDF2无效参数检测正确" << std::endl;
    
    // 测试HKDF无效参数
    EXPECT_EQ(KeyDerivation::hkdf(nullptr, 0, salt, 16, salt, 16, 32, output), 
              CryptoError::INVALID_PARAMETER);
    EXPECT_EQ(KeyDerivation::hkdf(salt, 16, salt, 16, salt, 16, 0, output), 
              CryptoError::INVALID_PARAMETER);
    EXPECT_EQ(KeyDerivation::hkdf(salt, 16, salt, 16, salt, 16, 32, nullptr), 
              CryptoError::INVALID_PARAMETER);
    
    // 测试HKDF长度限制
    EXPECT_EQ(KeyDerivation::hkdf(salt, 16, salt, 16, salt, 16, 256 * 32, output), 
              CryptoError::INVALID_PARAMETER);
    
    std::cout << "2. ✅ HKDF无效参数检测正确" << std::endl;
    
    // 测试便利函数错误处理
    EXPECT_EQ(KeyDerivation::pbkdf2_password("", salt, 16, 1000, 32, output), 
              CryptoError::INVALID_PARAMETER);
    
    std::cout << "3. ✅ 便利函数错误处理正确" << std::endl;
    
    std::cout << "✅ 所有错误处理测试通过" << std::endl;
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
