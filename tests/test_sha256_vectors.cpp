#include <gtest/gtest.h>
#include "crypto/crypto.h"
#include <iostream>
#include <string>

using namespace sduvpn::crypto;

class SHA256VectorTest : public ::testing::Test {
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

// 测试NIST标准测试向量
TEST_F(SHA256VectorTest, NISTTestVectors) {
    std::cout << "\n=== SHA-256 NIST标准测试向量 ===" << std::endl;
    
    struct TestVector {
        std::string input;
        std::string expected;
        std::string description;
    };
    
    // NIST FIPS 180-4标准测试向量
    std::vector<TestVector> vectors = {
        {
            "",  // 空字符串
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "空字符串"
        },
        {
            "61",  // "a"
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            "单字符 'a'"
        },
        {
            "616263",  // "abc"
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "字符串 'abc'"
        },
        {
            "6d65737361676520646967657374",  // "message digest"
            "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
            "字符串 'message digest'"
        },
        {
            "6162636465666768696a6b6c6d6e6f707172737475767778797a",  // "abcdefghijklmnopqrstuvwxyz"
            "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
            "26个小写字母"
        }
    };
    
    for (size_t i = 0; i < vectors.size(); ++i) {
        const auto& vec = vectors[i];
        std::cout << "\n测试向量 " << (i + 1) << ": " << vec.description << std::endl;
        
        // 转换输入
        std::vector<uint8_t> input_bytes = hexToBytes(vec.input);
        
        // 计算哈希
        uint8_t actual_hash[SHA_256_HASH_SIZE];
        CryptoError result = SHA256::hash(
            input_bytes.empty() ? nullptr : input_bytes.data(),
            input_bytes.size(),
            actual_hash
        );
        
        EXPECT_EQ(result, CryptoError::SUCCESS);
        
        // 比较结果
        std::string actual_hex = bytesToHex(actual_hash, SHA_256_HASH_SIZE);
        std::cout << "  输入: " << (vec.input.empty() ? "(空)" : vec.input) << std::endl;
        std::cout << "  期望: " << vec.expected << std::endl;
        std::cout << "  实际: " << actual_hex << std::endl;
        
        EXPECT_EQ(actual_hex, vec.expected) << "测试向量 " << (i + 1) << " 失败";
        
        if (actual_hex == vec.expected) {
            std::cout << "  ✅ 通过" << std::endl;
        } else {
            std::cout << "  ❌ 失败" << std::endl;
        }
    }
}

// 测试大数据块哈希
TEST_F(SHA256VectorTest, LargeDataHash) {
    std::cout << "\n=== 大数据块哈希测试 ===" << std::endl;
    
    // 创建1MB的测试数据
    const size_t data_size = 1024 * 1024;
    std::vector<uint8_t> large_data(data_size);
    
    // 填充模式数据
    for (size_t i = 0; i < data_size; ++i) {
        large_data[i] = i & 0xff;
    }
    
    uint8_t hash[SHA_256_HASH_SIZE];
    CryptoError result = SHA256::hash(large_data.data(), large_data.size(), hash);
    EXPECT_EQ(result, CryptoError::SUCCESS);
    
    std::cout << "1MB数据哈希: " << bytesToHex(hash, SHA_256_HASH_SIZE) << std::endl;
    
    // 验证哈希不为零
    bool hash_nonzero = false;
    for (size_t i = 0; i < SHA_256_HASH_SIZE; ++i) {
        if (hash[i] != 0) {
            hash_nonzero = true;
            break;
        }
    }
    EXPECT_TRUE(hash_nonzero);
}

// 测试增量哈希
TEST_F(SHA256VectorTest, IncrementalHash) {
    std::cout << "\n=== 增量哈希测试 ===" << std::endl;
    
    const std::string test_string = "The quick brown fox jumps over the lazy dog";
    
    // 一次性哈希
    uint8_t hash_once[SHA_256_HASH_SIZE];
    CryptoError result = SHA256::hash(
        reinterpret_cast<const uint8_t*>(test_string.c_str()),
        test_string.length(),
        hash_once
    );
    EXPECT_EQ(result, CryptoError::SUCCESS);
    
    // 增量哈希
    SHA256 incremental_hasher;
    
    // 分块添加数据
    const char* data = test_string.c_str();
    size_t len = test_string.length();
    
    incremental_hasher.update(reinterpret_cast<const uint8_t*>(data), 10);
    incremental_hasher.update(reinterpret_cast<const uint8_t*>(data + 10), 15);
    incremental_hasher.update(reinterpret_cast<const uint8_t*>(data + 25), len - 25);
    
    uint8_t hash_incremental[SHA_256_HASH_SIZE];
    result = incremental_hasher.finalize(hash_incremental);
    EXPECT_EQ(result, CryptoError::SUCCESS);
    
    // 比较结果
    EXPECT_TRUE(utils::secureCompare(hash_once, hash_incremental, SHA_256_HASH_SIZE));
    
    std::cout << "测试字符串: " << test_string << std::endl;
    std::cout << "一次性哈希: " << bytesToHex(hash_once, SHA_256_HASH_SIZE) << std::endl;
    std::cout << "增量哈希:   " << bytesToHex(hash_incremental, SHA_256_HASH_SIZE) << std::endl;
    std::cout << "✅ 增量哈希与一次性哈希结果一致" << std::endl;
}

// 测试HMAC标准测试向量
TEST_F(SHA256VectorTest, HMACTestVectors) {
    std::cout << "\n=== HMAC-SHA256标准测试向量 ===" << std::endl;
    
    struct HMACVector {
        std::string key;
        std::string data;
        std::string expected;
        std::string description;
    };
    
    // RFC 4231 HMAC-SHA256测试向量
    std::vector<HMACVector> vectors = {
        {
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",  // 20字节的0x0b
            "4869205468657265",  // "Hi There"
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "RFC 4231 测试用例1"
        },
        {
            "4a656665",  // "Jefe"
            "7768617420646f2079612077616e7420666f72206e6f7468696e673f",  // "what do ya want for nothing?"
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            "RFC 4231 测试用例2"
        }
    };
    
    for (size_t i = 0; i < vectors.size(); ++i) {
        const auto& vec = vectors[i];
        std::cout << "\n" << vec.description << std::endl;
        
        // 转换输入
        std::vector<uint8_t> key_bytes = hexToBytes(vec.key);
        std::vector<uint8_t> data_bytes = hexToBytes(vec.data);
        
        // 计算HMAC
        uint8_t actual_hmac[SHA_256_HASH_SIZE];
        CryptoError result = SHA256::hmac(
            key_bytes.data(), key_bytes.size(),
            data_bytes.data(), data_bytes.size(),
            actual_hmac
        );
        
        EXPECT_EQ(result, CryptoError::SUCCESS);
        
        // 比较结果
        std::string actual_hex = bytesToHex(actual_hmac, SHA_256_HASH_SIZE);
        std::cout << "  期望: " << vec.expected << std::endl;
        std::cout << "  实际: " << actual_hex << std::endl;
        
        EXPECT_EQ(actual_hex, vec.expected) << "HMAC测试向量 " << (i + 1) << " 失败";
        
        if (actual_hex == vec.expected) {
            std::cout << "  ✅ 通过" << std::endl;
        } else {
            std::cout << "  ❌ 失败" << std::endl;
        }
    }
}

// 测试边界情况
TEST_F(SHA256VectorTest, EdgeCases) {
    std::cout << "\n=== SHA-256边界情况测试 ===" << std::endl;
    
    uint8_t hash[SHA_256_HASH_SIZE];
    
    // 测试1: 空数据
    CryptoError result = SHA256::hash(nullptr, 0, hash);
    EXPECT_EQ(result, CryptoError::SUCCESS);
    std::cout << "空数据哈希: " << bytesToHex(hash, SHA_256_HASH_SIZE) << std::endl;
    
    // 测试2: 单字节
    uint8_t single_byte = 0x42;
    result = SHA256::hash(&single_byte, 1, hash);
    EXPECT_EQ(result, CryptoError::SUCCESS);
    std::cout << "单字节(0x42)哈希: " << bytesToHex(hash, SHA_256_HASH_SIZE) << std::endl;
    
    // 测试3: 55字节 (填充边界-1)
    std::vector<uint8_t> data_55(55, 0xAA);
    result = SHA256::hash(data_55.data(), 55, hash);
    EXPECT_EQ(result, CryptoError::SUCCESS);
    std::cout << "55字节数据哈希: " << bytesToHex(hash, SHA_256_HASH_SIZE) << std::endl;
    
    // 测试4: 56字节 (填充边界)
    std::vector<uint8_t> data_56(56, 0xBB);
    result = SHA256::hash(data_56.data(), 56, hash);
    EXPECT_EQ(result, CryptoError::SUCCESS);
    std::cout << "56字节数据哈希: " << bytesToHex(hash, SHA_256_HASH_SIZE) << std::endl;
    
    // 测试5: 64字节 (一个完整块)
    std::vector<uint8_t> data_64(64, 0xCC);
    result = SHA256::hash(data_64.data(), 64, hash);
    EXPECT_EQ(result, CryptoError::SUCCESS);
    std::cout << "64字节数据哈希: " << bytesToHex(hash, SHA_256_HASH_SIZE) << std::endl;
    
    std::cout << "✅ 所有边界情况测试通过" << std::endl;
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
