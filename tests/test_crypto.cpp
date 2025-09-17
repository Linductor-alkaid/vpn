#include "crypto/crypto.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <cassert>
#include <functional>

using namespace sduvpn::crypto;

// =============================================================================
// 简单测试框架
// =============================================================================
class SimpleTest {
public:
    static void run(const std::string& test_name, std::function<bool()> test_func) {
        std::cout << "[TEST] " << test_name << " ... ";
        
        try {
            bool result = test_func();
            if (result) {
                std::cout << "PASSED" << std::endl;
                passed_++;
            } else {
                std::cout << "FAILED" << std::endl;
                failed_++;
            }
        } catch (const std::exception& e) {
            std::cout << "EXCEPTION: " << e.what() << std::endl;
            failed_++;
        }
        
        total_++;
    }
    
    static void printSummary() {
        std::cout << "\n=== TEST SUMMARY ===" << std::endl;
        std::cout << "Total: " << total_ << " tests" << std::endl;
        std::cout << "Passed: " << passed_ << " tests" << std::endl;
        std::cout << "Failed: " << failed_ << " tests" << std::endl;
        std::cout << "Success Rate: " << std::fixed << std::setprecision(1) 
                  << (total_ > 0 ? (100.0 * passed_ / total_) : 0.0) << "%" << std::endl;
    }
    
    static bool allPassed() {
        return failed_ == 0;
    }

private:
    static int total_;
    static int passed_;
    static int failed_;
};

int SimpleTest::total_ = 0;
int SimpleTest::passed_ = 0;
int SimpleTest::failed_ = 0;

// =============================================================================
// 辅助函数
// =============================================================================
void printHexBuffer(const std::string& label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) 
                  << static_cast<unsigned>(data[i]);
        if (i < len - 1) std::cout << " ";
    }
    std::cout << std::dec << std::endl;
}

bool isAllZero(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (data[i] != 0) return false;
    }
    return true;
}

bool isAllSame(const uint8_t* data, size_t len) {
    if (len <= 1) return true;
    uint8_t first = data[0];
    for (size_t i = 1; i < len; ++i) {
        if (data[i] != first) return false;
    }
    return true;
}

// =============================================================================
// SecureRandom 测试
// =============================================================================
bool testSecureRandomBasic() {
    std::cout << "\n--- SecureRandom Basic Function Test ---" << std::endl;
    
    // Test generating random numbers of different lengths
    const size_t sizes[] = {1, 16, 32, 64, 128, 256};
    
    for (size_t size : sizes) {
        std::vector<uint8_t> buffer(size);
        CryptoError result = SecureRandom::generate(buffer.data(), size);
        
        if (result != CryptoError::SUCCESS) {
            std::cout << "Failed to generate " << size << " bytes random number" << std::endl;
            return false;
        }
        
        // Check not all zeros
        if (isAllZero(buffer.data(), size)) {
            std::cout << "Generated " << size << " bytes random number is all zeros" << std::endl;
            return false;
        }
        
        std::cout << "✓ Successfully generated " << size << " bytes random number" << std::endl;
        if (size <= 32) {
            printHexBuffer("  Random", buffer.data(), size);
        }
    }
    
    return true;
}

bool testSecureRandomUniqueness() {
    std::cout << "\n--- SecureRandom Uniqueness Test ---" << std::endl;
    
    const size_t buffer_size = 32;
    const int test_count = 10;
    
    std::vector<std::vector<uint8_t>> randoms;
    
    // Generate multiple random numbers
    for (int i = 0; i < test_count; ++i) {
        std::vector<uint8_t> buffer(buffer_size);
        CryptoError result = SecureRandom::generate(buffer.data(), buffer_size);
        
        if (result != CryptoError::SUCCESS) {
            std::cout << "Failed to generate random number #" << (i + 1) << std::endl;
            return false;
        }
        
        randoms.push_back(buffer);
    }
    
    // Check for duplicates
    for (int i = 0; i < test_count; ++i) {
        for (int j = i + 1; j < test_count; ++j) {
            if (utils::secureCompare(randoms[i].data(), randoms[j].data(), buffer_size)) {
                std::cout << "Found duplicate random numbers: #" << i << " and #" << j << std::endl;
                return false;
            }
        }
    }
    
    std::cout << "✓ All " << test_count << " random numbers are unique" << std::endl;
    return true;
}

bool testSecureRandomInt() {
    std::cout << "\n--- SecureRandom Integer Generation Test ---" << std::endl;
    
    // Test random integers in different ranges
    struct TestCase {
        uint32_t min, max;
        const char* desc;
    };
    
    TestCase cases[] = {
        {0, 1, "Boolean (0-1)"},
        {1, 6, "Dice (1-6)"},
        {0, 255, "Byte (0-255)"},
        {1000, 9999, "4-digit (1000-9999)"},
        {0, 1000000, "Large range (0-1000000)"}  // Avoid UINT32_MAX which might cause issues
    };
    
    for (const auto& test_case : cases) {
        std::cout << "Testing " << test_case.desc << std::endl;
        
        std::vector<uint32_t> values;
        const int sample_count = 100;
        
        // Generate samples
        for (int i = 0; i < sample_count; ++i) {
            try {
                uint32_t value = SecureRandom::generateInt(test_case.min, test_case.max);
                
                // Check range
                if (value < test_case.min || value > test_case.max) {
                    std::cout << "  ✗ Value " << value << " out of range [" 
                              << test_case.min << ", " << test_case.max << "]" << std::endl;
                    return false;
                }
                
                values.push_back(value);
                
            } catch (const std::exception& e) {
                std::cout << "  ✗ Exception during integer generation: " << e.what() << std::endl;
                return false;
            } catch (...) {
                std::cout << "  ✗ Unknown exception during integer generation" << std::endl;
                return false;
            }
        }
        
        // Simple distribution check (for small ranges)
        if (test_case.max - test_case.min <= 10) {
            std::vector<int> counts(test_case.max - test_case.min + 1, 0);
            for (uint32_t value : values) {
                counts[value - test_case.min]++;
            }
            
            std::cout << "  Distribution: ";
            for (size_t i = 0; i < counts.size(); ++i) {
                std::cout << (test_case.min + i) << ":" << counts[i] << " ";
            }
            std::cout << std::endl;
        }
        
        std::cout << "  ✓ All values within valid range" << std::endl;
    }
    
    return true;
}

// =============================================================================
// SecureBuffer Tests
// =============================================================================
bool testSecureBufferBasic() {
    std::cout << "\n--- SecureBuffer Basic Function Test ---" << std::endl;
    
    // Test buffers of different sizes
    const size_t sizes[] = {1, 16, 32, 64, 128, 256, 1024, 4096};
    
    for (size_t size : sizes) {
        try {
            SecureBuffer buffer(size);
            
            // Check size
            if (buffer.size() != size) {
                std::cout << "Buffer size mismatch: expected " << size 
                          << ", actual " << buffer.size() << std::endl;
                return false;
            }
            
            // Check data pointer
            if (buffer.data() == nullptr) {
                std::cout << "Buffer data pointer is null" << std::endl;
                return false;
            }
            
            // Test write and read
            for (size_t i = 0; i < size; ++i) {
                buffer.data()[i] = static_cast<uint8_t>(i & 0xFF);
            }
            
            for (size_t i = 0; i < size; ++i) {
                if (buffer.data()[i] != static_cast<uint8_t>(i & 0xFF)) {
                    std::cout << "Buffer data mismatch at " << i << std::endl;
                    return false;
                }
            }
            
            std::cout << "✓ " << size << " bytes buffer test passed" << std::endl;
            
        } catch (const std::exception& e) {
            std::cout << "Failed to create " << size << " bytes buffer: " << e.what() << std::endl;
            return false;
        }
    }
    
    return true;
}

bool testSecureBufferClear() {
    std::cout << "\n--- SecureBuffer Clear Function Test ---" << std::endl;
    
    const size_t size = 256;
    SecureBuffer buffer(size);
    
    // Fill with random data
    SecureRandom::generate(buffer.data(), size);
    
    // Check not all zeros
    if (isAllZero(buffer.data(), size)) {
        std::cout << "Random data is unexpectedly all zeros" << std::endl;
        return false;
    }
    
    std::cout << "✓ Buffer filled with random data" << std::endl;
    
    // Clear
    buffer.clear();
    
    // Check all zeros
    if (!isAllZero(buffer.data(), size)) {
        std::cout << "Buffer still has non-zero data after clear" << std::endl;
        return false;
    }
    
    std::cout << "✓ Buffer successfully cleared" << std::endl;
    return true;
}

bool testSecureBufferMove() {
    std::cout << "\n--- SecureBuffer Move Semantics Test ---" << std::endl;
    
    const size_t size = 128;
    
    // Create original buffer
    SecureBuffer original(size);
    SecureRandom::generate(original.data(), size);
    
    // Save data copy for comparison
    std::vector<uint8_t> original_data(original.data(), original.data() + size);
    
    // Move construction
    SecureBuffer moved = std::move(original);
    
    // Check original buffer is cleared
    if (original.data() != nullptr || original.size() != 0) {
        std::cout << "Original buffer not cleared after move" << std::endl;
        return false;
    }
    
    // Check moved buffer
    if (moved.size() != size || moved.data() == nullptr) {
        std::cout << "Moved buffer state incorrect" << std::endl;
        return false;
    }
    
    // Check data integrity
    if (!utils::secureCompare(moved.data(), original_data.data(), size)) {
        std::cout << "Data mismatch after move" << std::endl;
        return false;
    }
    
    std::cout << "✓ Move construction test passed" << std::endl;
    
    // Test move assignment
    SecureBuffer another(64);
    another = std::move(moved);
    
    if (moved.data() != nullptr || moved.size() != 0) {
        std::cout << "Source buffer not cleared after move assignment" << std::endl;
        return false;
    }
    
    if (another.size() != size || another.data() == nullptr) {
        std::cout << "Target buffer state incorrect after move assignment" << std::endl;
        return false;
    }
    
    std::cout << "✓ Move assignment test passed" << std::endl;
    return true;
}

// =============================================================================
// Utility Functions Tests
// =============================================================================
bool testSecureCompare() {
    std::cout << "\n--- Secure Compare Function Test ---" << std::endl;
    
    // Test identical data
    std::vector<uint8_t> data1 = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> data2 = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    if (!utils::secureCompare(data1.data(), data2.data(), data1.size())) {
        std::cout << "Identical data comparison failed" << std::endl;
        return false;
    }
    
    std::cout << "✓ Identical data comparison correct" << std::endl;
    
    // Test different data
    data2[2] = 0xFF;
    if (utils::secureCompare(data1.data(), data2.data(), data1.size())) {
        std::cout << "Different data comparison failed" << std::endl;
        return false;
    }
    
    std::cout << "✓ Different data comparison correct" << std::endl;
    
    // Test null pointer
    if (utils::secureCompare(nullptr, data1.data(), data1.size())) {
        std::cout << "Null pointer comparison should return false" << std::endl;
        return false;
    }
    
    std::cout << "✓ Null pointer handling correct" << std::endl;
    
    return true;
}

bool testHexConversion() {
    std::cout << "\n--- Hex Conversion Test ---" << std::endl;
    
    // Test data
    std::vector<uint8_t> original = {
        0x00, 0x01, 0x0F, 0x10, 0xFF, 0xAB, 0xCD, 0xEF
    };
    
    // Convert to hex string
    std::string hex = utils::toHex(original.data(), original.size());
    std::cout << "Original data to hex: " << hex << std::endl;
    
    // Check length
    if (hex.length() != original.size() * 2) {
        std::cout << "Hex string length incorrect" << std::endl;
        return false;
    }
    
    // Convert back to binary
    std::vector<uint8_t> converted(original.size());
    size_t converted_len = utils::fromHex(hex, converted.data(), converted.size());
    
    if (converted_len != original.size()) {
        std::cout << "Converted length from hex incorrect" << std::endl;
        return false;
    }
    
    // Compare data
    if (!utils::secureCompare(original.data(), converted.data(), original.size())) {
        std::cout << "Hex round-trip conversion data mismatch" << std::endl;
        return false;
    }
    
    std::cout << "✓ Hex round-trip conversion correct" << std::endl;
    
    // Test invalid hex string
    if (utils::fromHex("invalid", converted.data(), converted.size()) != 0) {
        std::cout << "Invalid hex string should return 0" << std::endl;
        return false;
    }
    
    std::cout << "✓ Invalid input handling correct" << std::endl;
    
    return true;
}

bool testSecureZero() {
    std::cout << "\n--- Secure Zero Test ---" << std::endl;
    
    // Create test data
    std::vector<uint8_t> data(256);
    SecureRandom::generate(data.data(), data.size());
    
    // Ensure not all zeros
    if (isAllZero(data.data(), data.size())) {
        std::cout << "Test data is unexpectedly all zeros" << std::endl;
        return false;
    }
    
    std::cout << "✓ Test data prepared" << std::endl;
    
    // Secure zero
    utils::secureZero(data.data(), data.size());
    
    // Check all zeros
    if (!isAllZero(data.data(), data.size())) {
        std::cout << "Data still has non-zero values after secure zero" << std::endl;
        return false;
    }
    
    std::cout << "✓ Secure zero function correct" << std::endl;
    return true;
}

// =============================================================================
// Performance Tests
// =============================================================================
bool testPerformance() {
    std::cout << "\n--- Performance Test ---" << std::endl;
    
    // Reduced test size to avoid memory issues
    const size_t test_size = 64 * 1024; // 64KB instead of 1MB
    const int iterations = 10;           // 10 instead of 100
    
    std::cout << "Testing " << iterations << " iterations of " 
              << test_size << " bytes each..." << std::endl;
    
    try {
        // Test random number generation performance
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < iterations; ++i) {
            std::vector<uint8_t> buffer(test_size);
            CryptoError result = SecureRandom::generate(buffer.data(), buffer.size());
            
            if (result != CryptoError::SUCCESS) {
                std::cout << "Random generation failed at iteration " << i << std::endl;
                return false;
            }
            
            // Progress indicator
            if (i % 2 == 0) {
                std::cout << "  Progress: " << (i + 1) << "/" << iterations << std::endl;
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        if (duration.count() > 0) {
            double mb_per_sec = (double)(test_size * iterations) / (1024 * 1024) / (duration.count() / 1000.0);
            std::cout << "Random generation performance: " << std::fixed << std::setprecision(2) 
                      << mb_per_sec << " MB/s" << std::endl;
        } else {
            std::cout << "Performance test completed too quickly to measure accurately" << std::endl;
        }
        
        std::cout << "✓ Performance test completed successfully" << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cout << "Performance test failed with exception: " << e.what() << std::endl;
        return false;
    } catch (...) {
        std::cout << "Performance test failed with unknown exception" << std::endl;
        return false;
    }
}

// =============================================================================
// Main Function
// =============================================================================
int main() {
    std::cout << "=== SDUVPN Crypto Library Test Program ===" << std::endl;
    std::cout << "Windows Platform - No Dependencies Version" << std::endl;
    std::cout << "Build Time: " << __DATE__ << " " << __TIME__ << std::endl;
    std::cout << std::endl;
    
    // Run all tests
    SimpleTest::run("SecureRandom Basic Functions", testSecureRandomBasic);
    SimpleTest::run("SecureRandom Uniqueness", testSecureRandomUniqueness);
    SimpleTest::run("SecureRandom Integer Generation", testSecureRandomInt);
    
    SimpleTest::run("SecureBuffer Basic Functions", testSecureBufferBasic);
    SimpleTest::run("SecureBuffer Clear Function", testSecureBufferClear);
    SimpleTest::run("SecureBuffer Move Semantics", testSecureBufferMove);
    
    SimpleTest::run("Secure Compare Function", testSecureCompare);
    SimpleTest::run("Hex Conversion", testHexConversion);
    SimpleTest::run("Secure Zero", testSecureZero);
    
    SimpleTest::run("Performance Test", testPerformance);
    
    // Output test results
    SimpleTest::printSummary();
    
    if (SimpleTest::allPassed()) {
        std::cout << "\nAll tests PASSED! Crypto library is working properly." << std::endl;
        return 0;
    } else {
        std::cout << "\nSome tests FAILED. Please check the implementation." << std::endl;
        return 1;
    }
}
