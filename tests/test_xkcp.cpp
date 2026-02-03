#include "src/core/k12_and_key_util.h"
// #include "XKCP/KangarooTwelve.h"
#include <gtest/gtest.h>
#include <chrono>
#include <vector>
#include <random>
extern "C" {
int KT128(const unsigned char *input, size_t inputByteLen,
          unsigned char *output, size_t outputByteLen,
          const unsigned char *customization, size_t customByteLen);
int KT256(const unsigned char *input, size_t inputByteLen,
          unsigned char *output, size_t outputByteLen,
          const unsigned char *customization, size_t customByteLen);
}

class KangarooTwelveTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Generate random test data
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        testData.resize(1024);
        for (auto &byte: testData) {
            byte = static_cast<unsigned char>(dis(gen));
        }
    }

    std::vector<unsigned char> testData;
};

TEST_F(KangarooTwelveTest, CompareImplementations) {
    const size_t outputLength = 32; // 256 bits
    std::vector<unsigned char> output1(outputLength);
    std::vector<unsigned char> output2(outputLength);

    // Test stock implementation
    auto start1 = std::chrono::high_resolution_clock::now();
    KangarooTwelve(testData.data(), testData.size(), output1.data(), outputLength);
    auto end1 = std::chrono::high_resolution_clock::now();
    auto duration1 = std::chrono::duration_cast<std::chrono::microseconds>(end1 - start1);

    // Test optimized implementation
    auto start2 = std::chrono::high_resolution_clock::now();
    KT128(testData.data(), testData.size(), output2.data(), 32, nullptr, 0);
    auto end2 = std::chrono::high_resolution_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end2 - start2);

    // Compare results
    ASSERT_EQ(output1, output2) << "Hash results differ between implementations";

    // Print performance comparison
    std::cout << "Stock implementation time: " << duration1.count() << " microseconds\n";
    std::cout << "Optimized implementation time: " << duration2.count() << " microseconds\n";
}

