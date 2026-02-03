#include "gtest/gtest.h"
#include <thread>
#include <vector>
#include <numeric>
#include <algorithm>
// Include the headers for the code under test
#include "../src/special_buffer_structs.h"
#include "structs.h"

// Provide a definition for the extern variable to allow linking.
// This instance won't be used in the tests; we'll create local instances.
MutexRoundBuffer MRB_Data(1);


// --- Test Helper Function ---

// Step 2: Create a helper function to generate test packets.
/**
 * @brief Creates a test packet with a header and patterned data.
 * @param size Total size of the packet.
 * @param type The type to set in the packet header.
 * @return A vector containing the raw packet data.
 */
std::vector<uint8_t> createTestPacket(uint32_t size, uint8_t type) {
    if (size < sizeof(RequestResponseHeader)) {
        size = sizeof(RequestResponseHeader);
    }
    std::vector<uint8_t> packet(size);
    auto* header = reinterpret_cast<RequestResponseHeader*>(packet.data());
    header->setSize(size);
    header->setType(type);
    header->randomizeDejavu();

    // Fill payload with a recognizable pattern
    for (uint32_t i = sizeof(RequestResponseHeader); i < size; ++i) {
        packet[i] = (i % 256);
    }
    return packet;
}


// --- Test Fixture ---

class MutexRoundBufferTest : public ::testing::Test {
protected:
    static constexpr size_t BUFFER_CAPACITY = 1024;
};


// --- Single-Threaded Tests ---

// Step 3: Test basic enqueue and dequeue functionality.
TEST_F(MutexRoundBufferTest, BasicEnqueueDequeue) {
    MutexRoundBuffer buffer(BUFFER_CAPACITY);
    auto testPacket = createTestPacket(100, 1);

    ASSERT_TRUE(buffer.EnqueuePacket(testPacket.data()));

    std::vector<uint8_t> receivedPacket(BUFFER_CAPACITY);
    uint32_t receivedSize = 0;
    ASSERT_TRUE(buffer.TryGetPacket(receivedPacket.data(), receivedSize));

    ASSERT_EQ(receivedSize, testPacket.size());
    receivedPacket.resize(receivedSize);
    ASSERT_EQ(testPacket, receivedPacket);
}

// Step 3: Test that multiple packets are handled correctly in sequence.
TEST_F(MutexRoundBufferTest, MultiplePacketSequence) {
    MutexRoundBuffer buffer(BUFFER_CAPACITY);
    auto packet1 = createTestPacket(50, 1);
    auto packet2 = createTestPacket(75, 2);
    auto packet3 = createTestPacket(60, 3);

    ASSERT_TRUE(buffer.EnqueuePacket(packet1.data()));
    ASSERT_TRUE(buffer.EnqueuePacket(packet2.data()));
    ASSERT_TRUE(buffer.EnqueuePacket(packet3.data()));

    std::vector<uint8_t> out(BUFFER_CAPACITY);
    uint32_t outSize = 0;

    ASSERT_TRUE(buffer.TryGetPacket(out.data(), outSize));
    ASSERT_EQ(outSize, packet1.size());
    ASSERT_EQ(0, memcmp(out.data(), packet1.data(), outSize));

    ASSERT_TRUE(buffer.TryGetPacket(out.data(), outSize));
    ASSERT_EQ(outSize, packet2.size());
    ASSERT_EQ(0, memcmp(out.data(), packet2.data(), outSize));

    ASSERT_TRUE(buffer.TryGetPacket(out.data(), outSize));
    ASSERT_EQ(outSize, packet3.size());
    ASSERT_EQ(0, memcmp(out.data(), packet3.data(), outSize));
}

// Step 3: Test a scenario where writing a packet wraps around the buffer.
TEST_F(MutexRoundBufferTest, WraparoundWrite) {
    MutexRoundBuffer buffer(100);
    auto packet1 = createTestPacket(70, 1);
    auto packet2 = createTestPacket(50, 2); // This will wrap

    ASSERT_TRUE(buffer.EnqueuePacket(packet1.data()));

    uint32_t outSize = 0;
    std::vector<uint8_t> out(100);
    ASSERT_TRUE(buffer.TryGetPacket(out.data(), outSize)); // Make space
    ASSERT_EQ(outSize, packet1.size());

    ASSERT_TRUE(buffer.EnqueuePacket(packet2.data())); // Should now be at tail=70, needs to wrap

    ASSERT_TRUE(buffer.TryGetPacket(out.data(), outSize));
    ASSERT_EQ(outSize, packet2.size());
    ASSERT_EQ(0, memcmp(out.data(), packet2.data(), outSize));
}

// Step 3: Test a scenario where reading a packet wraps around the buffer.
TEST_F(MutexRoundBufferTest, WraparoundRead) {
    MutexRoundBuffer buffer(100);
    auto packet1 = createTestPacket(70, 1);
    auto packet2 = createTestPacket(50, 2);

    // Fill buffer to position tail at 70
    ASSERT_TRUE(buffer.EnqueuePacket(packet1.data()));
    std::vector<uint8_t> out(100);
    uint32_t outSize = 0;
    ASSERT_TRUE(buffer.TryGetPacket(out.data(), outSize));

    // Enqueue a packet that will wrap
    ASSERT_TRUE(buffer.EnqueuePacket(packet2.data())); // tail becomes (70+50)%100 = 20, head is 70

    // Now get the wrapped packet
    ASSERT_TRUE(buffer.TryGetPacket(out.data(), outSize));
    ASSERT_EQ(outSize, packet2.size());
    ASSERT_EQ(0, memcmp(out.data(), packet2.data(), outSize));
}

// Step 3: Test input validation cases.
TEST_F(MutexRoundBufferTest, InvalidInputs) {
    MutexRoundBuffer buffer(BUFFER_CAPACITY);

    // Enqueue nullptr
    ASSERT_FALSE(buffer.EnqueuePacket(nullptr));

    // TryGetPacket with nullptr
    uint32_t size = 0;
    ASSERT_FALSE(buffer.TryGetPacket(nullptr, size));

    // Packet larger than capacity
    auto largePacket = createTestPacket(BUFFER_CAPACITY + 1, 99);
    ASSERT_FALSE(buffer.EnqueuePacket(largePacket.data()));
}


// --- Multi-Threaded Tests ---

// Step 4: Test with a single producer and a single consumer.
TEST_F(MutexRoundBufferTest, SingleProducerSingleConsumer) {
    MutexRoundBuffer buffer(BUFFER_CAPACITY * 10);
    const int num_packets = 100;
    std::vector<std::vector<uint8_t>> sent_packets;
    std::vector<std::vector<uint8_t>> received_packets;

    std::thread producer([&]() {
        for (int i = 0; i < num_packets; ++i) {
            uint32_t size = (rand() % 100) + sizeof(RequestResponseHeader);
            auto packet = createTestPacket(size, i % 256);
            sent_packets.push_back(packet);
            buffer.EnqueuePacket(packet.data());
        }
    });

    std::thread consumer([&]() {
        for (int i = 0; i < num_packets; ++i) {
            std::vector<uint8_t> out(BUFFER_CAPACITY);
            uint32_t outSize = 0;
            buffer.TryGetPacket(out.data(), outSize);
            out.resize(outSize);
            received_packets.push_back(out);
        }
    });

    producer.join();
    consumer.join();

    ASSERT_EQ(sent_packets.size(), num_packets);
    ASSERT_EQ(received_packets.size(), num_packets);
    ASSERT_EQ(sent_packets, received_packets);
}

// Step 4: Test with multiple producers and a single consumer.
TEST_F(MutexRoundBufferTest, MultipleProducersSingleConsumer) {
    MutexRoundBuffer buffer(BUFFER_CAPACITY * 10);
    const int num_producers = 4;
    const int packets_per_producer = 50;
    const int total_packets = num_producers * packets_per_producer;

    std::vector<std::thread> producers;
    for (int i = 0; i < num_producers; ++i) {
        producers.emplace_back([&, i]() {
            for (int j = 0; j < packets_per_producer; ++j) {
                uint32_t size = (rand() % 50) + sizeof(RequestResponseHeader);
                // Use producer index in type to identify origin
                auto packet = createTestPacket(size, i);
                buffer.EnqueuePacket(packet.data());
            }
        });
    }

    std::vector<std::vector<uint8_t>> received_packets;
    std::thread consumer([&]() {
        for (int i = 0; i < total_packets; ++i) {
            std::vector<uint8_t> out(BUFFER_CAPACITY);
            uint32_t outSize = 0;
            buffer.TryGetPacket(out.data(), outSize);
            out.resize(outSize);
            received_packets.push_back(out);
        }
    });

    for (auto& p : producers) {
        p.join();
    }
    consumer.join();

    ASSERT_EQ(received_packets.size(), total_packets);
    // Check that we received the correct number of packets from each producer
    std::map<uint8_t, int> packet_counts;
    for(const auto& packet : received_packets) {
        auto* header = reinterpret_cast<const RequestResponseHeader*>(packet.data());
        packet_counts[header->type()]++;
    }

    for(int i = 0; i < num_producers; ++i) {
        ASSERT_EQ(packet_counts[i], packets_per_producer);
    }
}