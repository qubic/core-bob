#pragma once

#include "src/core/structs.h"
#include <chrono> // For timestamps
#include <climits>
#include <condition_variable>
#include <cstdint>
#include <cstring> // For memcpy
#include <iostream>
#include <map>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>
/**
 * @class MutexRoundBuffer
 * @brief A thread-safe circular buffer for storing and retrieving variable-length raw data packets.
 *
 * This class is designed for a single-producer, single-consumer scenario, but is safe
 * for multiple producers/consumers due to the use of a mutex. It uses a condition variable
 * to efficiently wait for space to become available (for producers) or for data to arrive

 * (for consumers), avoiding busy-waiting.
 */
class MutexRoundBuffer {
public:
    /**
     * @brief Constructs the circular buffer with a fixed total capacity.
     * @param capacity The maximum number of bytes the buffer can hold.
     */
    explicit MutexRoundBuffer(size_t capacity) :
            capacity_(capacity),
            size_(0),
            head_(0),
            tail_(0) {
        buffer_.resize(capacity);
    }

    // Disable copy and assignment to prevent ownership issues.
    MutexRoundBuffer(const MutexRoundBuffer&) = delete;
    MutexRoundBuffer& operator=(const MutexRoundBuffer&) = delete;

    /**
     * @brief Enqueues a complete packet into the buffer.
     *
     * This function is thread-safe. It will wait until enough space is available in the buffer.
     * @param ptr A pointer to the raw data of the packet. The packet must start with a valid RequestResponseHeader.
     * @return True if the packet was successfully enqueued, false if the packet is invalid (e.g., larger than buffer capacity).
     */
    bool EnqueuePacket(const uint8_t* ptr) {
        if (!ptr) {
            return false;
        }
        RequestResponseHeader _header;
        memcpy(&_header, ptr, sizeof(RequestResponseHeader));
        RequestResponseHeader* header = &_header;
        const uint32_t packet_size = header->size();

        if (packet_size > capacity_) {
            // Packet is too large to ever fit in the buffer.
            return false;
        }

        std::unique_lock<std::mutex> lock(mtx_);

        // Wait until there is enough space for the entire packet.
        // A loop is necessary to handle spurious wakeups.
        cv_not_full_.wait(lock, [this, packet_size] {
            return capacity_ - size_ >= packet_size;
        });
        // Write the packet data into the buffer, handling wraparound if necessary.
        if (tail_ + packet_size <= capacity_) {
            // The packet fits without wrapping around.
            memcpy(buffer_.data() + tail_, ptr, packet_size);
        } else {
            // The packet needs to wrap around the end of the buffer.
            size_t first_chunk_size = capacity_ - tail_;
            memcpy(buffer_.data() + tail_, ptr, first_chunk_size);
            memcpy(buffer_.data(), ptr + first_chunk_size, packet_size - first_chunk_size);
        }

        // Update tail pointer and current size.
        tail_ = (tail_ + packet_size) % capacity_;
        size_ += packet_size;

        // Notify one waiting consumer that a packet is ready.
        cv_not_empty_.notify_one();

        return true;
    }

    bool TryGetPacket(uint8_t *out_ptr, uint32_t &size) {
        if (!out_ptr) {
            return false;
        }

        std::unique_lock<std::mutex> lock(mtx_);

        // Check if there's at least enough data for a header
        if (size_ < sizeof(RequestResponseHeader)) {
            return false;
        }

        // Peek at the header to determine the full packet size
        RequestResponseHeader header;
        peek_data(reinterpret_cast<uint8_t *>(&header), sizeof(RequestResponseHeader));
        const uint32_t packet_size = header.size();
        // Check if the entire packet is available
        if (size_ < packet_size) {
            return false;
        }

        // The full packet is available, so we can copy it out
        if (head_ + packet_size <= capacity_) {
            // The packet can be read in a single contiguous block
            memcpy(out_ptr, buffer_.data() + head_, packet_size);
        } else {
            // The packet is wrapped around the buffer's end
            size_t first_chunk_size = capacity_ - head_;
            memcpy(out_ptr, buffer_.data() + head_, first_chunk_size);
            memcpy(out_ptr + first_chunk_size, buffer_.data(), packet_size - first_chunk_size);
        }

        // Update head pointer, current size, and the output size parameter
        head_ = (head_ + packet_size) % capacity_;
        size_ -= packet_size;
        size = packet_size;

        // Notify one waiting producer that space is now available
        cv_not_full_.notify_one();

        return true;
    }

    /**
     * @brief Returns a string containing the current buffer usage information.
     * @return String with buffer size, capacity, and usage percentage.
     */
    std::string GetBufferUsageString() {
        std::lock_guard<std::mutex> lock(mtx_);
        double usage_percent = (static_cast<double>(size_) / capacity_) * 100.0;
        return "Buffer Usage: " + std::to_string(size_) + "/" +
               std::to_string(capacity_) + " bytes (" +
               std::to_string(usage_percent) + "%)";
    }


private:
    /**
     * @brief Peeks at data from the head of the buffer without removing it.
     * Helper function to read the header before consuming the whole packet.
     * THIS FUNCTION IS NOT THREAD-SAFE and must be called within a locked context.
     */
    void peek_data(uint8_t* dest, size_t len) const {
        if (head_ + len <= capacity_) {
            memcpy(dest, buffer_.data() + head_, len);
        } else {
            size_t first_chunk = capacity_ - head_;
            memcpy(dest, buffer_.data() + head_, first_chunk);
            memcpy(dest + first_chunk, buffer_.data(), len - first_chunk);
        }
    }

    std::vector<uint8_t> buffer_;
    size_t capacity_;
    size_t size_; // Current number of bytes used
    size_t head_; // Read position
    size_t tail_; // Write position

    std::mutex mtx_;
    std::condition_variable cv_not_full_;
    std::condition_variable cv_not_empty_;
};