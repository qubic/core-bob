#pragma once

#include <iomanip>
#include <ios>
#include <random>

static void byteToHex(const uint8_t* byte, char* hex, const int sizeInByte)
{
    for (int i = 0; i < sizeInByte; i++){
        sprintf(hex+i*2, "%02x", byte[i]);
    }
}
static std::string byteToHexStr(const uint8_t* byte, const int sizeInByte)
{
    std::string result;
    result.resize(sizeInByte*2);
    byteToHex(byte, result.data(), sizeInByte);
    return result;
}
static void hexToByte(const char* hex, uint8_t* byte, const int sizeInByte)
{
    for (int i = 0; i < sizeInByte; i++){
        sscanf(hex+i*2, "%2hhx", &byte[i]);
    }
}

static void rand32(uint32_t* r) {
    std::random_device rd;
    static thread_local std::mt19937 generator(rd());
    std::uniform_int_distribution<uint32_t> distribution(0,UINT32_MAX);
    *r = distribution(generator);
}

static void rand64(uint64_t* r) {
    static thread_local std::mt19937 generator;
    std::uniform_int_distribution<uint64_t> distribution(0,UINT32_MAX);
    *r = distribution(generator);
}

static bool isArrayZero(uint8_t *ptr, int len) {
    for (int i = 0; i < len; i++) {
        if (ptr[i] != 0) {
            return false;
        }
    }
    return true;
}

// Helper to convert byte array to hex string
static std::string bytes_to_hex_string(const unsigned char* bytes, size_t size) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(bytes[i]);
    }
    return ss.str();
}