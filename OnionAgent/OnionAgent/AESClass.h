#ifndef AESCLASS_H
#define AESCLASS_H

#include <string>
#include <vector>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <cstdint>

class AES256Encryptor {
private:
    static constexpr int Nk = 8;  // Key size in 32-bit words (256-bit)
    static constexpr int Nr = 14; // Number of rounds
    static constexpr int Nb = 4;  // Block size in 32-bit words (128-bit)

    // Standard AES S-box
    static constexpr uint8_t Sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    // Inverse AES S-box
    static constexpr uint8_t InvSbox[256] = {
        0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
        0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
        0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
        0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
        0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
        0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
        0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
        0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
        0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
        0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
        0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
        0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
        0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
        0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
        0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
        0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
    };

    // Rcon table for key expansion
    static constexpr uint32_t Rcon[11] = {
        0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
    };

    uint32_t roundKey[4 * (Nr + 1)];

    static uint32_t SubWord(uint32_t word) {
        return (Sbox[(word >> 24) & 0xFF] << 24) |
            (Sbox[(word >> 16) & 0xFF] << 16) |
            (Sbox[(word >> 8) & 0xFF] << 8) |
            (Sbox[word & 0xFF]);
    }

    static uint32_t RotWord(uint32_t word) {
        return ((word << 8) | (word >> 24));
    }

    void KeyExpansion(const uint8_t* key) {
        uint32_t temp;
        for (int i = 0; i < Nk; i++) {
            roundKey[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) |
                (key[4 * i + 2] << 8) | key[4 * i + 3];
        }

        for (int i = Nk; i < 4 * (Nr + 1); i++) {
            temp = roundKey[i - 1];
            if (i % Nk == 0) {
                temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk];
            }
            else if (Nk > 6 && i % Nk == 4) {
                temp = SubWord(temp);
            }
            roundKey[i] = roundKey[i - Nk] ^ temp;
        }
    }

    static uint8_t GMul(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        for (int counter = 0; counter < 8; counter++) {
            if ((b & 1) == 1) p ^= a;
            uint8_t hi_bit_set = (a & 0x80);
            a <<= 1;
            if (hi_bit_set == 0x80) a ^= 0x1b;
            b >>= 1;
        }
        return p;
    }

    void SubBytes(uint8_t state[4][4]) {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] = Sbox[state[i][j]];
    }

    void InvSubBytes(uint8_t state[4][4]) {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] = InvSbox[state[i][j]];
    }

    void ShiftRows(uint8_t state[4][4]) {
        uint8_t temp;
        for (int i = 1; i < 4; i++) {
            for (int j = 0; j < i; j++) {
                temp = state[i][0];
                state[i][0] = state[i][1];
                state[i][1] = state[i][2];
                state[i][2] = state[i][3];
                state[i][3] = temp;
            }
        }
    }

    void InvShiftRows(uint8_t state[4][4]) {
        uint8_t temp;
        for (int i = 1; i < 4; i++) {
            for (int j = 0; j < i; j++) {
                temp = state[i][3];
                state[i][3] = state[i][2];
                state[i][2] = state[i][1];
                state[i][1] = state[i][0];
                state[i][0] = temp;
            }
        }
    }

    void MixColumns(uint8_t state[4][4]) {
        for (int i = 0; i < 4; i++) {
            uint8_t s0 = state[0][i], s1 = state[1][i], s2 = state[2][i], s3 = state[3][i];
            state[0][i] = GMul(0x02, s0) ^ GMul(0x03, s1) ^ s2 ^ s3;
            state[1][i] = s0 ^ GMul(0x02, s1) ^ GMul(0x03, s2) ^ s3;
            state[2][i] = s0 ^ s1 ^ GMul(0x02, s2) ^ GMul(0x03, s3);
            state[3][i] = GMul(0x03, s0) ^ s1 ^ s2 ^ GMul(0x02, s3);
        }
    }

    void InvMixColumns(uint8_t state[4][4]) {
        for (int i = 0; i < 4; i++) {
            uint8_t s0 = state[0][i], s1 = state[1][i], s2 = state[2][i], s3 = state[3][i];
            state[0][i] = GMul(0x0e, s0) ^ GMul(0x0b, s1) ^ GMul(0x0d, s2) ^ GMul(0x09, s3);
            state[1][i] = GMul(0x09, s0) ^ GMul(0x0e, s1) ^ GMul(0x0b, s2) ^ GMul(0x0d, s3);
            state[2][i] = GMul(0x0d, s0) ^ GMul(0x09, s1) ^ GMul(0x0e, s2) ^ GMul(0x0b, s3);
            state[3][i] = GMul(0x0b, s0) ^ GMul(0x0d, s1) ^ GMul(0x09, s2) ^ GMul(0x0e, s3);
        }
    }

    void AddRoundKey(uint8_t state[4][4], int round) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] ^= (roundKey[round * 4 + i] >> (24 - 8 * j)) & 0xFF;
            }
        }
    }

    void EncryptBlock(uint8_t state[4][4]) {
        AddRoundKey(state, 0);

        for (int round = 1; round < Nr; round++) {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, round);
        }

        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, Nr);
    }

    void DecryptBlock(uint8_t state[4][4]) {
        AddRoundKey(state, Nr);

        for (int round = Nr - 1; round >= 1; round--) {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, round);
            InvMixColumns(state);
        }

        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, 0);
    }

    static uint8_t HexToByte(char hi, char lo) {
        auto hexVal = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw std::runtime_error("Invalid hex character");
            };
        return (hexVal(hi) << 4) | hexVal(lo);
    }

public:
    AES256Encryptor(const std::string& keyStr) {
        uint8_t key[32];

        if (keyStr.length() < 32) {
            std::memset(key, 0, 32);
            std::memcpy(key, keyStr.c_str(), keyStr.length());
        }
        else if (keyStr.length() > 32) {
            std::memcpy(key, keyStr.c_str(), 32);
            for (size_t i = 32; i < keyStr.length(); i++) {
                key[i % 32] ^= static_cast(keyStr[i]);
            }
        }
        else {
            std::memcpy(key, keyStr.c_str(), 32);
        }

        KeyExpansion(key);
    }

    std::string encrypt(const std::string& plaintext) {
        std::vector data(plaintext.begin(), plaintext.end());

        // PKCS7 padding
        uint8_t padLen = 16 - (data.size() % 16);
        for (int i = 0; i < padLen; i++)
            data.push_back(padLen);

        std::vector ciphertext;

        for (size_t i = 0; i < data.size(); i += 16) {
            uint8_t state[4][4];
            // load column-major
            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {
                    state[j][k] = data[i + j + 4 * k];
                }
            }

            EncryptBlock(state);

            // store row-major (your original order)
            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {
                    ciphertext.push_back(state[j][k]);
                }
            }
        }

        // Convert to hex string
        std::stringstream ss;
        for (uint8_t byte : ciphertext)
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;

        return ss.str();
    }

    std::string decrypt(const std::string& hexCiphertext) {
        if (hexCiphertext.size() % 2 != 0)
            throw std::runtime_error("Ciphertext hex length must be even");

        std::vector data;
        data.reserve(hexCiphertext.size() / 2);

        for (size_t i = 0; i < hexCiphertext.size(); i += 2) {
            data.push_back(HexToByte(hexCiphertext[i], hexCiphertext[i + 1]));
        }

        if (data.size() % 16 != 0)
            throw std::runtime_error("Ciphertext length must be multiple of 16 bytes");

        std::vector plaintextBytes;
        plaintextBytes.reserve(data.size());

        for (size_t i = 0; i < data.size(); i += 16) {
            uint8_t state[4][4];

            // load row-major (matches your encrypt output)
            for (int row = 0; row < 4; row++) {
                for (int col = 0; col < 4; col++) {
                    state[row][col] = data[i + row * 4 + col];
                }
            }

            DecryptBlock(state);

            // store column-major (matches your encrypt input)
            for (int col = 0; col < 4; col++) {
                for (int row = 0; row < 4; row++) {
                    plaintextBytes.push_back(state[row][col]);
                }
            }
        }

        // PKCS7 unpadding
        if (plaintextBytes.empty())
            return "";

        uint8_t padLen = plaintextBytes.back();
        if (padLen == 0 || padLen > 16 || padLen > plaintextBytes.size())
            throw std::runtime_error("Invalid PKCS7 padding");

        for (size_t i = plaintextBytes.size() - padLen; i < plaintextBytes.size(); i++) {
            if (plaintextBytes[i] != padLen)
                throw std::runtime_error("Invalid PKCS7 padding");
        }
        plaintextBytes.resize(plaintextBytes.size() - padLen);

        return std::string(plaintextBytes.begin(), plaintextBytes.end());
    }
};

#endif // AESCLASS_H