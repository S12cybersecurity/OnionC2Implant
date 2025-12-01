#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>  // For std::min


#pragma comment(lib, "bcrypt.lib")

std::string ToHex(const std::vector<unsigned char>& data, size_t maxBytes = 16) {  // Fixed: added <unsigned char>
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    size_t n = std::min(maxBytes, data.size());  // Use std::min instead of min
    for (size_t i = 0; i < n; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(data[i]);  // Added <unsigned int>
    }
    return oss.str();
}

std::string HashToken_SHA256(const std::string& token, const std::string& salt) {
    std::string input = token + salt;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        0
    );
    if (!BCRYPT_SUCCESS(status)) return {};

    DWORD hashObjectSize = 0, dataLen = 0;
    status = BCryptGetProperty(
        hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&hashObjectSize,
        sizeof(hashObjectSize),
        &dataLen,
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    std::vector<unsigned char> hashObject(hashObjectSize);  // Fixed: added <unsigned char>
    DWORD hashLen = 0;
    status = BCryptGetProperty(
        hAlg,
        BCRYPT_HASH_LENGTH,
        (PUCHAR)&hashLen,
        sizeof(hashLen),
        &dataLen,
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    std::vector<unsigned char> hash(hashLen);  // Fixed: added <unsigned char>

    status = BCryptCreateHash(
        hAlg,
        &hHash,
        hashObject.data(),
        hashObjectSize,
        nullptr,
        0,
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    status = BCryptHashData(
        hHash,
        (PUCHAR)input.data(),
        (ULONG)input.size(),
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    status = BCryptFinishHash(
        hHash,
        hash.data(),
        hashLen,
        0
    );
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) {
        return {};
    }

    return ToHex(hash, 16);
}

std::string Narrow(const std::wstring& ws) {
    return std::string(ws.begin(), ws.end());
}

std::string EscapeJson(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '\"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            out += c;
            break;
        }
    }
    return out;
}