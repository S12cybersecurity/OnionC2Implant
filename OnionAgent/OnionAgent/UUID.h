// RegistryManager.h
#pragma once
#include <windows.h>
#include <string>

class RegistryManager
{
private:
    static constexpr const wchar_t* REG_PATH = L"Software\\Microsoft\\Windows";
    static constexpr const wchar_t* VALUE_NAME = L"uuid";

public:
    // Devuelve el UUID como std::wstring (recomendado en Windows)
    static bool ReadUUID(std::wstring& outUuid)
    {
        outUuid.clear();

        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_PATH, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
            return false;

        wchar_t buffer[128] = { 0 };
        DWORD bufferSize = sizeof(buffer);
        DWORD type = REG_SZ;

        LONG result = RegQueryValueExW(hKey, VALUE_NAME, nullptr, &type, (LPBYTE)buffer, &bufferSize);
        RegCloseKey(hKey);

        if (result == ERROR_SUCCESS && bufferSize > sizeof(wchar_t)) // al menos un carácter + null
        {
            outUuid = buffer;
            return true;
        }
        return false;
    }

    // Escribe el UUID (acepta wstring)
    static bool WriteUUID(const std::wstring& uuid)
    {
        HKEY hKey = nullptr;
        LONG result = RegCreateKeyExW(HKEY_CURRENT_USER, REG_PATH, 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
        if (result != ERROR_SUCCESS)
            return false;

        bool ok = (RegSetValueExW(hKey, VALUE_NAME, 0, REG_SZ,
            (const BYTE*)uuid.c_str(),
            (DWORD)((uuid.length() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS);

        RegCloseKey(hKey);
        return ok;
    }

    // Versión cómoda con std::string (conversión automática)
    static bool ReadUUID(std::string& outUuid)
    {
        std::wstring wUuid;
        if (ReadUUID(wUuid))
        {
            outUuid = std::string(wUuid.begin(), wUuid.end());
            return true;
        }
        return false;
    }

    static bool WriteUUID(const std::string& uuid)
    {
        return WriteUUID(std::wstring(uuid.begin(), uuid.end()));
    }
};