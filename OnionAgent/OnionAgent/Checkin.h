#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <iostream>
#include <string>
#include <vector>
#include <winhttp.h>
#include <VersionHelpers.h>
#include "Utils.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "winhttp.lib")  

struct SystemInfo {
    std::wstring uuid;         // motherboard UUID
    std::wstring buildNumber;  // Windows build
    std::wstring machineGuid;  // registry
    std::vector<std::wstring> ips;  // Add type here

    std::wstring os;           // OS name (e.g. "Microsoft Windows 10 Pro")
    std::wstring user;         // current user
    std::wstring host;         // hostname
    std::wstring architecture; // "x64" / "x86"
    std::wstring domain;       // AD / DNS domain

    std::string hashedUUID;    // your reduced token
};

// Get all IP addresses (IPv4/IPv6) from all IP-enabled adapters.
std::vector<std::wstring> GetIpAddresses(IWbemServices* pSvc) {
    std::vector<std::wstring> ips;
    if (!pSvc) return ips;

    HRESULT hr;
    IEnumWbemClassObject* pEnumerator = nullptr;

    hr = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnumerator
    );

    if (FAILED(hr) || !pEnumerator) {
        return ips;
    }

    IWbemClassObject* pObj = nullptr;
    ULONG uReturn = 0;

    while (SUCCEEDED(pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &uReturn)) && uReturn == 1) {
        VARIANT vtProp;
        VariantInit(&vtProp);

        hr = pObj->Get(L"IPAddress", 0, &vtProp, nullptr, nullptr);
        if (SUCCEEDED(hr) && (vtProp.vt & VT_ARRAY) && (vtProp.vt & VT_BSTR) && vtProp.parray != nullptr) {
            SAFEARRAY* psa = vtProp.parray;
            LONG lBound = 0, uBound = -1;
            if (SUCCEEDED(SafeArrayGetLBound(psa, 1, &lBound)) &&
                SUCCEEDED(SafeArrayGetUBound(psa, 1, &uBound))) {

                for (LONG i = lBound; i <= uBound; ++i) {
                    BSTR bstrIp;
                    if (SUCCEEDED(SafeArrayGetElement(psa, &i, &bstrIp))) {
                        if (bstrIp) {
                            ips.emplace_back(bstrIp);
                            SysFreeString(bstrIp);
                        }
                    }
                }
            }
        }

        VariantClear(&vtProp);
        pObj->Release();
    }

    pEnumerator->Release();
    return ips;
}

std::wstring GetWmiStringProperty(
    IWbemServices* pSvc,
    const wchar_t* wqlQuery,
    const wchar_t* propertyName
) {
    if (!pSvc) return L"";

    HRESULT hr;
    IEnumWbemClassObject* pEnumerator = nullptr;

    hr = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(wqlQuery),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnumerator
    );

    if (FAILED(hr) || !pEnumerator) {
        return L"";
    }

    IWbemClassObject* pObj = nullptr;
    ULONG uReturn = 0;
    std::wstring result;

    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &uReturn);
    if (SUCCEEDED(hr) && uReturn == 1 && pObj) {
        VARIANT vtProp;
        VariantInit(&vtProp);

        hr = pObj->Get(propertyName, 0, &vtProp, nullptr, nullptr);
        if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR && vtProp.bstrVal != nullptr) {
            result = vtProp.bstrVal;
        }

        VariantClear(&vtProp);
        pObj->Release();
    }

    pEnumerator->Release();
    return result;
}

std::wstring GetMachineGuid() {
    HKEY hKey;
    if (RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Cryptography",
        0,
        KEY_READ | KEY_WOW64_64KEY,
        &hKey
    ) != ERROR_SUCCESS) {
        return L"";
    }

    wchar_t buf[256];
    DWORD bufSize = sizeof(buf);
    DWORD type = 0;

    LONG res = RegGetValueW(
        hKey,
        nullptr,
        L"MachineGuid",
        RRF_RT_REG_SZ,
        &type,
        buf,
        &bufSize
    );

    RegCloseKey(hKey);

    if (res != ERROR_SUCCESS) {
        return L"";
    }

    return std::wstring(buf);
}

std::wstring getOsName()
{
    if (IsWindows10OrGreater()) {
        return L"Windows 10 or later";
    }
    else if (IsWindows8Point1OrGreater()) {
        return L"Windows 8.1";
    }
    else if (IsWindows8OrGreater()) {
        return L"Windows 8";
    }
    else if (IsWindows7SP1OrGreater()) {
        return L"Windows 7 SP1";
    }
    else if (IsWindows7OrGreater()) {
        return L"Windows 7";
    }
    else if (IsWindowsVistaSP2OrGreater()) {
        return L"Windows Vista SP2";
    }
    else if (IsWindowsVistaSP1OrGreater()) {
        return L"Windows Vista SP1";
    }
    else if (IsWindowsVistaOrGreater()) {
        return L"Windows Vista";
    }
    else if (IsWindowsXPOrGreater()) {
        return L"Windows XP";
    }
    else {
        return L"Unknown Windows version";
    }
}

static bool is64bitOS()
{
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);

    WORD arch = si.wProcessorArchitecture;
    return arch == PROCESSOR_ARCHITECTURE_AMD64 ||
        arch == PROCESSOR_ARCHITECTURE_IA64 ||
        arch == PROCESSOR_ARCHITECTURE_ARM64;
}

std::wstring getArchitecture() {
    if (is64bitOS()) {
        return L"x64";
    }
    else {
        return L"x86";
    }
}

std::wstring GetDomain() {
    DWORD size = 0;
    GetComputerNameExW(ComputerNameDnsDomain, nullptr, &size);

    if (size == 0) {
        return L""; // not domain joined or error
    }

    std::wstring buffer(size, L'\0');
    if (!GetComputerNameExW(ComputerNameDnsDomain, &buffer[0], &size)) {
        return L"";
    }

    if (!buffer.empty() && buffer.back() == L'\0') {
        buffer.pop_back();
    }
    return buffer;
}

std::wstring GetHostName() {
    DWORD size = 0;
    GetComputerNameExW(ComputerNameDnsHostname, nullptr, &size);
    if (GetLastError() != ERROR_MORE_DATA || size == 0) {
        return L"";
    }

    std::wstring buffer(size, L'\0');
    if (!GetComputerNameExW(ComputerNameDnsHostname, &buffer[0], &size)) {
        return L"";
    }

    // buffer is null-terminated; trim trailing null if any
    if (!buffer.empty() && buffer.back() == L'\0') {
        buffer.pop_back();
    }
    return buffer;
}

std::wstring GetCurrentUser() {
    DWORD size = 0;

    BOOL ok = GetUserNameW(nullptr, &size);
    DWORD err = GetLastError();
    if (ok || err != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        return L"";
    }

    std::wstring buffer(size, L'\0');

    ok = GetUserNameW(&buffer[0], &size);
    if (!ok) {
        return L"";
    }

    if (!buffer.empty() && buffer.back() == L'\0') {
        buffer.pop_back();
    }
    return buffer;
}

void PrintSystemInfo(const SystemInfo& info) {
    std::cout << "Hashed UUID   : " << info.hashedUUID << std::endl;

    std::wcout << L"UUID          : " << (info.uuid.empty() ? L"" : info.uuid) << std::endl;
    std::wcout << L"Build Number  : " << (info.buildNumber.empty() ? L"" : info.buildNumber) << std::endl;
    std::wcout << L"OS            : " << (info.os.empty() ? L"" : info.os) << std::endl;
    std::wcout << L"Machine GUID  : " << (info.machineGuid.empty() ? L"" : info.machineGuid) << std::endl;
    std::wcout << L"User          : " << (info.user.empty() ? L"" : info.user) << std::endl;
    std::wcout << L"Host          : " << (info.host.empty() ? L"" : info.host) << std::endl;
    std::wcout << L"Architecture  : " << (info.architecture.empty() ? L"" : info.architecture) << std::endl;
    std::wcout << L"Domain        : " << (info.domain.empty() ? L"" : info.domain) << std::endl;

    // IPs (vector)
    std::wcout << L"IPs           : [";
    for (size_t i = 0; i < info.ips.size(); ++i) {
        if (i > 0) std::wcout << L", ";
        std::wcout << info.ips[i];
    }
    std::wcout << L"]" << std::endl;
}

bool GetSystemInfo(SystemInfo& info) {
    HRESULT hr;

    hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        std::wcerr << L"CoInitializeEx failed: 0x" << std::hex << hr << std::endl;
        return false;
    }

    hr = CoInitializeSecurity(
        nullptr,
        -1,
        nullptr,
        nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE,
        nullptr
    );

    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        std::wcerr << L"CoInitializeSecurity failed: 0x" << std::hex << hr << std::endl;
        CoUninitialize();
        return false;
    }

    IWbemLocator* pLoc = nullptr;
    hr = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)&pLoc
    );

    if (FAILED(hr) || !pLoc) {
        std::wcerr << L"CoCreateInstance(IWbemLocator) failed: 0x" << std::hex << hr << std::endl;
        CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        nullptr,
        nullptr,
        0,
        0,
        0,
        0,
        &pSvc
    );

    if (FAILED(hr) || !pSvc) {
        std::wcerr << L"ConnectServer failed: 0x" << std::hex << hr << std::endl;
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    hr = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE
    );

    if (FAILED(hr)) {
        std::wcerr << L"CoSetProxyBlanket failed: 0x" << std::hex << hr << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // --- WMI-based info ---
    info.uuid = GetWmiStringProperty(
        pSvc,
        L"SELECT UUID FROM Win32_ComputerSystemProduct",
        L"UUID"
    );

    info.buildNumber = GetWmiStringProperty(
        pSvc,
        L"SELECT BuildNumber FROM Win32_OperatingSystem",
        L"BuildNumber"
    );

    // OS friendly name (e.g., "Microsoft Windows 10 Pro")
    info.os = GetWmiStringProperty(
        pSvc,
        L"SELECT Caption FROM Win32_OperatingSystem",
        L"Caption"
    );

    // IPs via your helper
    info.ips = GetIpAddresses(pSvc);

    // --- Non-WMI info ---
    info.machineGuid = GetMachineGuid();
    info.user = GetCurrentUser();
    info.host = GetHostName();
    info.architecture = getArchitecture();
    info.domain = GetDomain();

    // Build the combined token and hash it
    std::wstring allInfo = info.uuid + L"-" + info.buildNumber + L"-" + info.machineGuid;
    std::string stringUUID(allInfo.begin(), allInfo.end());

    std::string key = "g5cX].v&3I:%oUw'";
    info.hashedUUID = HashToken_SHA256(stringUUID, key);
    PrintSystemInfo(info);

    // Cleanup
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return true;
}

bool SendRegisterRequest(const SystemInfo& info,
    const std::string& encryptionKey,
    const std::string& decryptionKey)
{
    // -------------------
    // 1. Construct JSON
    // -------------------
    std::string json;
    json += "{\n";
    json += "  \"uuid\": \"" + EscapeJson(info.hashedUUID) + "\",\n";

    json += "  \"ips\": [";
    for (size_t i = 0; i < info.ips.size(); ++i) {
        if (i > 0) json += ", ";
        json += "\"" + EscapeJson(Narrow(info.ips[i])) + "\"";
    }
    json += "],\n";

    json += "  \"os\": \"" + EscapeJson(Narrow(info.os)) + "\",\n";
    json += "  \"user\": \"" + EscapeJson(Narrow(info.user)) + "\",\n";
    json += "  \"host\": \"" + EscapeJson(Narrow(info.host)) + "\",\n";
    json += "  \"architecture\": \"" + EscapeJson(Narrow(info.architecture)) + "\",\n";
    json += "  \"domain\": \"" + EscapeJson(Narrow(info.domain)) + "\",\n";

    json += "  \"encryption_key\": \"" + EscapeJson(encryptionKey) + "\",\n";
    json += "  \"decryption_key\": \"" + EscapeJson(decryptionKey) + "\"\n";
    json += "}\n";

    // -------------------
    // 2. WinHTTP
    // -------------------
    bool result = false;
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;

    // Abrir sesión
    hSession = WinHttpOpen(L"SystemRegister/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) {
        std::wcerr << L"WinHttpOpen failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hSession);
    }

    hConnect = WinHttpConnect(hSession,
        L"192.168.1.144",
        5000,
        0);
    if (!hConnect) {
        std::wcerr << L"WinHttpConnect failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hSession);
    }

    // Crear petición POST /register
    hRequest = WinHttpOpenRequest(hConnect,
        L"POST",
        L"/register",
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    if (!hRequest) {
        std::wcerr << L"WinHttpOpenRequest failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
    }

    LPCWSTR headers = L"Content-Type: application/json\r\n";

    //DWORD dataSize = static_cast(json.size());
    DWORD dataSize = static_cast<DWORD>(json.size());

    if (!WinHttpSendRequest(hRequest,
        headers,
        -1L,
        (LPVOID)json.data(),
        dataSize,
        dataSize,
        0))
    {
        std::wcerr << L"WinHttpSendRequest failed: " << GetLastError() << std::endl;
        goto cleanup;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        std::wcerr << L"WinHttpReceiveResponse failed: " << GetLastError() << std::endl;
        goto cleanup;
    }

    // (Opcional) leer respuesta
    {
        DWORD dwSize = 0;
        do {
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                std::wcerr << L"WinHttpQueryDataAvailable failed: " << GetLastError() << std::endl;
                break;
            }

            if (dwSize == 0) break;

            std::vector<char> buffer(dwSize + 1, 0);  // Use char instead of unsigned char
            DWORD dwDownloaded = 0;
            if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
                std::wcerr << L"WinHttpReadData failed: " << GetLastError() << std::endl;
                break;
            }

            std::cout.write(buffer.data(), dwDownloaded);
        } while (dwSize > 0);

        std::cout << std::endl;
    }

    result = true;

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return result;
}