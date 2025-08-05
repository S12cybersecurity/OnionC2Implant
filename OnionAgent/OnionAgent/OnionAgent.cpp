#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>  

#pragma comment(lib, "ws2_32.lib")

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    char buffer[4096];
    std::string request;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed.\n";
        return 1;
    }

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed.\n";
        WSACleanup();
        return 1;
    }

    // Setup server struct
    server.sin_family = AF_INET;
    server.sin_port = htons(5000);

    // Set server IP address
    if (InetPton(AF_INET, L"192.168.1.144", &server.sin_addr) <= 0) {
        std::cerr << "Invalid IP address.\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // Connect to redirector
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        std::cerr << "Connection failed.\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // Send HTTP GET request
    request = "GET /getCommand HTTP/1.1\r\n";
    request += "Host: 192.168.1.144\r\n";
    request += "Connection: close\r\n\r\n";

    if (send(sock, request.c_str(), request.length(), 0) < 0) {
        std::cerr << "Send failed.\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // Receive and display response
    int bytesReceived;
    do {
        bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived > 0) {
            buffer[bytesReceived] = '\0';
            std::cout << buffer;
        }
    } while (bytesReceived > 0);

    // Cleanup
    closesocket(sock);
    WSACleanup();

    return 0;
}
