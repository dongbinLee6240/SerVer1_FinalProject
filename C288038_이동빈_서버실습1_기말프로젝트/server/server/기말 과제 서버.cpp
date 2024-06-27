#pragma comment(lib, "ws2_32")
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <WinSock2.h>
#include <stdlib.h>
#include <iostream>
#include <tchar.h>
#include <string>
#include <Windows.h>
#include <ctime>
#include <vector>

using namespace std;
#define BUFFERSIZE 512
#define PORT 9000

void printCurrentDateTime(char* time)
{
    // 현재 시간을 가져옴
    std::time_t t = std::time(nullptr);
    std::tm* now = std::localtime(&t);

    // 원하는 형식으로 시간 출력
    char buffer[100];
    std::strftime(buffer, sizeof(buffer), "%Y년도 %m월 %d일 %H시 %M분 %S초", now);
    strcpy(time, buffer);
}

class Packet
{
public:
    short length;
    const char* header;
    const char* data;
    short end;

    Packet() : length(0), header(nullptr), data(nullptr), end(0)
    {
    }
    ~Packet()
    {
    }

    void ack_con(Packet* packet, const string& str, char* buffer);

    void ack_move(Packet* packet, const string& str, char* buffer);

    void ack_chat_string(Packet* packet, const string& str, char* buffer);

    void ack_close(Packet* packet, const string& str, char* buffer);

};

void Packet::ack_con(Packet* packet, const string& str, char* buffer)
{
    packet->header = "ack_con";
    packet->data = str.c_str();
    packet->end = 0xff;
    packet->length = sizeof(packet->length) + strlen(packet->header) + strlen(packet->data) + sizeof(packet->end);

    int offset = 0;
    memcpy(buffer + offset, &packet->length, sizeof(packet->length));
    offset += sizeof(packet->length);
    memcpy(buffer + offset, packet->header, strlen(packet->header) + 1);
    offset += strlen(packet->header) + 1;
    memcpy(buffer + offset, packet->data, strlen(packet->data) + 1);
    offset += strlen(packet->data) + 1;
    memcpy(buffer + offset, &packet->end, sizeof(packet->end));
}

void Packet::ack_move(Packet* packet, const string& str, char* buffer)
{
    packet->header = "ack_move";
    packet->data = str.c_str();
    packet->end = 0xff;
    packet->length = sizeof(packet->length) + strlen(packet->header) + strlen(packet->data) + sizeof(packet->end);

    int offset = 0;
    memcpy(buffer + offset, &packet->length, sizeof(packet->length));
    offset += sizeof(packet->length);
    memcpy(buffer + offset, packet->header, strlen(packet->header) + 1);
    offset += strlen(packet->header) + 1;
    memcpy(buffer + offset, packet->data, strlen(packet->data) + 1);
    offset += strlen(packet->data) + 1;
    memcpy(buffer + offset, &packet->end, sizeof(packet->end));
}

void Packet::ack_chat_string(Packet* packet, const string& str, char* buffer)
{
    packet->header = "ack_chat_string";
    packet->data = str.c_str();
    packet->end = 0xff;
    packet->length = sizeof(packet->length) + strlen(packet->header) + strlen(packet->data) + sizeof(packet->end);

    int offset = 0;
    memcpy(buffer + offset, &packet->length, sizeof(packet->length));
    offset += sizeof(packet->length);
    memcpy(buffer + offset, packet->header, strlen(packet->header) + 1);
    offset += strlen(packet->header) + 1;
    memcpy(buffer + offset, packet->data, strlen(packet->data) + 1);
    offset += strlen(packet->data) + 1;
    memcpy(buffer + offset, &packet->end, sizeof(packet->end));
}

void Packet::ack_close(Packet* packet, const string& str, char* buffer)
{
    packet->header = "ack_close";
    packet->data = str.c_str();
    packet->end = 0xff;
    packet->length = sizeof(packet->length) + strlen(packet->header) + strlen(packet->data) + sizeof(packet->end);

    int offset = 0;
    memcpy(buffer + offset, &packet->length, sizeof(packet->length));
    offset += sizeof(packet->length);
    memcpy(buffer + offset, packet->header, strlen(packet->header) + 1);
    offset += strlen(packet->header) + 1;
    memcpy(buffer + offset, packet->data, strlen(packet->data) + 1);
    offset += strlen(packet->data) + 1;
    memcpy(buffer + offset, &packet->end, sizeof(packet->end));
}

class ServerAgent
{
private:
    // For Socket
    USHORT SERVERPORT;
    WSADATA Wsadata;        // Initiate WinSock
    SOCKET Listen_Socket;
    SOCKADDR_IN ServerAddress;

    // Variable for Data Communication
    SOCKET clientSocket;
    SOCKADDR_IN clientAddress;
    INT AddressLen;
    TCHAR Buffer[BUFFERSIZE + 1];
    HANDLE hSemaphore;
    vector<pair<SOCKET, SOCKADDR_IN>> clientList;

public:
    ServerAgent();
    ~ServerAgent();
    VOID error_Quit(const TCHAR* Msg);
    VOID error_Display(const TCHAR* Msg);
    VOID setReadyState();
    VOID communicate();
    static DWORD WINAPI ClientThread(LPVOID lpParam);
    static DWORD WINAPI Socketack_con(LPVOID lpParam);
    static DWORD WINAPI Socketack_move(LPVOID lpParam, char x, char y, char z);
    static DWORD WINAPI Socketack_chat_string(LPVOID lpParam);
    static DWORD WINAPI Socketack_close(LPVOID lpParam);
    VOID handleClient(SOCKET clientSocket);
    Packet deserializePacket(const char* buffer);
    void displayPacket(const Packet& packet);
    void extractCoordinates(const char* data, char& x, char& y, char& z);
};

ServerAgent::ServerAgent()
{
    SERVERPORT = PORT;
    hSemaphore = CreateSemaphore(NULL, 3, 3, NULL);  // Create semaphore with max count of 3
    if (WSAStartup(MAKEWORD(2, 2), &Wsadata) != 0)
        return;
}

ServerAgent::~ServerAgent()
{
    // CloseSocket()
    closesocket(Listen_Socket);
    // Winsock Quit
    WSACleanup();
    CloseHandle(hSemaphore);
}

// Displaying Socket Error
VOID ServerAgent::error_Quit(const char* Msg)
{
    LPVOID lpMsgBuf;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, WSAGetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), (LPTSTR)&lpMsgBuf, 0, NULL);
    MessageBox(NULL, (LPCTSTR)lpMsgBuf, Msg, MB_ICONERROR);
    LocalFree(lpMsgBuf);
    exit(1);

}

// Displaying Socket Function Error
VOID ServerAgent::error_Display(const char* Msg)
{
    LPVOID lpMsgBuf;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, WSAGetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);
    std::wcout << "[" << Msg << "]" << (TCHAR*)lpMsgBuf;
    LocalFree(lpMsgBuf);
}

VOID ServerAgent::setReadyState()
{
    INT Retval;

    // Socket()
    Listen_Socket = socket(AF_INET, SOCK_STREAM, 0);
    if (Listen_Socket == INVALID_SOCKET)
        error_Quit(_T("Socket()"));

    // bind()
    ZeroMemory(&ServerAddress, sizeof(SOCKADDR_IN));
    ServerAddress.sin_family = AF_INET;
    ServerAddress.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
    ServerAddress.sin_port = htons(SERVERPORT);
    Retval = bind(Listen_Socket, (SOCKADDR*)&ServerAddress, sizeof(ServerAddress));
    if (Retval == SOCKET_ERROR)
        error_Quit(_T("Bind()"));

    // listen()
    Retval = listen(Listen_Socket, SOMAXCONN);
    if (Retval == SOCKET_ERROR)
        error_Quit(_T("listen()"));
}

Packet ServerAgent::deserializePacket(const char* buffer)
{
    Packet packet;
    int offset = 0;
    memcpy(&packet.length, buffer + offset, sizeof(packet.length));
    offset += sizeof(packet.length);
    packet.header = buffer + offset;
    offset += strlen(packet.header) + 1;
    packet.data = buffer + offset;
    offset += strlen(packet.data) + 1;
    memcpy(&packet.end, buffer + offset, sizeof(packet.end));
    return packet;
}
void ServerAgent::extractCoordinates(const char* data, char& x, char& y, char& z)
{
    int len = strlen(data);
    x = data[len - 3];
    y = data[len - 2];
    z = data[len - 1];
}
void ServerAgent::displayPacket(const Packet& packet)
{
    std::wcout << _T("Length: ") << packet.length << _T(", Header: ") << packet.header
        << _T(", Data: ") << packet.data << _T(", End: ") << std::hex << packet.end << std::dec << std::endl;
}

VOID ServerAgent::communicate()
{
    while (true)
    {
        AddressLen = sizeof(clientAddress);
        clientSocket = accept(Listen_Socket, (SOCKADDR*)&clientAddress, &AddressLen);
        std::wcout << std::endl << inet_ntoa(clientAddress.sin_addr) << _T(", Client Connected : IP Address = ")
            << _T(", Port = ") << ntohs(clientAddress.sin_port) << std::endl;
        if (clientSocket == INVALID_SOCKET)
        {
            error_Display(_T("Accept"));
            continue;
        }

        clientList.push_back(make_pair(clientSocket, clientAddress));

        auto params = new pair<ServerAgent*, SOCKET>(this, clientSocket);
        HANDLE hThread = CreateThread(NULL, 0, &ServerAgent::ClientThread, params, 0, NULL);

        printf("스레드 생성\n");
        if (hThread == NULL)
        {
            error_Display(_T("CreateThread()"));
            CloseHandle(hThread);
        }
        else
            CloseHandle(hThread);
    }
}

DWORD WINAPI ServerAgent::ClientThread(LPVOID lpParam)
{
    // lpParam은 (ServerAgent*, SOCKET)의 쌍을 가리킵니다.
    auto params = reinterpret_cast<pair<ServerAgent*, SOCKET>*>(lpParam);
    ServerAgent* server = params->first;
    SOCKET clientSocket = params->second;

    server->handleClient(clientSocket);
    delete params; // 동적으로 할당된 메모리 해제
    return 0;
}

VOID ServerAgent::handleClient(SOCKET clientSocket)
{
    char buffer[BUFFERSIZE + 1];
    Packet packet;

    while (1)
    {
        ZeroMemory(buffer, sizeof(buffer));
        int retval = recv(clientSocket, buffer, BUFFERSIZE, 0);
        if (retval == SOCKET_ERROR)
        {
            error_Display(_T("recv()"));
            break;
        }
        else if (retval == 0)
            break;
        buffer[retval] = '\0';
        //역 직렬화
        packet = deserializePacket(buffer);
        //패킷 출력
        displayPacket(packet);
        //헤더값에 따른 send
        if (strcmp(packet.header, "req_con") == 0)
        {
            WaitForSingleObject(hSemaphore, INFINITE);
            Socketack_con(this);
            ReleaseSemaphore(hSemaphore, 1, NULL);
        }

        else if (strcmp(packet.header, "req_move") == 0)
        {
            char x, y, z;
            extractCoordinates(packet.data, x, y, z);
            WaitForSingleObject(hSemaphore, INFINITE);
            Socketack_move(this, x, y, z);
            ReleaseSemaphore(hSemaphore, 1, NULL);
        }

        else if (strcmp(packet.header, "req_chat_string") == 0)
        {
            WaitForSingleObject(hSemaphore, INFINITE);
            Socketack_chat_string(this);
            ReleaseSemaphore(hSemaphore, 1, NULL);
        }
        else if (strcmp(packet.header, "req_close") == 0)
        {
            // Handle req_close
            WaitForSingleObject(hSemaphore, INFINITE);
            Socketack_close(this);
            ReleaseSemaphore(hSemaphore, 1, NULL);

        }

    }
    for (auto it = clientList.begin(); it != clientList.end(); it++)
    {
        if (it->first == clientSocket)
        {
            clientList.erase(it);
            break;
        }
    }

    closesocket(clientSocket);
}

DWORD WINAPI ServerAgent::Socketack_con(LPVOID lpParam)
{
    ServerAgent* This = (ServerAgent*)lpParam;
    INT retval;
    char buffer[BUFFERSIZE + 1];
    Packet packet;

    char timeBuffer[100];
    printCurrentDateTime(timeBuffer);
    for (auto& client : This->clientList)
    {
        SOCKET sock = client.first;
        int addressLen = sizeof(SOCKADDR_IN);
        SOCKADDR_IN threadSocketAddress;
        string ClientIp;

        getpeername(sock, (SOCKADDR*)&threadSocketAddress, &addressLen);
        ClientIp = inet_ntoa(threadSocketAddress.sin_addr);
        ClientIp = timeBuffer + ClientIp + ", connection completed";
        
        // ack_con 패킷 구성
        packet.ack_con(&packet, ClientIp, buffer);

        // 전송
        retval = send(sock, buffer, sizeof(buffer), 0);
        if (retval == SOCKET_ERROR)
        {
            This->error_Display("send()");
        }
    }

    return 1;
}

DWORD WINAPI ServerAgent::Socketack_move(LPVOID lpParam, char x, char y, char z)
{
    ServerAgent* This = (ServerAgent*)lpParam;
    INT retval;
    char buffer[BUFFERSIZE + 1];
    Packet packet;
    for (auto& client : This->clientList)
    {
        SOCKET sock = client.first;
        int addressLen = sizeof(SOCKADDR_IN);
        SOCKADDR_IN threadSocketAddress;
        string ClientIp;

        getpeername(sock, (SOCKADDR*)&threadSocketAddress, &addressLen);
        ClientIp = inet_ntoa(threadSocketAddress.sin_addr);

        string response = ClientIp + ", moved to ";
        response += x;
        response += " ";
        response += y;
        response += " ";
        response += z;

        // ack_move 패킷 구성
        packet.ack_move(&packet, response, buffer);

        // 전송
        retval = send(sock, buffer, sizeof(buffer), 0);
        if (retval == SOCKET_ERROR)
        {
            This->error_Display("send()");
        }
    }

    return 1;
}

DWORD WINAPI ServerAgent::Socketack_chat_string(LPVOID lpParam)
{
    ServerAgent* This = (ServerAgent*)lpParam;
    INT retval;
    char buffer[BUFFERSIZE + 1];
    Packet packet;
  
    for (auto& client : This->clientList)
    {
        SOCKET sock = client.first;
        int addressLen = sizeof(SOCKADDR_IN);
        SOCKADDR_IN threadSocketAddress;
        string ClientIp;

        getpeername(sock, (SOCKADDR*)&threadSocketAddress, &addressLen);
        ClientIp = inet_ntoa(threadSocketAddress.sin_addr);

        string response = "Received";

        // ack_chat_string 패킷 구성
        packet.ack_chat_string(&packet, response, buffer);

        // 전송
        retval = send(sock, buffer, sizeof(buffer), 0);
        if (retval == SOCKET_ERROR)
        {
            This->error_Display("send()");
        }
    }

    return 1;
}

DWORD WINAPI ServerAgent::Socketack_close(LPVOID lpParam)
{
    ServerAgent* This = (ServerAgent*)lpParam;
    INT retval;
    char buffer[BUFFERSIZE + 1];
    Packet packet;

    char timeBuffer[100];
    printCurrentDateTime(timeBuffer);

    for (auto& client : This->clientList)
    {
        SOCKET sock = client.first;
        int addressLen = sizeof(SOCKADDR_IN);
        SOCKADDR_IN threadSocketAddress;
        string ClientIp;

        getpeername(sock, (SOCKADDR*)&threadSocketAddress, &addressLen);
        ClientIp = inet_ntoa(threadSocketAddress.sin_addr);
        ClientIp = timeBuffer + ClientIp + " disconnected";

        // ack_close 패킷 구성
        packet.ack_close(&packet, ClientIp, buffer);

        // 전송
        retval = send(sock, buffer, sizeof(buffer), 0);
        if (retval == SOCKET_ERROR)
        {
            This->error_Display("send()");
        }
    }

    // 클라이언트 목록 비우기
    This->clientList.clear();
    return 1;
}

INT _tmain(INT argc, TCHAR* argv[])
{
    ServerAgent Server;
    SOCKADDR_IN threadSocketAddress;
    Server.setReadyState();
    Server.communicate();
    // std::wcout << _T("[TCP Server] Client Disconnected : IP Address=") << inet_ntoa(threadSocketAddress.sin_addr) << _T(" PORT = ") << ntohs(threadSocketAddress.sin_port) << std::endl;
    return 0;
}
