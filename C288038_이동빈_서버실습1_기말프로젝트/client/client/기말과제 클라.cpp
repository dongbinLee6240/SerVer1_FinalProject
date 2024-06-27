#define _WINSOCK_DEPRECATED_NO_WARNINGS // �ֽ� VC++ ������ �� ��� ����
#define _CRT_SECURE_NO_WARNINGS
#pragma comment(lib, "ws2_32")
#include <winsock2.h>
#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include <iostream>
#include <string>
#include <string.h>

using namespace std;
#define SERVERIP   "127.0.0.1"
#define SERVERIP_rec_con "127.0.0.1, request to move "
#define SERVERPORT 9000
#define BUFSIZE    512

class Packet
{
public:
    short length;
    const char* header;
    const char* data;
    short end;

    Packet() : length(0), header(nullptr), data(nullptr), end(0xff) {}
    ~Packet() {}

    void req_con(Packet* packet, char* buffer);
    void req_move(Packet* packet, char* x, char* y, char* z, char* buffer);
    void req_chat_string(Packet* packet, const string& str, char* buffer);
    void req_close(Packet* packet, const string& str, char* buffer);
};

void Packet::req_con(Packet* packet, char* buffer)
{
    packet->header = "req_con";
    packet->data = SERVERIP;
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

void Packet::req_move(Packet* packet, char* x, char* y, char* z, char* buffer)
{
    packet->header = "req_move";
    string data = string(1, *x) + string(1, *y) + string(1, *z); // x, y, z�� ���ڿ��� ����
    data = SERVERIP_rec_con + data;
    packet->data = data.c_str();
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

void Packet::req_chat_string(Packet* packet, const string& str, char* buffer)
{
    packet->header = "req_chat_string";
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

void Packet::req_close(Packet* packet, const string& str, char* buffer)
{
    packet->header = "req_close";
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

class ClientAgent
{
private:
    WSADATA Wsadata;
    SOCKET sock;
    SOCKADDR_IN serveraddr;
    SOCKADDR_IN clientAddress;
    INT AddressLen;
    TCHAR Buffer[BUFSIZE + 1];
    HANDLE hMutex;
public:
    ClientAgent();
    ~ClientAgent();
    VOID error_Quit(const TCHAR* Msg);
    VOID error_Display(const TCHAR* Msg);
    VOID setReadyState();
    VOID communicate();
    static DWORD WINAPI SocketReceiver(LPVOID lpParam);
    static DWORD WINAPI Socketreq_con(LPVOID lpParam);
    static DWORD WINAPI Socketreq_move(LPVOID lpParam);
    static DWORD WINAPI Socketreq_chat_string(LPVOID lpParam);
    static DWORD WINAPI Socketreq_close(LPVOID lpParam);
    Packet deserializePacket(const char* buffer);
    void displayPacket(const Packet& packet);
};

ClientAgent::ClientAgent()
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return;
    hMutex = CreateMutex(NULL, FALSE, NULL);
    if (hMutex == NULL)
        error_Quit(_T("CreateMutex"));
}

ClientAgent::~ClientAgent()
{
    closesocket(sock);
    CloseHandle(hMutex);
    WSACleanup();
}

// ���� �Լ� ���� ��� �� ����
VOID ClientAgent::error_Quit(const char* msg)
{
    LPVOID lpMsgBuf;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, WSAGetLastError(),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf, 0, NULL);
    MessageBox(NULL, (LPCTSTR)lpMsgBuf, msg, MB_ICONERROR);
    LocalFree(lpMsgBuf);
    exit(1);
}

// ���� �Լ� ���� ���
VOID ClientAgent::error_Display(const char* msg)
{
    LPVOID lpMsgBuf;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, WSAGetLastError(),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf, 0, NULL);
    printf("[%s] %s", msg, (char*)lpMsgBuf);
    LocalFree(lpMsgBuf);
}

VOID ClientAgent::setReadyState()
{
    INT retval;

    // socket()
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET)
        error_Quit(_T("socket()"));

    // connect()
    ZeroMemory(&serveraddr, sizeof(SOCKADDR_IN));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = inet_addr(SERVERIP);
    serveraddr.sin_port = htons(SERVERPORT);
    retval = connect(sock, (SOCKADDR*)&serveraddr, sizeof(serveraddr));
    if (retval == SOCKET_ERROR)
        error_Quit(_T("connect()"));
}

Packet ClientAgent::deserializePacket(const char* buffer)
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

void ClientAgent::displayPacket(const Packet& packet)
{
    std::wcout << _T("Length: ") << packet.length << _T(", Header: ") << packet.header
        << _T(", Data: ") << packet.data << _T(", End: ") << std::hex << packet.end << std::dec << std::endl;
}

VOID ClientAgent::communicate()
{
    HANDLE hThread[3];
    HANDLE hChatThread;
    hThread[0] = CreateThread(NULL, 0, Socketreq_con, this, 0, NULL);
    WaitForSingleObject(hThread[0], INFINITE);
    CloseHandle(hThread[0]);

    hThread[1] = CreateThread(NULL, 0, Socketreq_move, this, 0, NULL);
    WaitForSingleObject(hThread[1], INFINITE);
    CloseHandle(hThread[1]);

    // ���� ������ ����
    hThread[2] = CreateThread(NULL, 0, SocketReceiver, this, 0, NULL);

    while (true)
    {
        hChatThread = CreateThread(NULL, 0, Socketreq_chat_string, this, 0, NULL);
        WaitForSingleObject(hChatThread, INFINITE);
        CloseHandle(hChatThread);
    }
    // ���� ������ ���� ���
    WaitForSingleObject(hThread[2], INFINITE);
    CloseHandle(hThread[2]);
}

DWORD WINAPI ClientAgent::Socketreq_con(LPVOID lpParam)
{
    ClientAgent* This = (ClientAgent*)lpParam;
    SOCKET clsock = This->sock;
    INT retval;
    INT addressLen;
    SOCKADDR_IN threadSocketAddress;
    char buffer[BUFSIZE + 1];
    Packet packet;
    packet.req_con(&packet, buffer);

    WaitForSingleObject(This->hMutex, INFINITE);

    retval = send(clsock, buffer, packet.length, 0);
    if (retval == SOCKET_ERROR)
    {
        This->error_Display("send()");
    }

    retval = recv(clsock, buffer, BUFSIZE, 0);
    if (retval == SOCKET_ERROR)
    {
        This->error_Display("recv()");
    }

    Packet recvpacket = This->deserializePacket(buffer);
    This->displayPacket(recvpacket);

    ReleaseMutex(This->hMutex);
    return 1;
}

DWORD WINAPI ClientAgent::Socketreq_move(LPVOID lpParam)
{
    ClientAgent* This = (ClientAgent*)lpParam;
    SOCKET sock = This->sock;
    INT retval;
    INT addressLen;
    SOCKADDR_IN threadSocketAddress;
    char buffer[BUFSIZE + 1];

    char x;
    char y;
    char z;

    Packet packet;
    cout << "Enter ��ǥ: ";
    cin >> x >> y >> z;
    packet.req_move(&packet, &x, &y, &z, buffer);

    WaitForSingleObject(This->hMutex, INFINITE);

    retval = send(sock, buffer, packet.length, 0);
    if (retval == SOCKET_ERROR)
    {
        This->error_Display("send()");
    }

    retval = recv(sock, buffer, BUFSIZE, 0);
    if (retval == SOCKET_ERROR)
    {
        This->error_Display("recv()");
    }

    Packet recvpacket = This->deserializePacket(buffer);
    //���� �߰��� �ٸ� Ŭ���̾�Ʈ�� �����ؼ� req_con �Ǵ� req_move�� �� ���
    if (strcmp(recvpacket.header, "ack_con") == 0 || strcmp(recvpacket.header, "ack_move") == 0 || strcmp(recvpacket.header, "ack_close") == 0)
    {
        cout << "move ���" << endl;
        This->displayPacket(recvpacket);
    }

    ReleaseMutex(This->hMutex);

    return 1;
}

DWORD WINAPI ClientAgent::Socketreq_chat_string(LPVOID lpParam)
{
    ClientAgent* This = (ClientAgent*)lpParam;
    SOCKET sock = This->sock;
    INT retval;
    INT addressLen;
    SOCKADDR_IN threadSocketAddress;
    char buffer[BUFSIZE + 1];
    string str;
    Packet packet;

    cout << "������ ���� ����(exit�� ������ Ŭ���̾�Ʈ�� �����ϴ�): " << endl;
    cin >> str;
    if (str.empty())
    {
        closesocket(sock);
        return 0;
    }

    if (str == "exit") {
        This->Socketreq_close(lpParam);
    }

    packet.req_chat_string(&packet, str, buffer);

    WaitForSingleObject(This->hMutex, INFINITE);

    //send
    retval = send(sock, buffer, packet.length, 0);
    if (retval == SOCKET_ERROR)
    {
        This->error_Display("send()");
    }
    cout << "���� ���ڿ�: " << packet.data << endl;

    //�޴� ��Ŷ�� ������ �޴� ���� ����
    retval = recv(sock, buffer, BUFSIZE, 0);

    Packet recvpacket = This->deserializePacket(buffer);
    //���� �߰��� �ٸ� Ŭ���̾�Ʈ�� �����ؼ� req_con �Ǵ� req_move�� �� ���
    if (strcmp(recvpacket.header, "ack_con") == 0 || strcmp(recvpacket.header, "ack_move") == 0 || strcmp(recvpacket.header, "ack_close") == 0)
    {
        This->displayPacket(recvpacket);
    }

    ReleaseMutex(This->hMutex);

    return 1;
}

DWORD WINAPI ClientAgent::Socketreq_close(LPVOID lpParam)
{
    ClientAgent* This = (ClientAgent*)lpParam;
    SOCKET sock = This->sock;
    INT retval;
    INT addressLen;
    SOCKADDR_IN threadSocketAddress;
    char buffer[BUFSIZE + 1];
    string str;
    Packet packet;

    str = string(SERVERIP) + ", wanted to close";
    packet.req_close(&packet, str, buffer);

    WaitForSingleObject(This->hMutex, INFINITE);

    retval = send(sock, buffer, packet.length, 0);
    if (retval == SOCKET_ERROR)
    {
        This->error_Display("send()");
    }

    closesocket(sock);
    ReleaseMutex(This->hMutex);
    ExitProcess(0);
    return 0;
}

DWORD WINAPI ClientAgent::SocketReceiver(LPVOID lpParam)
{
    ClientAgent* This = (ClientAgent*)lpParam;
    SOCKET sock = This->sock;
    INT retval;
    char buffer[BUFSIZE + 1];

    while (true)
    {
        // ���� �ʱ�ȭ
        ZeroMemory(buffer, BUFSIZE + 1);

        retval = recv(sock, buffer, BUFSIZE, 0);
        if (retval == SOCKET_ERROR)
        {
            This->error_Display("recv()");
            return 1;
        }
        else if (retval == 0)
        {
            printf("Server closed connection\n");
            return 1;
        }
        // ��Ŷ ���ڵ� �� ����
        Packet recvpacket = This->deserializePacket(buffer);
        if (recvpacket.length != 204 && recvpacket.length>0)
        {
            This->displayPacket(recvpacket);
        }

    }
    return 0;
}

int main(int argc, char* argv[])
{
    ClientAgent client;
    client.setReadyState();
    client.communicate();

    return 0;
}
