#pragma once
#pragma comment(lib,"ws2_32.lib")
#include "winsock2.h"
#include "ws2bth.h"
#include <strsafe.h>
#include <initguid.h>

#define DEVICE_ADDR //device address
#define ADDR_LEN 17
#define SUCCESS 1
#define ERROR 0

DEFINE_GUID(g_guidServiceClass, 0x00001101, 0x0000, 0x1000, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB);

class BluetoothServer
{
public:
	wchar_t g_szRemoteName[BTH_MAX_NAME_SIZE + 1] = { 0 };  // 1 extra for trailing NULL character
	wchar_t g_szRemoteAddr[ADDR_LEN + 1] = { 0 }; // 1 extra for trailing NULL character
	int  g_ulMaxCxnCycles = 1;

	LPCSADDR_INFO	lpCSAddrInfo = NULL;
	ULONG			ulRetCode = SUCCESS;
	WSAQUERYSET		wsaQuerySet = { 0 };
	HRESULT			res;
	size_t			cbInstanceNameSize = 0;
	wchar_t *		pszInstanceName = NULL;
	wchar_t			szThisComputerName[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD			dwLenComputerName = MAX_COMPUTERNAME_LENGTH + 1;

	WORD			version;
	WSADATA			wsaData;
	int				err;

	char* buffer;

	SOCKADDR_BTH	localBthAddr;
	SOCKADDR_BTH	remoteBthAddr;
	SOCKET			listenSock;
	SOCKET			clntSock;
public:
	BluetoothServer();
	~BluetoothServer();
	int bthConnection();
	int recvData(char*);

};


BluetoothServer::BluetoothServer()
{
	version = MAKEWORD(2, 2);
	err = WSAStartup(version, &wsaData);

	if (err != 0)
		std::cout << "WSAStartup Error\n" << std::endl;
	else {
		lpCSAddrInfo = (LPCSADDR_INFO)HeapAlloc(GetProcessHeap(),
			HEAP_ZERO_MEMORY,
			sizeof(CSADDR_INFO));

		if (NULL == lpCSAddrInfo) {
			std::cout << "!ERROR! | Unable to allocate memory for CSADDR_INFO" << std::endl;
			ulRetCode = ERROR;
		}

		if (!GetComputerName(szThisComputerName, &dwLenComputerName)) {
			std::cout << "=CRITICAL= | GetComputerName() call failed. WSAGetLastError=[%d]\n" << WSAGetLastError() << std::endl;
			ulRetCode = ERROR;
		}
	}

	if(ulRetCode == SUCCESS){

		listenSock = socket(AF_BTH, SOCK_STREAM, BTHPROTO_RFCOMM);
		if (listenSock == INVALID_SOCKET)
			std::cout << "socket Error\n" << std::endl;

		memset(&localBthAddr, 0x00, sizeof(localBthAddr));
		localBthAddr.addressFamily = AF_BTH;
		localBthAddr.port = BT_PORT_ANY;

	}
}


BluetoothServer::~BluetoothServer()
{
	if (INVALID_SOCKET != clntSock) {
		closesocket(clntSock);
		clntSock = INVALID_SOCKET;
	}

	if (INVALID_SOCKET != listenSock) {
		closesocket(listenSock);
		listenSock = INVALID_SOCKET;
	}

	if (NULL != lpCSAddrInfo) {
		HeapFree(GetProcessHeap(), 0, lpCSAddrInfo);
		lpCSAddrInfo = NULL;
	}
	if (NULL != pszInstanceName) {
		HeapFree(GetProcessHeap(), 0, pszInstanceName);
		pszInstanceName = NULL;
	}

	if (NULL != buffer) {
		HeapFree(GetProcessHeap(), 0, buffer);
		buffer = NULL;
	}
}

int BluetoothServer::bthConnection()
{
	int addrLen = sizeof(remoteBthAddr);

	if (bind(listenSock, (SOCKADDR*)&localBthAddr, sizeof(localBthAddr)) == SOCKET_ERROR) {
		std::cout << "WINSOCK: 'bind' Return Code: " << WSAGetLastError() << "\r\n";
		ulRetCode = ERROR;

		return ERROR;
	}

	int code = getsockname(listenSock,
		(SOCKADDR*)&localBthAddr,
		&addrLen);

	if (code == SOCKET_ERROR) {
		std::cout << "WINSOCK: 'bind2' Return Code: " << WSAGetLastError() << "\r\n";
		return ERROR;
	}

	lpCSAddrInfo[0].LocalAddr.iSockaddrLength = sizeof(SOCKADDR_BTH);
	lpCSAddrInfo[0].LocalAddr.lpSockaddr = (LPSOCKADDR)&localBthAddr;
	lpCSAddrInfo[0].RemoteAddr.iSockaddrLength = sizeof(SOCKADDR_BTH);
	lpCSAddrInfo[0].RemoteAddr.lpSockaddr = (LPSOCKADDR)&localBthAddr;
	lpCSAddrInfo[0].iSocketType = SOCK_STREAM;
	lpCSAddrInfo[0].iProtocol = BTHPROTO_RFCOMM;

	///advertising
	ZeroMemory(&wsaQuerySet, sizeof(WSAQUERYSET));
	wsaQuerySet.dwSize = sizeof(WSAQUERYSET);
	wsaQuerySet.lpServiceClassId = (LPGUID)&g_guidServiceClass;

	res = StringCchLength(szThisComputerName, sizeof(szThisComputerName), &cbInstanceNameSize);
	if (FAILED(res)) {
		std::cout << "-FATAL- | ComputerName specified is too large" << std::endl;

		return ERROR;
	}

	cbInstanceNameSize += ADDR_LEN + 1;
	pszInstanceName = (LPWSTR)HeapAlloc(GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		cbInstanceNameSize);

	if (NULL == pszInstanceName) {
		std::cout << "-FATAL- | HeapAlloc failed | out of memory | gle = [%d]" << GetLastError() << std::endl;;
		return ERROR;
	}

	StringCbPrintf(pszInstanceName, cbInstanceNameSize, L"%s %s", szThisComputerName, "Bluetooth Server");
	wsaQuerySet.lpszServiceInstanceName = pszInstanceName;
	wsaQuerySet.lpszComment = LPWSTR("Example Service instance registered in the directory service through RnR");
	wsaQuerySet.dwNameSpace = NS_BTH;
	wsaQuerySet.dwNumberOfCsAddrs = 1;      // Must be 1.
	wsaQuerySet.lpcsaBuffer = lpCSAddrInfo; // Req'd.

	if (SOCKET_ERROR == WSASetService(&wsaQuerySet, RNRSERVICE_REGISTER, 0)) {
		std::cout << "=CRITICAL= | WSASetService() call failed. WSAGetLastError=[%d]" << WSAGetLastError() << std::endl;
		return ERROR;
	}

	if (listen(listenSock, 1) == SOCKET_ERROR){
		std::cout <<"=CRITICAL= | listen() call failed w/socket = [0x%I64X]. WSAGetLastError=[%d]"<< (ULONG64)listenSock << WSAGetLastError() << std::endl;
		return ERROR;
	}

	
	clntSock = accept(listenSock, (SOCKADDR*)&remoteBthAddr, &addrLen);

	if (clntSock == INVALID_SOCKET) {
		std::cout << "=CRITICAL= | accept() call failed. WSAGetLastError=[%d]"<< WSAGetLastError() << std::endl;

		return ERROR;
	}

	else{
		std::cout << "accept success\n" << std::endl;
		return SUCCESS;
	}
}

int BluetoothServer::recvData(char* buf)
{
	return recv(clntSock, buf, sizeof(buf), 0);
}
