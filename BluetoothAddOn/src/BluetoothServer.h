#pragma once
#pragma comment(lib,"ws2_32.lib")
#include "nan.h"
#include "winsock2.h"
#include "ws2bth.h"
#include "strsafe.h"
#include "initguid.h"
#include "iostream"
#include "Windows.h"

#define DEVICE_ADDR 0x34415DEF5BAE
#define ADDR_LEN 17
#define SUCCESS 1
#define ERROR 0

DEFINE_GUID(g_guidServiceClass, 0x00001101, 0x0000, 0x1000, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB);

class BluetoothServer : public Nan::ObjectWrap
{
public:
	static wchar_t g_szRemoteName[BTH_MAX_NAME_SIZE + 1];  // 1 extra for trailing NULL character
	static wchar_t g_szRemoteAddr[ADDR_LEN + 1]; // 1 extra for trailing NULL character
	static int  g_ulMaxCxnCycles;

	static LPCSADDR_INFO	lpCSAddrInfo;
	static ULONG			ulRetCode;
	static WSAQUERYSET		wsaQuerySet;
	static HRESULT			res;
	static size_t			cbInstanceNameSize;
	static wchar_t *		pszInstanceName;
	static wchar_t			szThisComputerName[MAX_COMPUTERNAME_LENGTH + 1];
	static DWORD			dwLenComputerName;

	static WORD			version;
	static WSADATA			wsaData;
	static int				err;

	static char* buffer;

	static SOCKADDR_BTH	localBthAddr;
	static SOCKADDR_BTH	remoteBthAddr;
	static SOCKET			listenSock;
	static SOCKET			clntSock;
public:
	BluetoothServer();
	~BluetoothServer();
    static int bthConnection();
    static NAN_MODULE_INIT(Init);
    static NAN_METHOD(New);
	static NAN_METHOD(connection);
    
    static Nan::Persistent<v8::FunctionTemplate> constructor;

};

