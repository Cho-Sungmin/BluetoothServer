#include "BluetoothServer.h"

Nan::Persistent<v8::FunctionTemplate> BluetoothServer::constructor;


wchar_t         BluetoothServer::g_szRemoteName[BTH_MAX_NAME_SIZE + 1] = { 0 };  // 1 extra for trailing NULL character
wchar_t         BluetoothServer::g_szRemoteAddr[ADDR_LEN + 1] = { 0 }; // 1 extra for trailing NULL character
int             BluetoothServer::g_ulMaxCxnCycles = 1;

LPCSADDR_INFO	BluetoothServer::lpCSAddrInfo = NULL;
ULONG			BluetoothServer::ulRetCode = SUCCESS;
WSAQUERYSET		BluetoothServer::wsaQuerySet = { 0 };
HRESULT			BluetoothServer::res;
size_t			BluetoothServer::cbInstanceNameSize = 0;
wchar_t *		BluetoothServer::pszInstanceName = NULL;
wchar_t			BluetoothServer::szThisComputerName[MAX_COMPUTERNAME_LENGTH + 1];
DWORD			BluetoothServer::dwLenComputerName = MAX_COMPUTERNAME_LENGTH + 1;

WORD			BluetoothServer::version;
WSADATA			BluetoothServer::wsaData;
int				BluetoothServer::err;

char*           BluetoothServer::buffer;

SOCKADDR_BTH	BluetoothServer::localBthAddr;
SOCKADDR_BTH	BluetoothServer::remoteBthAddr;
SOCKET			BluetoothServer::listenSock;
SOCKET			BluetoothServer::clntSock;

NAN_MODULE_INIT(BluetoothServer::Init) {
  v8::Local<v8::FunctionTemplate> ctor = Nan::New<v8::FunctionTemplate>(BluetoothServer::New);
  constructor.Reset(ctor);
  ctor->InstanceTemplate()->SetInternalFieldCount(1);
  ctor->SetClassName(Nan::New("BluetoothServer").ToLocalChecked());

  // link our getters and setter to the object property

  Nan::SetPrototypeMethod(ctor, "Connection", connection);

  target->Set(Nan::New("BluetoothServer").ToLocalChecked(), ctor->GetFunction());
}

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

		if (!GetComputerName((LPSTR)szThisComputerName, &dwLenComputerName)) {
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

	res = StringCchLength((STRSAFE_PCNZCH)szThisComputerName, sizeof(szThisComputerName), &cbInstanceNameSize);
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

	StringCbPrintf((STRSAFE_LPSTR)pszInstanceName, cbInstanceNameSize, "%s %s", szThisComputerName, "Bluetooth Server");
	wsaQuerySet.lpszServiceInstanceName = (LPSTR)pszInstanceName;
	wsaQuerySet.lpszComment = "Example Service instance registered in the directory service through RnR";
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

NAN_METHOD(BluetoothServer::New) {
  // throw an error if constructor is called without new keyword
  if(!info.IsConstructCall()) {
    return Nan::ThrowError(Nan::New("BluetoothServer::New - called without new keyword").ToLocalChecked());
  }
    BluetoothServer* bluetoothServer = new BluetoothServer();
    bluetoothServer->Wrap(info.Holder());
    
    info.GetReturnValue().Set(info.Holder());
}

NAN_METHOD(BluetoothServer::connection){
    int result = bthConnection();
    
    info.GetReturnValue().Set(result);
}