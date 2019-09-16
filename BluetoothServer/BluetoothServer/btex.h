#pragma once
#pragma comment(lib,"ws2_32.lib")
#include "stdio.h"
#include "winsock2.h"
#include "ws2bth.h"
#include <strsafe.h>
#include <intsafe.h>
#include <initguid.h>

#define CXN_INSTANCE_STRING L"Sample Bluetooth Server"

DEFINE_GUID(g_guidServiceClass, 0x00001101, 0x0000, 0x1000, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB);

#define CXN_TEST_DATA_STRING              (L"~!@#$%^&*()-_=+?<>1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
#define CXN_TRANSFER_DATA_LENGTH          (sizeof(CXN_TEST_DATA_STRING))


#define CXN_BDADDR_STR_LEN                17   // 6 two-digit hex values plus 5 colons
#define CXN_MAX_INQUIRY_RETRY             3
#define CXN_DELAY_NEXT_INQUIRY            15
#define CXN_SUCCESS                       0
#define CXN_ERROR                         1
#define CXN_DEFAULT_LISTEN_BACKLOG        4

wchar_t g_szRemoteName[BTH_MAX_NAME_SIZE + 1] = { 0 };  // 1 extra for trailing NULL character
wchar_t g_szRemoteAddr[CXN_BDADDR_STR_LEN + 1] = { 0 }; // 1 extra for trailing NULL character
int  g_ulMaxCxnCycles = 1;


ULONG RunServerMode(_In_ int iMaxCxnCycles)
{
	ULONG           ulRetCode = CXN_SUCCESS;
	int             iAddrLen = sizeof(SOCKADDR_BTH);
	int             iCxnCount = 0;
	UINT            iLengthReceived = 0;
	UINT            uiTotalLengthReceived;
	size_t          cbInstanceNameSize = 0;
	char *          pszDataBuffer = NULL;
	char *          pszDataBufferIndex = NULL;
	wchar_t *       pszInstanceName = NULL;
	wchar_t         szThisComputerName[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD           dwLenComputerName = MAX_COMPUTERNAME_LENGTH + 1;
	SOCKET          LocalSocket = INVALID_SOCKET;
	SOCKET          ClientSocket = INVALID_SOCKET;
	WSAQUERYSET     wsaQuerySet = { 0 };
	SOCKADDR_BTH    SockAddrBthLocal = { 0 };
	LPCSADDR_INFO   lpCSAddrInfo = NULL;
	HRESULT         res;

	WORD version;
	WSADATA wsaData;
	int err;

	version = MAKEWORD(2, 2);
	err = WSAStartup(version, &wsaData);

	if (err != 0)
		//std::cout << "WSAStartup Error\n" << std::endl;

	//
	// This fixed-size allocation can be on the stack assuming the
	// total doesn't cause a stack overflow (depends on your compiler settings)
	// However, they are shown here as dynamic to allow for easier expansion
	//
		
	lpCSAddrInfo = (LPCSADDR_INFO)HeapAlloc(GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		sizeof(CSADDR_INFO));
	if (NULL == lpCSAddrInfo) {
		wprintf(L"!ERROR! | Unable to allocate memory for CSADDR_INFO\n");
		ulRetCode = CXN_ERROR;
	}

	if (CXN_SUCCESS == ulRetCode) {

		if (!GetComputerName(szThisComputerName, &dwLenComputerName)) {
			wprintf(L"=CRITICAL= | GetComputerName() call failed. WSAGetLastError=[%d]\n", WSAGetLastError());
			ulRetCode = CXN_ERROR;
		}
	}

	//
	// Open a bluetooth socket using RFCOMM protocol
	//
	if (CXN_SUCCESS == ulRetCode) {
		LocalSocket = socket(AF_BTH, SOCK_STREAM, BTHPROTO_RFCOMM);
		if (INVALID_SOCKET == LocalSocket) {
			wprintf(L"=CRITICAL= | socket() call failed. WSAGetLastError = [%d]\n", WSAGetLastError());
			ulRetCode = CXN_ERROR;
		}
	}

	if (CXN_SUCCESS == ulRetCode) {

		//
		// Setting address family to AF_BTH indicates winsock2 to use Bluetooth port
		//
		SockAddrBthLocal.addressFamily = AF_BTH;
		SockAddrBthLocal.port = BT_PORT_ANY;

		//
		// bind() associates a local address and port combination
		// with the socket just created. This is most useful when
		// the application is a server that has a well-known port
		// that clients know about in advance.
		//
		if (SOCKET_ERROR == bind(LocalSocket,
			(struct sockaddr *) &SockAddrBthLocal,
			sizeof(SOCKADDR_BTH))) {
			wprintf(L"=CRITICAL= | bind() call failed w/socket = [0x%I64X]. WSAGetLastError=[%d]\n", (ULONG64)LocalSocket, WSAGetLastError());
			ulRetCode = CXN_ERROR;
		}
	}

	if (CXN_SUCCESS == ulRetCode) {

		ulRetCode = getsockname(LocalSocket,
			(struct sockaddr *)&SockAddrBthLocal,
			&iAddrLen);
		if (SOCKET_ERROR == ulRetCode) {
			wprintf(L"=CRITICAL= | getsockname() call failed w/socket = [0x%I64X]. WSAGetLastError=[%d]\n", (ULONG64)LocalSocket, WSAGetLastError());
			ulRetCode = CXN_ERROR;
		}
	}

	if (CXN_SUCCESS == ulRetCode) {
		//
		// CSADDR_INFO
		//
		lpCSAddrInfo[0].LocalAddr.iSockaddrLength = sizeof(SOCKADDR_BTH);
		lpCSAddrInfo[0].LocalAddr.lpSockaddr = (LPSOCKADDR)&SockAddrBthLocal;
		lpCSAddrInfo[0].RemoteAddr.iSockaddrLength = sizeof(SOCKADDR_BTH);
		lpCSAddrInfo[0].RemoteAddr.lpSockaddr = (LPSOCKADDR)&SockAddrBthLocal;
		lpCSAddrInfo[0].iSocketType = SOCK_STREAM;
		lpCSAddrInfo[0].iProtocol = BTHPROTO_RFCOMM;

		//
		// If we got an address, go ahead and advertise it.
		//
		ZeroMemory(&wsaQuerySet, sizeof(WSAQUERYSET));
		wsaQuerySet.dwSize = sizeof(WSAQUERYSET);
		wsaQuerySet.lpServiceClassId = (LPGUID)&g_guidServiceClass;

		//
		// Adding a byte to the size to account for the space in the
		// format string in the swprintf call. This will have to change if converted
		// to UNICODE
		//
		res = StringCchLength(szThisComputerName, sizeof(szThisComputerName), &cbInstanceNameSize);
		if (FAILED(res)) {
			wprintf(L"-FATAL- | ComputerName specified is too large\n");
			ulRetCode = CXN_ERROR;
		}
	}

	if (CXN_SUCCESS == ulRetCode) {
		cbInstanceNameSize += sizeof(CXN_INSTANCE_STRING) + 1;
		pszInstanceName = (LPWSTR)HeapAlloc(GetProcessHeap(),
			HEAP_ZERO_MEMORY,
			cbInstanceNameSize);
		if (NULL == pszInstanceName) {
			wprintf(L"-FATAL- | HeapAlloc failed | out of memory | gle = [%d] \n", GetLastError());
			ulRetCode = CXN_ERROR;
		}
	}

	if (CXN_SUCCESS == ulRetCode) {
		StringCbPrintf(pszInstanceName, cbInstanceNameSize, L"%s %s", szThisComputerName, CXN_INSTANCE_STRING);
		wsaQuerySet.lpszServiceInstanceName = pszInstanceName;
		wsaQuerySet.lpszComment = LPWSTR("Example Service instance registered in the directory service through RnR");
		wsaQuerySet.dwNameSpace = NS_BTH;
		wsaQuerySet.dwNumberOfCsAddrs = 1;      // Must be 1.
		wsaQuerySet.lpcsaBuffer = lpCSAddrInfo; // Req'd.

		//
		// As long as we use a blocking accept(), we will have a race
		// between advertising the service and actually being ready to
		// accept connections.  If we use non-blocking accept, advertise
		// the service after accept has been called.
		//
		if (SOCKET_ERROR == WSASetService(&wsaQuerySet, RNRSERVICE_REGISTER, 0)) {
			wprintf(L"=CRITICAL= | WSASetService() call failed. WSAGetLastError=[%d]\n", WSAGetLastError());
			ulRetCode = CXN_ERROR;
		}
	}

	//
	// listen() call indicates winsock2 to listen on a given socket for any incoming connection.
	//
	if (CXN_SUCCESS == ulRetCode) {
		if (SOCKET_ERROR == listen(LocalSocket, CXN_DEFAULT_LISTEN_BACKLOG)) {
			wprintf(L"=CRITICAL= | listen() call failed w/socket = [0x%I64X]. WSAGetLastError=[%d]\n", (ULONG64)LocalSocket, WSAGetLastError());
			ulRetCode = CXN_ERROR;
		}
	}

	if (CXN_SUCCESS == ulRetCode) {

		for (iCxnCount = 0;
			(CXN_SUCCESS == ulRetCode) && ((iCxnCount < iMaxCxnCycles) || (iMaxCxnCycles == 0));
			iCxnCount++) {

			wprintf(L"\n");

			//
			// accept() call indicates winsock2 to wait for any
			// incoming connection request from a remote socket.
			// If there are already some connection requests on the queue,
			// then accept() extracts the first request and creates a new socket and
			// returns the handle to this newly created socket. This newly created
			// socket represents the actual connection that connects the two sockets.
			//
			ClientSocket = accept(LocalSocket, NULL, NULL);
			if (INVALID_SOCKET == ClientSocket) {
				wprintf(L"=CRITICAL= | accept() call failed. WSAGetLastError=[%d]\n", WSAGetLastError());
				ulRetCode = CXN_ERROR;
				break; // Break out of the for loop
			}

			//
			// Read data from the incoming stream
			//
			BOOL bContinue = TRUE;
			pszDataBuffer = (char *)HeapAlloc(GetProcessHeap(),
				HEAP_ZERO_MEMORY,
				CXN_TRANSFER_DATA_LENGTH);
			if (NULL == pszDataBuffer) {
				wprintf(L"-FATAL- | HeapAlloc failed | out of memory | gle = [%d] \n", GetLastError());
				ulRetCode = CXN_ERROR;
				break;
			}
			pszDataBufferIndex = pszDataBuffer;
			uiTotalLengthReceived = 0;
			while (bContinue && (uiTotalLengthReceived < CXN_TRANSFER_DATA_LENGTH)) {
				//
				// recv() call indicates winsock2 to receive data
				// of an expected length over a given connection.
				// recv() may not be able to get the entire length
				// of data at once.  In such case the return value,
				// which specifies the number of bytes received,
				// can be used to calculate how much more data is
				// pending and accordingly recv() can be called again.
				//
				iLengthReceived = recv(ClientSocket,
					(char *)pszDataBufferIndex,
					(CXN_TRANSFER_DATA_LENGTH - uiTotalLengthReceived),
					0);

				switch (iLengthReceived) {
				case 0: // socket connection has been closed gracefully
					bContinue = FALSE;
					break;

				case SOCKET_ERROR:
					wprintf(L"=CRITICAL= | recv() call failed. WSAGetLastError=[%d]\n", WSAGetLastError());
					bContinue = FALSE;
					ulRetCode = CXN_ERROR;
					break;

				default:

					//
					// Make sure we have enough room
					//
					if (iLengthReceived > (CXN_TRANSFER_DATA_LENGTH - uiTotalLengthReceived)) {
						wprintf(L"=CRITICAL= | received too much data\n");
						bContinue = FALSE;
						ulRetCode = CXN_ERROR;
						break;
					}

					pszDataBufferIndex += iLengthReceived;
					uiTotalLengthReceived += iLengthReceived;
					break;
				}
			}

			if (CXN_SUCCESS == ulRetCode) {

				if (CXN_TRANSFER_DATA_LENGTH != uiTotalLengthReceived) {
					wprintf(L"+WARNING+ | Data transfer aborted mid-stream. Expected Length = [%I64u], Actual Length = [%d]\n", (ULONG64)CXN_TRANSFER_DATA_LENGTH, uiTotalLengthReceived);
				}
				wprintf(L"*INFO* | Received following data string from remote device:\n%s\n", (wchar_t *)pszDataBuffer);

				//
				// Close the connection
				//
				if (SOCKET_ERROR == closesocket(ClientSocket)) {
					wprintf(L"=CRITICAL= | closesocket() call failed w/socket = [0x%I64X]. WSAGetLastError=[%d]\n", (ULONG64)LocalSocket, WSAGetLastError());
					ulRetCode = CXN_ERROR;
				}
				else {
					//
					// Make the connection invalid regardless
					//
					ClientSocket = INVALID_SOCKET;
				}
			}
		}
	}

	if (INVALID_SOCKET != ClientSocket) {
		closesocket(ClientSocket);
		ClientSocket = INVALID_SOCKET;
	}

	if (INVALID_SOCKET != LocalSocket) {
		closesocket(LocalSocket);
		LocalSocket = INVALID_SOCKET;
	}

	if (NULL != lpCSAddrInfo) {
		HeapFree(GetProcessHeap(), 0, lpCSAddrInfo);
		lpCSAddrInfo = NULL;
	}
	if (NULL != pszInstanceName) {
		HeapFree(GetProcessHeap(), 0, pszInstanceName);
		pszInstanceName = NULL;
	}

	if (NULL != pszDataBuffer) {
		HeapFree(GetProcessHeap(), 0, pszDataBuffer);
		pszDataBuffer = NULL;
	}

	return(ulRetCode);
}