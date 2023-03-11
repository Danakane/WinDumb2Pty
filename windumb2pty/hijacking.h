#ifndef _HIJACK_H_
#define _HIJACK_H_

#include "stdafx.h"
#include "wininternal.h"

typedef struct _THREAD_PARAMS
{
    PSYSTEM_HANDLE_INFORMATION pSysHandleInformation;
    DWORD dwProcessId;
    HANDLE hStartEvent;
    HANDLE hFinishedEvent;
    bool bStatus;
} THREAD_PARAMS;

typedef struct _SOCKET_BYTESIN
{
    SOCKET sock;
    UINT64 bytes_in;
} SOCKET_BYTESIN;

enum SOCKET_STATE
{
    SocketOpen = 0,
    SocketBound = 1,
    SocketBoundUdp = 2,
    SocketConnected = 3,
    SocketClosed = 4
};

enum AFD_GROUP_TYPE
{
    GroupTypeNeither = 0,
    GroupTypeConstrained = SG_CONSTRAINED_GROUP,
    GroupTypeUnconstrained = SG_UNCONSTRAINED_GROUP
};


typedef struct _SOCK_SHARED_INFO
{
    enum SOCKET_STATE state;
    INT AddressFamily;
    INT SocketType;
    INT Protocol;
    INT LocalAddressLength;
    INT RemoteAddressLength;

    // Socket options controlled by getsockopt(), setsockopt().
    struct linger LingerInfo;
    UINT SendTimeout;
    UINT ReceiveTimeout;
    UINT ReceiveBufferSize;
    UINT SendBufferSize;
    /* Those are the bits in the SocketProerty, proper order:
        Listening;
        Broadcast;
        Debug;
        OobInline;
        ReuseAddresses;
        ExclusiveAddressUse;
        NonBlocking;
        DontUseWildcard;
        ReceiveShutdown;
        SendShutdown;
        ConditionalAccept;
    */
    USHORT SocketProperty;
    // Snapshot of several parameters passed into WSPSocket() when creating this socket
    UINT CreationFlags;
    UINT CatalogEntryId;
    UINT ServiceFlags1;
    UINT ProviderFlags;
    UINT GroupID;
    enum AFD_GROUP_TYPE GroupType;
    INT GroupPriority;
    // Last error set on this socket
    INT LastError;
    // Info stored for WSAAsyncSelect()
    HANDLE AsyncSelecthWnd;
    UINT AsyncSelectSerialNumber;
    UINT AsyncSelectwMsg;
    UINT AsyncSelectlEvent;
    UINT DisabledAsyncSelectEvents;
} SOCK_SHARED_INFO;

typedef struct _SOCKET_CONTEXT
{
    SOCK_SHARED_INFO SharedData;
    UINT SizeOfHelperData;
    UINT Padding;
    SOCKADDR LocalAddress;
    SOCKADDR RemoteAddress;
    // Helper Data - found out with some reversing
    BYTE HelperData[24];
} SOCKET_CONTEXT;


bool IsSocketHandle(HANDLE hHandle);

bool GetSocketTcpInfo(SOCKET hSock, TCP_INFO_v0** tcpInfoOut);

typedef struct _HANDLE_NODE
{
    HANDLE hHandle;
    struct _HANDLE_NODE* pNext;
} HANDLE_NODE;

typedef struct _HANDLE_LIST
{
    HANDLE_NODE* pHead;
    HANDLE_NODE* pTail;
    DWORD dwLength;
} HANDLE_LIST;

typedef struct _SOCKET_NODE
{
    SOCKET hSock;
    struct _SOCKET_NODE* pNext;
} SOCKET_NODE;

typedef struct _SOCKET_LIST
{
    SOCKET_NODE* pHead;
    SOCKET_NODE* pTail;
    DWORD dwLength;
} SOCKET_LIST;

int compare_sockets(const void* a, const void* b);

SOCKET_LIST* FilterAndOrderSocketsByBytesIn(SOCKET_LIST* pDupSocks);

SOCKET_LIST* GetTargetProcessSockets(DWORD dwProcessId);

bool IsSocketOverlapped(SOCKET sock);

SOCKET DuplicateSocketFromHandle(HANDLE hHandle);
SOCKET_LIST* DuplicateSocketsFromHandles(HANDLE_LIST* pHandles);

DWORD WINAPI ThreadProc(LPVOID lParams);

SOCKET DuplicateTargetProcessSocket(DWORD dwProcessId, bool* pOverlappedSocket);

bool SetSocketBlockingMode(SOCKET hSock, int iMode);

#endif
