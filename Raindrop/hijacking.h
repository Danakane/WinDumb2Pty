#ifndef _HIJACK_H_
#define _HIJACK_H_

#include "stdafx.h"

typedef list<HANDLE> HANDLE_LIST;
typedef list<SOCKET> SOCKET_LIST;

typedef LONG NTSTATUS;
typedef UCHAR BOOLEAN;           // winnt
typedef BOOLEAN* PBOOLEAN;       // winnt
typedef ULONG  ACCESS_MASK;

#define NTSTATUS_SUCCESS 0x00000000
#define NTSTATUS_PENDING 0x00000103
#define NTSTATUS_INFOLENGTHMISMATCH 0xc0000004
#define NTSTATUS_BUFFEROVERFLOW 0x80000005
#define NTSTATUS_BUFFERTOOSMALL 0xc0000023
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) == NTSTATUS_SUCCESS)


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemHandleInformation = 0X10,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE
{
    DWORD       dwProcessId;
    BYTE		bObjectType;
    BYTE		bFlags;
    WORD		wValue;
    PVOID       pAddress;
    DWORD GrantedAccess;
}SYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    DWORD         dwCount;
    SYSTEM_HANDLE handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION, **PPSYSTEM_HANDLE_INFORMATION;

typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {

    UNICODE_STRING TypeName;

    ULONG Reserved[22];    // reserved for internal use

} PUBLIC_OBJECT_TYPE_INFORMATION, * PPUBLIC_OBJECT_TYPE_INFORMATION;

typedef struct __PUBLIC_OBJECT_NAME_INFORMATION {

    UNICODE_STRING Name;

} PUBLIC_OBJECT_NAME_INFORMATION, * PPUBLIC_OBJECT_NAME_INFORMATION;

typedef NTSTATUS(WINAPI* NtQuerySystemInformationPtr)
(IN	SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT	PVOID					 SystemInformation,
    IN	ULONG					 SystemInformationLength,
    OUT	PULONG					 ReturnLength OPTIONAL);

typedef NTSTATUS(NTAPI* NtQueryObjectPtr)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength);


struct THREAD_PARAMS
{
    PSYSTEM_HANDLE_INFORMATION pSysHandleInformation;
    DWORD dwProcessId;
    HANDLE hStartEvent;
    HANDLE hFinishedEvent;
    bool bStatus;
};

struct SOCKET_BYTESIN
{
    SOCKET sock;
    UINT64 bytes_in;
};

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

struct SOCK_SHARED_INFO
{
    SOCKET_STATE state;
    INT AddressFamily;
    INT SocketType;
    INT Protocol;
    INT LocalAddressLength;
    INT RemoteAddressLength;

    // Socket options controlled by getsockopt(), setsockopt().
    linger LingerInfo;
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
    AFD_GROUP_TYPE GroupType;
    INT GroupPriority;
    // Last error set on this socket
    INT LastError;
    // Info stored for WSAAsyncSelect()
    HANDLE AsyncSelecthWnd;
    UINT AsyncSelectSerialNumber;
    UINT AsyncSelectwMsg;
    UINT AsyncSelectlEvent;
    UINT DisabledAsyncSelectEvents;
};

struct SOCKET_CONTEXT
{
    SOCK_SHARED_INFO SharedData;
    UINT SizeOfHelperData;
    UINT Padding;
    SOCKADDR LocalAddress;
    SOCKADDR RemoteAddress;
    // Helper Data - found out with some reversing
    BYTE HelperData[24];
};

typedef enum _EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;


typedef NTSTATUS(NTAPI* NtCreateEventPtr)(
    PHANDLE pEventHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES pObjectInformation,
    EVENT_TYPE EventType,
    BOOLEAN InitialState);

#define IOCTL_AFD_GET_CONTEXT 0x12043

typedef NTSTATUS(NTAPI* NtDeviceIoControlFilePtr)(
    HANDLE           FileHandle,
    HANDLE           Event,
    PVOID            ApcRoutine, // couldn't find the type definition
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG            IoControlCode,
    PVOID            InputBuffer,
    ULONG            InputBufferLength,
    PVOID            OutputBuffer,
    ULONG            OutputBufferLength
);


bool IsSocketHandle(HANDLE hHandle);

bool GetSocketTcpInfo(SOCKET hSock, TCP_INFO_v0** tcpInfoOut);

SOCKET_LIST FilterAndOrderSocketsByBytesIn(SOCKET_LIST& lstSocks);

SOCKET_LIST GetTargetProcessSockets(DWORD dwProcessId);

bool IsSocketOverlapped(SOCKET sock);

bool IsSocketInherited(SOCKET hSock, DWORD dwProcessId);

SOCKET DuplicateSocketFromHandle(HANDLE hHandle);

SOCKET_LIST DuplicateSocketsFromHandles(HANDLE_LIST& lstHandles);

DWORD WINAPI ThreadProc(LPVOID lParams);

SOCKET DuplicateTargetProcessSocket(DWORD dwProcessId, bool& bOverlappedSocket);

bool SetSocketBlockingMode(SOCKET hSock, int iMode);

#endif
