# ifndef _WININTERNAL_H_
#define _WININTERNAL_H_

#include "stdafx.h"
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

typedef struct _STRING
{
    WORD Length;
    WORD MaximumLength;
    CHAR* Buffer;
} STRING, * PSTRING;

typedef struct _UNICODE_STRING {
    WORD Length;
    WORD MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

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
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION, ** PPSYSTEM_HANDLE_INFORMATION;

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


typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation = 0
}PROCESSINFOCLASS;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    STRING DosPath;
}RTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID ConsoleHandle;
    ULONG ConsoleFlags;
    PVOID StdInputHandle;
    PVOID StdOutputHandle;
    PVOID StdErrorHandle;
    UNICODE_STRING CurrentDirectoryPath;
    PVOID CurrentDirectoryHandle;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingPositionLeft;
    ULONG StartingPositionTop;
    ULONG Width;
    ULONG Height;
    ULONG CharWidth;
    ULONG CharHeight;
    ULONG ConsoleTextAttributes;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopName;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[32];
    ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef VOID (NTAPI* PPS_POST_PROCESS_INIT_ROUTINE) (VOID);

typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    PVOID                         Reserved4[3];
    PVOID                         AtlThunkSListPtr;
    PVOID                         Reserved5;
    ULONG                         Reserved6;
    PVOID                         Reserved7;
    ULONG                         Reserved8;
    ULONG                         AtlThunkSListPtr32;
    PVOID                         Reserved9[45];
    BYTE                          Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE                          Reserved11[128];
    PVOID                         Reserved12[1];
    ULONG                         SessionId;
} PEB, * PPEB;

typedef LONG KPRIORITY;

typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS NtExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
}PROCESS_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI* NtQueryInformationProcessPtr)(
    HANDLE hProcess,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID pProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef enum _EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

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

#endif