#include "globals.h"
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
    // Unfortunately doesn't work as expected but still pretty cool
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

bool GetProcessCwd(HANDLE hReadPipe, HANDLE hWritePipe, CString& csCurrentWorkingDirectory)
{
    // This is really hackish and may not work if PeekNamedPipe doesn't read all the data
    // Unfortunately, there is no "non-blocking" IO on pipes like for sockets
    bool bRes = false;
    char cmd[] = "cmd /c cd\r";
    DWORD dwNbBytesWritten = 0;
    if (WriteFile(hWritePipe, cmd, (DWORD)strlen(cmd), &dwNbBytesWritten, NULL) != FALSE)
    {
        Sleep(200);
        BOOL bPeekSuccess = false;
        DWORD dwBytesAvailables = 0;
        bPeekSuccess = PeekNamedPipe(hReadPipe, NULL, 0, NULL, &dwBytesAvailables, NULL);
        if (bPeekSuccess && dwBytesAvailables > 0)
        {
            char* pBuffer = new char[dwBytesAvailables];
            ZeroMemory(pBuffer, dwBytesAvailables);
            DWORD dwTotalBytesRead = 0;
            DWORD dwBytesRead = 0;
            BOOL bReadSuccess = FALSE;
            do
            {
                dwBytesRead = 0;
                bReadSuccess = ReadFile(hReadPipe, pBuffer + dwTotalBytesRead, dwBytesAvailables - dwTotalBytesRead, &dwBytesRead, NULL);
                dwTotalBytesRead += dwBytesRead;
            } while (dwBytesRead != dwBytesAvailables && bReadSuccess != FALSE);
            if (bReadSuccess)
            {
                char* pStart = pBuffer;
                char* pEnd = NULL;
                const char crlf[] = "\r\n";
                do
                {
                    pEnd = strstr(pStart, crlf);
                    if (pEnd != NULL)
                    {
                        size_t length = pEnd - pStart;
                        CString csCandidate = CString(pStart, (int)length);
                        DWORD dwAttrib = GetFileAttributes(csCandidate);
                        if (dwAttrib != INVALID_FILE_ATTRIBUTES &&
                            (dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
                        {
                            csCurrentWorkingDirectory = csCandidate;
                            bRes = true;
                        }
                        else
                            pStart = pEnd + strlen(crlf);
                    }
                } while (pStart != NULL && pEnd != NULL && !bRes);
            }
            delete[] pBuffer;
        }
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
                WriteStdErr("ERROR: Could not set pseudoconsole thread attribute.\r\n");
            }
        }
        else
        {
            WriteStdErr("ERROR: Could not create process.\r\n");
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
            WriteStdErr("Could not create process.\r\n");
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

bool SendAll(SOCKET hSock, const char* pBuffer, DWORD dwLength) {
    
    DWORD dwTotalSent = 0;

    while (dwTotalSent < dwLength) {
        DWORD dwSent = send(hSock, pBuffer + dwTotalSent, dwLength - dwTotalSent, 0);
        if (dwSent == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK)
                break;
            else
                dwSent = 0;
        }
        dwTotalSent += dwSent;
    }

    return dwTotalSent == dwLength;
}


DWORD WINAPI ThreadReadPipeWriteSocket(LPVOID lpParams)
{
    CommunicationThreadParams* pThreadParams = (CommunicationThreadParams*)lpParams;
    HANDLE hPipe = pThreadParams->hOutPipe;
    SOCKET hSock = pThreadParams->hSock;
    HANDLE  hBlockWriteSockThread = pThreadParams->hBlockWriteSockThread;
    bool bOverlapped = pThreadParams->bOverlapped;
    bool bReadSuccess = false;
    bool bSendSuccess = 0;
    DWORD dwBytesRead = 0;
    char pBytesToWrite[BUFFER_SIZE_SOCKET];
    do
    {        
        ZeroMemory(pBytesToWrite, BUFFER_SIZE_SOCKET);
        WaitForSingleObject(hBlockWriteSockThread, INFINITE);
        bReadSuccess = ReadFile(hPipe, pBytesToWrite, BUFFER_SIZE_SOCKET, &dwBytesRead, NULL);
        if (bReadSuccess)
            bSendSuccess = SendAll(hSock, pBytesToWrite, (int)dwBytesRead);
    } while (bSendSuccess && bReadSuccess);
    return 0;
}

HANDLE StartThreadReadPipeWriteSocket(CommunicationThreadParams* pParams)
{
    HANDLE hThread = CreateThread(0, 0, ThreadReadPipeWriteSocket, pParams, 0, 0);
    return hThread;
}

bool ParseReceivedBytes(char* pBytesReceived, DWORD dwNbBytesReceived, char* pBytesToHold, DWORD* pNbBytesToHold, 
    char* pBytesToWrite, DWORD* pNbBytesToWrite, char* pSwitchModeControlCode, DWORD dwSwitchControlCodeSize, 
    char* pRemainingBytes, DWORD dwRemainingBufferSize, DWORD* pNbRemainingBytes)
{
    bool bSwitchMode = false;
    DWORD dwBytesToHold = *pNbBytesToHold;
    DWORD dwBytesToWrite = 0;
    for (DWORD i = 0; i < dwNbBytesReceived; ++i)
    {
        if (dwBytesToHold < dwSwitchControlCodeSize && pBytesReceived[i] == pSwitchModeControlCode[dwBytesToHold])
        {
            pBytesToHold[dwBytesToHold++] = pBytesReceived[i];
            if (dwBytesToHold == dwSwitchControlCodeSize)
            {
                bSwitchMode = true;
                ZeroMemory(pBytesToHold, BUFFER_SIZE_SOCKET);
                *pNbBytesToHold = 0;
                *pNbRemainingBytes = min(dwNbBytesReceived - (i + 1), dwRemainingBufferSize); // 0 if i == dwBytesReceived and dwBytesReceived - 1 if i = 0
                if (*pNbRemainingBytes > 0)
                {
                    // copy the remaining bytes of the receiving buffer: they are going to be returned.
                    ZeroMemory(pRemainingBytes, dwRemainingBufferSize);
                    memcpy(pRemainingBytes, pBytesReceived + i + 1, *pNbRemainingBytes);
                }
                break;
            }
        }
        else
        {
            if (dwBytesToHold != 0)
            {
                memcpy(pBytesToWrite + dwBytesToWrite, pBytesToHold, dwBytesToHold);
                dwBytesToWrite += dwBytesToHold;
                ZeroMemory(pBytesToHold, BUFFER_SIZE_SOCKET); // reset the holding buffer
                dwBytesToHold = 0;
            }
            else
            {
                pBytesToWrite[dwBytesToWrite++] = pBytesReceived[i];
            }
        }
        
    }
    *pNbBytesToHold = dwBytesToHold;
    *pNbBytesToWrite = dwBytesToWrite;
    return bSwitchMode;
}

bool ReadSockWritePipe(SOCKET hSock, HANDLE hPipe, bool bOverlapped, char *pPopenControlCode, DWORD dwPopenControlCodeSize, 
    char* pRemainingBytes, DWORD dwRemainingBufferSize, DWORD* pNbRemainingBytes)
{
    /* Read the socket and write the pipe
    * When it receive a buffer that contains popen mode control code
    * It copies the remaining data in pRemainingBytes buffer and return with true
    */
    bool bSwitchMode = false;

    bool bWriteSuccess = false;
    char pBytesReceived[BUFFER_SIZE_SOCKET];
    char *pBytesToHold = new char[BUFFER_SIZE_SOCKET];
    char *pBytesToWrite = new char[BUFFER_SIZE_SOCKET];
    DWORD dwNbBytesReceived = 0;
    DWORD dwNbBytesWritten = 0;
    DWORD dwNbBytesToHold = 0;
    DWORD dwNbBytesToWrite = 0;

    ZeroMemory(pBytesToHold, BUFFER_SIZE_SOCKET);
    ZeroMemory(pBytesToWrite, BUFFER_SIZE_SOCKET);

    if (bOverlapped)
    {
        do
        {
            bWriteSuccess = false;
            ZeroMemory(pBytesReceived, BUFFER_SIZE_SOCKET);
            if (*pNbRemainingBytes > 0)
            {
                // transfert remaining bytes to pBytesReceived buffer
                memcpy(pBytesReceived, pRemainingBytes, *pNbRemainingBytes);
                dwNbBytesReceived = *pNbRemainingBytes;
                ZeroMemory(pRemainingBytes, dwRemainingBufferSize);
                *pNbRemainingBytes = 0;
            }
            else
            {
                dwNbBytesReceived = recv(hSock, pBytesReceived, BUFFER_SIZE_SOCKET, 0);
            }
            if (dwNbBytesReceived != SOCKET_ERROR)
            {
                bSwitchMode = ParseReceivedBytes(pBytesReceived, dwNbBytesReceived, pBytesToHold, &dwNbBytesToHold, pBytesToWrite, &dwNbBytesToWrite,
                    pPopenControlCode, dwPopenControlCodeSize, pRemainingBytes, dwRemainingBufferSize, pNbRemainingBytes);
                if (dwNbBytesToWrite > 0)
                {
                    bWriteSuccess = WriteFile(hPipe, pBytesToWrite, dwNbBytesToWrite, &dwNbBytesWritten, NULL);
                    dwNbBytesToWrite = 0;
                    ZeroMemory(pBytesToWrite, BUFFER_SIZE_SOCKET);
                }
            }
                
        } while (dwNbBytesReceived > 0          // receiving 0 bytes would mean that the sockeet died
            && !bSwitchMode                     // non switch mode command
            && (bWriteSuccess                   // we managed to write to the pipe
                || dwNbBytesToHold > 0));       // we are waiting for a potential switch mode command
    }
    else
    {
        HANDLE hReadEvent = WSACreateEvent();
        if (hReadEvent != NULL && hReadEvent != INVALID_HANDLE_VALUE)
        {
            // we expect the socket to be non-blocking at this point. we create an asynch event to be signaled when the recv operation is ready to get some data
            if (WSAEventSelect(hSock, hReadEvent, FD_READ) == 0)
            {
                bool bSocketBlockingOperation = false;
                do
                {
                    bWriteSuccess = false;
                    ZeroMemory(pBytesReceived, BUFFER_SIZE_SOCKET);
                    WSAWaitForMultipleEvents(1, &hReadEvent, true, 100, false);
                    if (*pNbRemainingBytes > 0)
                    {
                        // transfert remaining bytes to pBytesReceived buffer
                        memcpy(pBytesReceived, pRemainingBytes, *pNbRemainingBytes);
                        dwNbBytesReceived = *pNbRemainingBytes;
                        ZeroMemory(pRemainingBytes, dwRemainingBufferSize);
                        *pNbRemainingBytes = 0;
                        WSASetLastError(0); // clear the last error so that we are sure to get in the next if block that check WSAGetLastError()
                    }
                    else
                    {
                        dwNbBytesReceived = recv(hSock, pBytesReceived, BUFFER_SIZE_SOCKET, 0);
                    }
                    // we still check WSAEWOULDBLOCK for a more robust implementation
                    if (WSAGetLastError() != WSAEWOULDBLOCK)
                    {
                        WSAResetEvent(hReadEvent);
                        bSocketBlockingOperation = false;
                        if (dwNbBytesReceived != SOCKET_ERROR)
                        {
                            bSwitchMode = ParseReceivedBytes(pBytesReceived, dwNbBytesReceived, pBytesToHold, &dwNbBytesToHold, pBytesToWrite, &dwNbBytesToWrite,
                                pPopenControlCode, dwPopenControlCodeSize, pRemainingBytes, dwRemainingBufferSize, pNbRemainingBytes);
                            if (dwNbBytesToWrite > 0)
                            {
                                bWriteSuccess = WriteFile(hPipe, pBytesReceived, dwNbBytesReceived, &dwNbBytesWritten, NULL);
                                dwNbBytesToWrite = 0;
                                ZeroMemory(pBytesToWrite, BUFFER_SIZE_SOCKET);
                            }
                        } 
                    }
                    else
                    {
                        bSocketBlockingOperation = true;
                    }
                } while (bSocketBlockingOperation                   // we didn't receive more bytes but the socket is still alive
                    || (
                        dwNbBytesReceived > 0                       // we received more bytes
                        && !bSwitchMode                             // no switch mode command
                        && (
                            bWriteSuccess                           // pipe write operator was successful
                            || dwNbBytesToHold > 0                  // we are waiting for a potential switch mode command
                            )));
            }
            WSACloseEvent(hReadEvent);
        }
    }

    delete[] pBytesToHold;
    delete[] pBytesToWrite;

    return bSwitchMode;
}


bool CallPopenWriteSock(SOCKET hSock, char* pBytesToWrite, DWORD *pNbBytesToWrite, char* pPendingCommand, DWORD *pNbPendingCommandSize)
{
    bool bRes = true;
    DWORD dwNbBytesToWrite = *pNbBytesToWrite;
    DWORD dwPendingCommandSize = *pNbPendingCommandSize;
    char pPopenOutput[BUFFER_SIZE_SOCKET];
    for (DWORD i = 0; i < dwNbBytesToWrite && dwPendingCommandSize < BUFFER_SIZE_SOCKET - 1 && bRes; ++i)
    {
        // loop stop if dwPendingCommandSize == BUFFER_SIZE_SOCKET - 1 because the last byte of the buffer is reserved for the null byte
        if (pBytesToWrite[i] != '\r')
        {
            pPendingCommand[dwPendingCommandSize++] = pBytesToWrite[i];
        }
        else
        {
            pPendingCommand[dwPendingCommandSize++] = '\0'; // make sure that the buffer is null terminated
            FILE* pPopen = _popen(pPendingCommand, "rb");
            ZeroMemory(pPopenOutput, BUFFER_SIZE_SOCKET);
            if (pPopen != NULL)
            {
                while (fgets(pPopenOutput, BUFFER_SIZE_SOCKET - 1, pPopen))
                {
                    bRes &= SendAll(hSock, pPopenOutput, (DWORD)strlen(pPopenOutput));
                    ZeroMemory(pPopenOutput, BUFFER_SIZE_SOCKET);
                }
                int endOfFileVal = feof(pPopen);
                int closeReturnVal = _pclose(pPopen);
            }
            else
            {
                bRes = false;
            }
            ZeroMemory(pPendingCommand, BUFFER_SIZE_SOCKET);
            dwPendingCommandSize = 0;
        }
    }
    if (dwPendingCommandSize >= BUFFER_SIZE_SOCKET - 1)
    {
        // we didn't receive the '\r' even after BUFFER_SIZE_SOCKET - 1 bytes
        // we purge the pending command buffer.
        ZeroMemory(pPendingCommand, BUFFER_SIZE_SOCKET);
        dwPendingCommandSize = 0;
    }
    dwNbBytesToWrite = 0;
    ZeroMemory(pBytesToWrite, BUFFER_SIZE_SOCKET);
    *pNbBytesToWrite = dwNbBytesToWrite;
    *pNbPendingCommandSize = dwPendingCommandSize;
    return bRes;
}

bool ReadSockCallPopen(SOCKET hSock, HANDLE hPipe, bool bOverlapped, char* pPtyControlCode, DWORD dwPtyControlCodeSize,
    char* pRemainingBytes, DWORD dwRemainingBufferSize, DWORD* pNbRemainingBytes)
{
    /* Read the socket and call popen for every line received
    * When it receive a buffer that contains popen mode control code
    * It copies the remaining data in pRemainingBytes buffer and return with true
    */
    bool bSwitchMode = false;

    char pBytesReceived[BUFFER_SIZE_SOCKET];
    char* pBytesToHold = new char[BUFFER_SIZE_SOCKET];
    char* pBytesToWrite = new char[BUFFER_SIZE_SOCKET];
    char* pPendingCommand = new char[BUFFER_SIZE_SOCKET];
    char* pPopenOutput = new char[BUFFER_SIZE_SOCKET];
    DWORD dwNbBytesReceived = 0;
    DWORD dwNbBytesToHold = 0;
    DWORD dwNbBytesToWrite = 0;
    DWORD dwPendingCommandSize = 0;
    DWORD dwNbBytesSent = 0;
    bool bStillAlive = false;

    ZeroMemory(pBytesToHold, BUFFER_SIZE_SOCKET);
    ZeroMemory(pBytesToWrite, BUFFER_SIZE_SOCKET);

    if (bOverlapped)
    {
        do
        {
            dwNbBytesReceived = 0;
            ZeroMemory(pBytesReceived, BUFFER_SIZE_SOCKET);
            if (*pNbRemainingBytes > 0)
            {
                // transfert remaining bytes to pBytesReceived buffer
                memcpy(pBytesReceived, pRemainingBytes, *pNbRemainingBytes);
                dwNbBytesReceived = *pNbRemainingBytes;
                ZeroMemory(pRemainingBytes, dwRemainingBufferSize);
                *pNbRemainingBytes = 0;
            }
            else
            {
                dwNbBytesReceived = recv(hSock, pBytesReceived, BUFFER_SIZE_SOCKET, 0);
            }
            if (dwNbBytesReceived != SOCKET_ERROR)
            {
                bSwitchMode = ParseReceivedBytes(pBytesReceived, dwNbBytesReceived, pBytesToHold, &dwNbBytesToHold, pBytesToWrite, &dwNbBytesToWrite,
                    pPtyControlCode, dwPtyControlCodeSize, pRemainingBytes, dwRemainingBufferSize, pNbRemainingBytes);
                if (dwNbBytesToWrite > 0)
                {
                    bStillAlive = CallPopenWriteSock(hSock, pBytesToWrite, &dwNbBytesToWrite, pPendingCommand, &dwPendingCommandSize);
                }
            }
            else
                bStillAlive = false;
        } while (dwNbBytesReceived > 0                  // receiving 0 data mean that the socket died 
            && !bSwitchMode                             // bSwitchMode == true mean we have to switch to pty mode
            && (bStillAlive                             // we managed to write back data from popen in the socket or the command failed and we didn't check the socket
                || dwNbBytesToHold > 0                  // we are currently waiting for a potentially switch mode command
                || dwPendingCommandSize > 0));          // we are currently waiting for the end of a OS command
    }
    else
    {
        HANDLE hReadEvent = WSACreateEvent();
        if (hReadEvent != NULL && hReadEvent != INVALID_HANDLE_VALUE)
        {
            // we expect the socket to be non-blocking at this point. we create an asynch event to be signaled when the recv operation is ready to get some data
            if (WSAEventSelect(hSock, hReadEvent, FD_READ) == 0)
            {
                bool bSocketBlockingOperation = false;
                do
                {
                    ZeroMemory(pBytesReceived, BUFFER_SIZE_SOCKET);
                    WSAWaitForMultipleEvents(1, &hReadEvent, true, 100, false);
                    if (*pNbRemainingBytes > 0)
                    {
                        // transfert remaining bytes to pBytesReceived buffer
                        memcpy(pBytesReceived, pRemainingBytes, *pNbRemainingBytes);
                        dwNbBytesReceived = *pNbRemainingBytes;
                        ZeroMemory(pRemainingBytes, dwRemainingBufferSize);
                        *pNbRemainingBytes = 0;
                        WSASetLastError(0); // clear the last error so that we are sure to get in the next if block that check WSAGetLastError()
                    }
                    else
                    {
                        dwNbBytesReceived = recv(hSock, pBytesReceived, BUFFER_SIZE_SOCKET, 0);
                    }
                    // we still check WSAEWOULDBLOCK for a more robust implementation
                    if (WSAGetLastError() != WSAEWOULDBLOCK)
                    {
                        WSAResetEvent(hReadEvent);
                        bSocketBlockingOperation = false;
                        if (dwNbBytesReceived != SOCKET_ERROR) // otherwise the socket died
                        {
                            bSwitchMode = ParseReceivedBytes(pBytesReceived, dwNbBytesReceived, pBytesToHold, &dwNbBytesToHold, pBytesToWrite, &dwNbBytesToWrite,
                                pPtyControlCode, dwPtyControlCodeSize, pRemainingBytes, dwRemainingBufferSize, pNbRemainingBytes);
                            if (dwNbBytesToWrite > 0)
                            {
                                bStillAlive = CallPopenWriteSock(hSock, pBytesToWrite, &dwNbBytesToWrite, pPendingCommand, &dwPendingCommandSize);
                            }
                        }
                        else
                            bStillAlive = false;
                    }
                    else
                    {
                        bSocketBlockingOperation = true;
                    }
                } while (bSocketBlockingOperation                   // we didn't receive more bytes but the socket is still alive
                    || (
                        dwNbBytesReceived > 0                       // we received more bytes
                        && !bSwitchMode                             // no switch mode command
                        && (bStillAlive                             // we managed to write back data from popen in the socket or the command failed and we didn't check the socket
                            || dwNbBytesToHold > 0                  // we are currently waiting for a potentially switch mode command
                            || dwPendingCommandSize > 0)));         // we are currently waiting for the end of a OS command
            }
            WSACloseEvent(hReadEvent);
        }
    }

    delete[] pBytesToHold;
    delete[] pBytesToWrite;
    delete[] pPendingCommand;
    delete[] pPopenOutput;

    return bSwitchMode;
}

DWORD WINAPI ThreadReadSocketWritePipe(LPVOID lpParams)
{
    CommunicationThreadParams* pThreadParams = (CommunicationThreadParams*)lpParams;
    HANDLE hPipe = pThreadParams->hInPipe;
    SOCKET hSock = pThreadParams->hSock;
    HANDLE hChildProcess = pThreadParams->piInfo.hProcess;
    HANDLE hBlockWriteSockThread = pThreadParams->hBlockWriteSockThread;
    bool bOverlapped = pThreadParams->bOverlapped;
    char* pPopenControlCode = pThreadParams->pPopenControlCode;
    DWORD dwPopenControlCodeSize = (DWORD)min(strlen(pPopenControlCode), BUFFER_SIZE_SOCKET);
    char* pPtyControlCode = pThreadParams->pPtyControlCode;
    DWORD dwPtyControlCodeSize = (DWORD)min(strlen(pPtyControlCode), BUFFER_SIZE_SOCKET);
    bool bPopenMode = false; // by default we're in pty mode
    bool bSwitchMode = false; // loop control flag
    char pRemainingBytes[BUFFER_SIZE_SOCKET];
    ZeroMemory(pRemainingBytes, BUFFER_SIZE_SOCKET);
    DWORD dwNbRemainingBytes = 0;

    do
    {
        if (bPopenMode)
        {
            // Reset the event to block the ReadPipeWriteSock thread
            ResetEvent(hBlockWriteSockThread); 
            DWORD dwBytesWritten = 0;
            // Unlock the read-pipe-write-sock thread if it's blocked on the ReadFile of the pipe
            WriteFile(pThreadParams->hInPipe, "\r", 1, &dwBytesWritten, NULL); 
            Sleep(200); // wait at least 0.2s before reading the child process CWD
            CString csCwd;
            if(GetProcessCwd(pThreadParams->hOutPipe, pThreadParams->hInPipe, csCwd))
                SetCurrentDirectory(csCwd);
            bSwitchMode = ReadSockCallPopen(hSock, hPipe, bOverlapped, pPtyControlCode, dwPtyControlCodeSize,
                pRemainingBytes, BUFFER_SIZE_SOCKET, &dwNbRemainingBytes);
            SetEvent(hBlockWriteSockThread); // Signal the event to unblock the ReadPipeWriteSock thread
        }
        else
        {
            bSwitchMode = ReadSockWritePipe(hSock, hPipe, bOverlapped, pPopenControlCode, dwPopenControlCodeSize, 
                pRemainingBytes, BUFFER_SIZE_SOCKET, &dwNbRemainingBytes);            
        }
        bPopenMode = !bPopenMode;
    } while (bSwitchMode);
    
    TerminateProcess(hChildProcess, 0);
    return 0;
}

HANDLE StartThreadReadSocketWritePipe(CommunicationThreadParams* pParams)
{
    HANDLE hThread = CreateThread(0, 0, ThreadReadSocketWritePipe, pParams, 0, 0);
    return hThread;
}

HRESULT SpawnPty(CString csCommandLine, DWORD dwRows, DWORD dwCols, char* pPopenControlCode, char* pPtyControlCode)
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
                    // try to duplicate the socket for the current process
                    bool bOverlapped = false;
                    SOCKET hSock = DuplicateTargetProcessSocket(dwProcessId, bOverlapped);
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
                            WriteStdErr("ERROR: Could not create pseudo console.\r\n");
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

                                if (!bOverlapped) SetSocketBlockingMode(hSock, 1);
                                // The threads functions doesn't work: Check if there is any problem with the pipes or the socket
                                CommunicationThreadParams params;
                                ZeroMemory(&params, sizeof(CommunicationThreadParams));
                                HANDLE hBlockWriteSockThread = CreateEvent(NULL, TRUE, TRUE, NULL); // handle for the read sock thread to block the write sock thread in popen mode
                                if (hBlockWriteSockThread != NULL && hBlockWriteSockThread != INVALID_HANDLE_VALUE)
                                {
                                    params.pPopenControlCode = pPopenControlCode;
                                    params.pPtyControlCode = pPtyControlCode;
                                    params.hInPipe = hInputPipeWrite;
                                    params.hOutPipe = hOutputPipeRead;
                                    params.hBlockWriteSockThread = hBlockWriteSockThread;
                                    params.hSock = hSock;
                                    params.piInfo = childProcessInfo;
                                    params.bOverlapped = bOverlapped;
                                    HANDLE hThreadReadPipeWriteSocket = StartThreadReadPipeWriteSocket(&params);
                                    HANDLE hThreadReadSocketWritePipe = StartThreadReadSocketWritePipe(&params);
                                    char pSuccessMsg[] = "SUCCESS: pty ready!\n";
                                    SendAll(hSock, pSuccessMsg, (DWORD)strlen(pSuccessMsg));
                                    hRes = S_OK;
                                    // wait for the child process until exit
                                    WaitForSingleObject(childProcessInfo.hProcess, INFINITE);
                                    //cleanup everything
                                    TerminateThread(hThreadReadPipeWriteSocket, 0);
                                    TerminateThread(hThreadReadSocketWritePipe, 0);
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
                                CloseHandle(childProcessInfo.hThread);
                                CloseHandle(childProcessInfo.hProcess);
                                WriteStdOut("Shutdown.\r\n");
                            }
                            if (hPseudoConsole != NULL) ClosePseudoConsole(hPseudoConsole);
                        }
                        if (bNewConsoleAllocated)
                            FreeConsole();
                        closesocket(hSock);
                    }
                    try
                    {
                        WSACleanup();
                    }
                    catch (...)
                    {
                        // WSACleanup crash but can find why.
                    }
                }
                else
                {
                    WriteStdErr("ERROR: Failed to start WinSock API\r\n");
                }
                RestoreStdHandles(hOldStdIn, hOldStdOut, hOldStdErr);
                if (hInputPipeWrite != NULL) CloseHandle(hInputPipeWrite);
                if (hOutputPipeRead != NULL) CloseHandle(hOutputPipeRead);
            }
            else
            {
                WriteStdErr("ERROR: Failed to create pipes\r\n");
            }
        }
        else
        {
            WriteStdErr("ERROR: The system doesn't support PseudoConsole API\r\n");
        }
    }
    return hRes;
}

void CleanUp()
{
    TCHAR szModuleName[MAX_PATH];
    TCHAR szCmd[2 * MAX_PATH];
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    GetModuleFileName(NULL, szModuleName, MAX_PATH);

    StringCbPrintf(szCmd, 2 * MAX_PATH, SELF_REMOVE_STRING, szModuleName);

    CreateProcess(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}