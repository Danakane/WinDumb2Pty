#include "spawn.h"

DWORD GetParentProcess()
{
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD ppid = 0, pid = GetCurrentProcessId();

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

HRESULT CreatePseudoConsoleWithPipes(HPCON* phPseudoConsole, HANDLE hConPtyInputPipeRead, HANDLE hConPtyOutputPipeWrite, UINT uiRows, UINT uiCols)
{
    HRESULT hRes = E_FAIL;
    if (EnableVirtualTerminalSequenceProcessing())
    {
        COORD consoleCoord;
        consoleCoord.X = (short)uiCols;
        consoleCoord.Y = (short)uiRows;
        hRes = CreatePseudoConsole(consoleCoord, hConPtyInputPipeRead, hConPtyOutputPipeWrite, 0, phPseudoConsole);
    }
    return hRes;
}

STARTUPINFOEX ConfigureProcessThread(HPCON* phPseudoConsole, IntPtr attributes)
{
    IntPtr lpSize = IntPtr.Zero;
    bool success = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
    if (success || lpSize == IntPtr.Zero)
    {
        throw new ConPtyShellException("Could not calculate the number of bytes for the attribute list. " + Marshal.GetLastWin32Error());
    }
    STARTUPINFOEX startupInfo = new STARTUPINFOEX();
    startupInfo.StartupInfo.cb = Marshal.SizeOf(startupInfo);
    startupInfo.lpAttributeList = Marshal.AllocHGlobal(lpSize);
    success = InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, ref lpSize);
    if (!success)
    {
        throw new ConPtyShellException("Could not set up attribute list. " + Marshal.GetLastWin32Error());
    }
    success = UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, attributes, phPseudoConsole, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
    if (!success)
    {
        throw new ConPtyShellException("Could not set pseudoconsole thread attribute. " + Marshal.GetLastWin32Error());
    }
    return startupInfo;
}

PROCESS_INFORMATION RunProcess(ref STARTUPINFOEX sInfoEx, string commandLine)
{
    PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
    SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
    int securityAttributeSize = Marshal.SizeOf(pSec);
    pSec.nLength = securityAttributeSize;
    SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();
    tSec.nLength = securityAttributeSize;
    bool success = CreateProcessEx(null, commandLine, ref pSec, ref tSec, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref sInfoEx, out pInfo);
    if (!success)
    {
        throw new ConPtyShellException("Could not create process. " + Marshal.GetLastWin32Error());
    }
    return pInfo;
}

PROCESS_INFORMATION CreateChildProcessWithPseudoConsole(IntPtr handlePseudoConsole, string commandLine)
{
    STARTUPINFOEX startupInfo = ConfigureProcessThread(handlePseudoConsole, (IntPtr)PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE);
    PROCESS_INFORMATION processInfo = RunProcess(ref startupInfo, commandLine);
    return processInfo;
}