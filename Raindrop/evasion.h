#ifndef _EVASION_H_
#define _EVASION_H_


#include "stdafx.h"

int UnHookDll(CString module = _T("ntdll.dll"), CString path = _T("c:\\windows\\system32\\ntdll.dll"));

#endif