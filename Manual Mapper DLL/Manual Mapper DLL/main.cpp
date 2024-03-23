#include "Injection.h"
//	C:\\Users\\INSECT\\source\\repos\\DPCPPDynamicLinkLibrary1\\x64\\Debug\\DPCPPDynamicLinkLibrary1.dll
//	C:\\Users\\INSECT\\source\\repos\\RE2 Intel C++\\x64\\Debug\\RE2 Intel C++.dll
//	C:\\Users\\INSECT\\source\\repos\\Dll1\\x64\\Debug\\Dll1.dll
#ifdef _WIN64
const char szDllFile[] = "C:\\Users\\INSECT\\source\\repos\\RE2 Intel C++\\x64\\Release\\RE2 Intel C++.dll";
const char szProc[] = "re2.exe";
#else
const char szDllFile[] = "C:\\Users\\INSECT\\source\\repos\\RE2 Intel C++\\x64\\Release\\RE2 Intel C++.dll";
const char szProc[] = "re2.exe";
#endif

bool IsCorrectTargetArchitecture(HANDLE hProc)
{
	BOOL bTarget = FALSE;
	if (!IsWow64Process(hProc, &bTarget))
	{
		printf("Can't confirm target process architecture: 0x%X\n", GetLastError());
		return false;
	}

	BOOL bHost = FALSE;
	IsWow64Process(GetCurrentProcess(), &bHost);

	return (bTarget == bHost);
}

int main()
{
	PROCESSENTRY32 PE32{ 0 };
	PE32.dwSize = sizeof(PE32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		DWORD Err = GetLastError();
		printf("CreateToolhelp32Snapshot failed: 0x%X\n", Err);
		system("PAUSE");
		return 0;
	}

	DWORD PID = 0;
	BOOL bRet = Process32First(hSnap, &PE32);
	while (bRet)
	{
		if (!strcmp(szProc, PE32.szExeFile))
		{
			PID = PE32.th32ProcessID;
			break;
		}
		bRet = Process32Next(hSnap, &PE32);
	}

	CloseHandle(hSnap);

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProc)
	{
		DWORD Err = GetLastError();
		printf("OpenProcess failed: 0x%X\n", Err);
		system("PAUSE");
		return 0;
	}

	if (!IsCorrectTargetArchitecture(hProc))
	{
		printf("Invalid target process.\n");
		CloseHandle(hProc);
		system("PAUSE");
		return 0;
	}

	if (!ManualMap(hProc, szDllFile))
	{
		CloseHandle(hProc);
		printf("Something went wrong FeelsBadMan\n");
		system("PAUSE");
		return 0;
	}

	CloseHandle(hProc);

	return 0;
}