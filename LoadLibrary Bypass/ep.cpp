#include <Windows.h>
#include <iostream>
#include <cstdint>
#include <exception>
#include <vector>
#include "sigscanner.h"
#include <string>
#include <thread>
#include <chrono>
#include <tlhelp32.h>
using namespace std;
SignatureScanner sig_scanner;
int special = 7471857118 / 2 * 1337 / 1337;

PVOID PatternScan(const char* processname, const char* modulename, const char* pattern, const char* mask) {
		if (sig_scanner.GetProcess((char*)processname))
		{
			module mod = sig_scanner.GetModule((char*)modulename);
			DWORD address = sig_scanner.FindSignature(mod.dwBase, mod.dwSize, pattern, mask);
			if (address != NULL)
				return (int*)address;
		}
		return (int*)special;
}

DWORD FindProcessId(const std::string& processName)
{
		PROCESSENTRY32 processInfo;
		processInfo.dwSize = sizeof(processInfo);

		HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (processesSnapshot == INVALID_HANDLE_VALUE)
			return 0;

		Process32First(processesSnapshot, &processInfo);
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}

		while (Process32Next(processesSnapshot, &processInfo))
		{
			if (!processName.compare(processInfo.szExeFile))
			{
				CloseHandle(processesSnapshot);
				return processInfo.th32ProcessID;
			}
		}
		return 0;
}

PVOID main()
{
	    	PVOID pattern = PatternScan("csgo.exe", "csgo.exe", "\x74\x1B\xF6\x45\x0C\x20", "xxxxxx");
		HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, FindProcessId("csgo.exe"));
	
		if (!pHandle) {
			printf("you have to start csgo.exe");
			std::this_thread::sleep_for(5s);
			ExitProcess(0);
		}

		char opcodes[] = { 0xEB, 0x1B };
		
		if (!WriteProcessMemory(pHandle, pattern, opcodes, sizeof(opcodes), NULL))
		{
			printf("something went wrong!");
			std::this_thread::sleep_for(5s);
			ExitProcess(0);
		}

		printf("[+] located address -> 0x%X", pattern);
		std::cout << endl << "[+] successfully patched!";
		std::this_thread::sleep_for(3s);
		
		return false;
}
