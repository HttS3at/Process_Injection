#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>

class Memory
{
private:
	HANDLE hProcess;
public:
	Memory()
	{
		hProcess = NULL;
	}

	~Memory()
	{
		CloseHandle(hProcess);
	}

	int Error(const char* text)
	{
		printf("%s (%u)\n", text, GetLastError());
		return 1;
	}

	uintptr_t GetProcessID(const wchar_t* targetProcess)
	{
		uintptr_t processID = NULL;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (hSnapshot == INVALID_HANDLE_VALUE)
			return Error("Failed in CreateToolhelp32Snapshot");

		PROCESSENTRY32 processEntry;
		processEntry.dwSize = sizeof(processEntry);

		if (!Process32First(hSnapshot, &processEntry))
			return Error("Failed in Process32First");

		do
		{
			if (!wcscmp(processEntry.szExeFile, targetProcess))
			{
				processID = processEntry.th32ProcessID;
				hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processID);
				break;
			}
		} while (Process32Next(hSnapshot, &processEntry));

		CloseHandle(hSnapshot);
		return processID;
	}

	uintptr_t GetModuleID(uintptr_t processID, const wchar_t* targetModule)
	{
		uintptr_t moduleID = NULL;
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processID);

		if (hSnapshot == INVALID_HANDLE_VALUE)
			return Error("Failed in CreateToolhelp32Snapshot");

		MODULEENTRY32 moduleEntry;
		moduleEntry.dwSize = sizeof(moduleEntry);

		if (!Module32First(hSnapshot, &moduleEntry))
			return Error("Failed in Process32First");

		do
		{
			if (!wcscmp(moduleEntry.szModule, targetModule))
			{
				moduleID = (uintptr_t)moduleEntry.modBaseAddr;
				break;
			}
		} while (Module32Next(hSnapshot, &moduleEntry));

		CloseHandle(hSnapshot);
		return moduleID;
	}

	template <class dataType>
	dataType ReadMemory(dataType lpBaseAddress)
	{
		dataType lpBuffer;
		ReadProcessMemory(hProcess, (LPVOID*)lpBaseAddress, &lpBuffer, sizeof(lpBuffer), NULL);
		return lpBuffer;
	}

	template <class dataType>
	dataType WriteMemory(dataType lpBaseAddress, dataType lpBuffer)
	{
		WriteProcessMemory(hProcess, (LPVOID*)lpBaseAddress, &lpBuffer, sizeof(lpBuffer), NULL);
		return lpBuffer;
	}

	uintptr_t FindDMAAddy(uintptr_t pointer, std::vector<unsigned int> offsets)
	{
		uintptr_t address = pointer;
		for (unsigned int i = 0; i < offsets.size(); ++i)
		{
			ReadProcessMemory(hProcess, (BYTE*)address, &address, sizeof(address), 0);
			address += offsets[i];
		}
		return address;
	}

	template<typename T>
	DWORD ProtectMemory(DWORD address, DWORD protection)
	{
		DWORD oldProtection;
		VirtualProtect((LPVOID)address, sizeof(T), protection, &oldProtection);
		return oldProtection;
	}

	DWORD GetVirtualFunction(DWORD classInstance, DWORD functionIndex)
	{
		DWORD VFTable = ReadMemory<DWORD>(classInstance);
		DWORD hookAddress = VFTable + functionIndex * sizeof(DWORD);
		return ReadMemory<DWORD>(hookAddress);
	}

	DWORD HookVirtualFunction(DWORD classInstance, DWORD functionIndex, DWORD newFunction)
	{
		DWORD VFTable = ReadMemory<DWORD>(classInstance);
		DWORD hookAddress = VFTable + functionIndex * sizeof(DWORD);

		auto oldProtection = ProtectMemory<DWORD>(hookAddress, PAGE_READWRITE);
		DWORD originalFunc = ReadMemory<DWORD>(hookAddress);
		WriteMemory<DWORD>(hookAddress, newFunction);
		ProtectMemory<DWORD>(hookAddress, oldProtection);

		return originalFunc;
	}

	unsigned char* InlineHook(DWORD src, DWORD dst)
	{
		DWORD newOffset = dst - src - 5;

		auto oldProtection = ProtectMemory<BYTE[5]>(src, PAGE_EXECUTE_READWRITE);

		unsigned char* originals = new unsigned char[5];
		for (unsigned int i = 0; i < 5; i++)
			originals[i] = ReadMemory<unsigned char>(src + i);

		WriteMemory<BYTE>(src, 0xE9);
		WriteMemory<DWORD>(src + 1, newOffset);

		ProtectMemory<BYTE[5]>(src + 1, oldProtection);
		return originals;
	}

	void InlineUnhook(DWORD src, unsigned char* originals)
	{
		auto oldProtection = ProtectMemory<BYTE[5]>(src, PAGE_EXECUTE_READWRITE);
		for (unsigned int i = 0; i < 5; i++)
			WriteMemory<BYTE>(src + i, originals[i]);
		ProtectMemory<BYTE[5]>(src + 1, oldProtection);

		delete[] originals;
	}
};
