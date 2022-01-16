#include <Windows.h>
#include "Memory.h"
#include <iostream>

using namespace std;

int main()
{
	Memory memory;

	uintptr_t processID = memory.GetProcessID(L"csgo.exe");
	uintptr_t moduleID = memory.GetModuleID(processID, L"client.dll");

	cout << processID << endl;
	cout << moduleID << endl;

	return 0;
}