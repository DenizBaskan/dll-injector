#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>

void log_err(const char* func)
{
	wchar_t err[256] = {0};

	FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), err, 255, NULL);

	printf("%s -> %ls\n", func, err);
}

DWORD GetProcID(const wchar_t* proc_name)
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		log_err("CreateToolhelp32Snapshot");
		return NULL;
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(snap, &pe)) {
		CloseHandle(snap);
		log_err("Process32First");
		return NULL;
	}

	do {
		if (wcscmp(pe.szExeFile, proc_name) == 0) {
			CloseHandle(snap);
			return pe.th32ProcessID;
		}
	} while (Process32Next(snap, &pe));

	CloseHandle(snap);

	printf("Could not find process\n");
	return NULL;
}

int main(int argc, char** argv)
{
	HANDLE proc = NULL;
	LPVOID lib_address = NULL;
	HANDLE thread = NULL;

	int return_value = 1;

	if (argc < 3) {
		printf("Invalid amount of args\n");
		return 1;
	}

	char* lib_name = argv[2];
	size_t lib_len = strlen(lib_name) + 1;

	wchar_t proc_name[100];
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, argv[1], -1, proc_name, 100);

	DWORD proc_id = GetProcID(proc_name);
	if (proc_id == NULL) {
		goto cleanup;
	}

	proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, NULL, proc_id);
	if (proc == NULL) {
		log_err("OpenProcess");
		goto cleanup;
	}

	lib_address = VirtualAllocEx(proc, NULL, lib_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lib_address == NULL) {
		log_err("VirtualAllocEx");
		goto cleanup;
	}

	if (WriteProcessMemory(proc, lib_address, lib_name, lib_len, NULL) == 0) {
		log_err("WriteProcessMemory");
		goto cleanup;
	}

	thread = CreateRemoteThread(proc, NULL, 0,
		(LPTHREAD_START_ROUTINE)LoadLibraryA, // works because of how kernel32.dll is always loaded first which locates LoadLibraryA at the same address for all programs with the same bits
		lib_address, 0, NULL);

	if (thread == NULL) {
		log_err("CreateRemoteThread");
		goto cleanup;
	}

	DWORD wait_res;
	wait_res = WaitForSingleObject(thread, 5000);
	if (wait_res != WAIT_OBJECT_0) {
		if (wait_res == WAIT_FAILED) {
			log_err("WaitForSingleObject");
		}
		else {
			printf("WaitForSingleObject(): %d\n", wait_res);
		}

		goto cleanup;
	}

	DWORD exit_code;
	if (GetExitCodeThread(thread, &exit_code) == NULL) {
		log_err("GetExitCodeThread");
		goto cleanup;
	}

	if (exit_code == NULL) {
		printf("LoadLibraryA failed in the remote process\n");
		goto cleanup;
	}

	printf("Injected DLL\n");
	return_value = 0;

cleanup:
	if (lib_address != NULL) {
		VirtualFreeEx(proc, lib_address, 0, MEM_RELEASE);
	}

	if (proc != NULL) {
		CloseHandle(proc);
	}

	if (thread != NULL) {
		CloseHandle(thread);
	}

	return return_value;
}
