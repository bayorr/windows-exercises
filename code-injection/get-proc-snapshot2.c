// TODO: each walk function declares its own HANDLE. To refactor, make a single snapshot and pass that handle to all the functions. Also experiement with making the HANDLE static. Compare the differences to see if the threads change between walk calls.
// TODO: add error handling
// TODO: add command line arguments to only print specific information ie: base addr of module x from process notepad.exe

/*
Steps:
	1) Get target PID
	2) Allocate space in target process for shell code
	3) Write shellcode in the allocated space
	4) Find target process threads
	5) Queue an APC on all of the threads to execute shellcode
*/
#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <string.h>

DWORD walk_process(char * process) {
	// find process from argv[1]
	PROCESSENTRY32 process_entry;
	process_entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if(Process32First(snapshot, &process_entry) == TRUE) {
		while(Process32Next(snapshot, &process_entry) == TRUE) {
			if(stricmp(process_entry.szExeFile, process) == 0) {
				CloseHandle(snapshot);
				return process_entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	printf("Did not find process '%s'\n", process);
	return 0;
}


/* from microsoft docs:
	You can enumerate the threads of a specific process by taking a snapshot that
	includes the threads and then by traversing the thread list, keeping information
	about the threads that have the same process identifier as the specified process.
*/
BOOL walk_threads(DWORD process) {
	THREADENTRY32 thread_entry32;
	thread_entry32.dwSize = sizeof(THREADENTRY32);
	
	HANDLE target_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, process);

	if(Thread32First(target_snapshot, &thread_entry32) == FALSE) {
		CloseHandle(target_snapshot);
		printf("Failed to enumerate threads at 'Thread32First'\n");
	}
	// enumerate through threads
	while(Thread32Next(target_snapshot, &thread_entry32)) {
		// if the next thread belongs to our target process
		if(thread_entry32.th32OwnerProcessID == process) {
			// print struct members
			printf("Thread ID: [%d]\n", thread_entry32.th32ThreadID);
			printf("Thread Kernel Base Priority: [%d]\n", thread_entry32.tpBasePri);
		}
	}
	CloseHandle(target_snapshot);	
}
/* from microsoft docs:
	A snapshot that includes the module list for a specified process contains information
	about each module, executable file, or dynamic-link library (DLL), used by the
	specified process
*/
BOOL walk_process_modules(DWORD process, char * target_module) {
    MODULEENTRY32 module32;
	module32.dwSize = sizeof(MODULEENTRY32);
	HANDLE target_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, process);

    if(target_module) {
        printf("[debug]: target_module = '%s'\n", target_module);
        if(Module32First(target_snapshot, &module32) == FALSE) {
		    CloseHandle(target_snapshot);
		    printf("Failed to enumerate modules from target snapshot\n");
	    }
        while(Module32Next(target_snapshot, &module32)) {
		    if(module32.th32ProcessID == process) {
                if(strcmp(module32.szModule, target_module) == 0) {
			        printf("Module Name: %s\n", module32.szModule);
			        printf("   Module Path: [%s]\n", module32.szExePath);
			        printf("   Module Addr: [0x%08X]\n", module32.modBaseAddr);
    			    printf("   Module Size: [0x%08X]\n", module32.modBaseAddr);
                }
            }
	    }

        CloseHandle(target_snapshot);
        return TRUE;
    }

	if(Module32First(target_snapshot, &module32) == FALSE) {
	    CloseHandle(target_snapshot);
	    printf("Failed to enumerate modules from target snapshot\n");
	}
	
	while(Module32Next(target_snapshot, &module32)) {
	    if(module32.th32ProcessID == process) {
		    printf("Module Name: %s\n", module32.szModule);
		    printf("   Module Path: [%s]\n", module32.szExePath);
		    printf("   Module Addr: [0x%08X]\n", module32.modBaseAddr);
		    printf("   Module Size: [0x%08X]\n", module32.modBaseAddr);
	    }
	}

	CloseHandle(target_snapshot);
    printf("[debug]: target_module = '%s'\n", target_module);
    printf("[debug]: module name = '%s'\n", module32.szModule);
}


int main(int argc, char ** argv) {
    char target_module[100];
    if(argc > 3 || !argv) {
		printf("Usage\n\tcmd <target_process_name>\n");
		return -1;
    }
    // If an argument module is give, try and search for just that module
    if(argc == 3) {
        char *target_module = argv[2];
        printf("Attempting to find module '%s'\n", target_module);
        	// set up structure to store threads
	    THREADENTRY32 thread_entry32;
	    thread_entry32.dwSize = sizeof(THREADENTRY32);
	    
	    // get target pid from argv[1]
	    DWORD target_pid = walk_process(argv[1]);
	    if(target_pid) printf("found target PID at [%d]\n", target_pid);
    
	    // enumerate threads from target process and print information
	    walk_threads(target_pid);
	    
	    // enumerate modules from target process and print information
        printf("[debug]: Walking %s for target module %s\n", argv[1], target_module);
	    walk_process_modules(target_pid, target_module);
        return 0;
    }
	// set up structure to store threads
	THREADENTRY32 thread_entry32;
	thread_entry32.dwSize = sizeof(THREADENTRY32);
	
	// get target pid from argv[1]
	DWORD target_pid = walk_process(argv[1]);
	if(target_pid) printf("found target PID at [%d]\n", target_pid);

	// enumerate threads from target process and print information
	walk_threads(target_pid);
	
	// enumerate modules from target process and print information
	walk_process_modules(target_pid, NULL);
	
    return 0;
}
