#pragma once

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <Fltuser.h>
#pragma comment(lib, "FltLib")


#define GLE( x ) { printf("%s failed with error: %d\n", x , GetLastError()); }

DWORD64 genPattern(BYTE b);
void DumpHex(const void* data, size_t size);// https://gist.github.com/ccbrown/9722406
BOOL OpenFile_Acronis(HANDLE hPort, const wchar_t* lpFileName, PHANDLE lpOutHandle);
DWORD CreateScanContextWithDir(HANDLE hPort, const wchar_t* lpFileName);
BOOL SetRegKeyHookLibs(HANDLE hPort, const wchar_t* x86HookLibPath, const wchar_t* x64HookLibPath);

// begin context

#define ACRONIS_CTX_OWNER (DWORD)1
#define ACRONIS_CTX_NOTOWNER (DWORD)2

typedef struct ACRONIS_FLT_CTX {
	DWORD reserved0;
	DWORD dwContextSwitch;
}ACRONIS_FLT_CTX, * PACRONIS_FLT_CTX;

// end context

// begin message types

#define ACRONIS_OP_CREATEFILE 0x22
#define ACRONIS_OP_QUERYINFOFILE 0x5
#define ACRONIS_OP_CREATEFILE_CONTEXTDIR 0x1b
#define ACRONIS_OP_REG_SET_HOOKLIBS 0x37

// end message types


// begin message buffer

#define ACRONIS_FLT_MSG_HDR (DWORD64)0x54724D73
#pragma pack(push)
#pragma pack(4)
typedef struct ACRONIS_FLT_MESSAGE {
	DWORD dwHeader; // must be ACRONIS_FLT_MSG_HDR
	DWORD dwMessageType; // opcode
	DWORD dwMessageSize;
	DWORD64 reserved0[12];
} ACRONIS_FLT_MESSAGE, * PACRONIS_FLT_MESSAGE;

typedef struct ACRONIS_SCANDIR_RESP {
	DWORD64 reserved0;
	DWORD reserved1;
	HANDLE hFile;
}ACRONIS_SCANDIR_RESP, * PACRONIS_SCANDIR_RESP;

typedef struct ACRONIS_CCWD {
	DWORD64 reserved0;
	DWORD reserved1;
	DWORD contextID;
}ACRONIS_CCWD, * PACRONIS_CCWD;
#pragma pack(pop)


#pragma pack(push)
#pragma pack(2)
typedef struct ACRONIS_FLT_CREATE_CONTEXTDIR {
	DWORD dwHeader; // must be ACRONIS_FLT_MSG_HDR
	DWORD dwMessageType; // opcode
	DWORD dwMessageSize;
	DWORD reserved0;
	WORD reserved1;
	WORD toSkip;
	WORD reserved2;
	WORD reserved3;
	WORD reserved4;
	WORD reserved5;
	WCHAR wstrPath[MAX_PATH + 1];
}ACRONIS_FLT_CREATE_CONTEXTDIR, * PACRONIS_FLT_CREATE_CONTEXTDIR;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(2)
typedef struct ACRONIS_FLT_REG_SET_HOOKLIBS {
	DWORD dwHeader; // must be ACRONIS_FLT_MSG_HDR
	DWORD dwMessageType; // opcode
	DWORD dwMessageSize;
	DWORD reserved0;
	WORD reserved1;
	WORD toSkip0;
	DWORD reserved2;
	WORD reserved3;
	WORD toSkip1;
	WCHAR wstrx86LibPath[MAX_PATH + 1];	
	WCHAR wstrx64LibPath[MAX_PATH + 1];
}ACRONIS_FLT_REG_SET_HOOKLIBS, * PACRONIS_FLT_REG_SET_HOOKLIBS;
#pragma pack(pop)
// end message buffer