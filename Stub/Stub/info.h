#pragma once
#include "windows.h"

#ifndef MAX_SECTION_SIZE
#define MAX_SECTION_SIZE 16
#endif // !MAX_SECTION_SIZE


typedef struct _SectionNode
{
	//解压区段
	DWORD SizeOfRawData;
	DWORD SectionRva;
}SectionNode;

typedef struct _Password
{
	bool setPassword;
	char password[15];
}Password;

typedef struct _MTime
{
	int year;
	int month;
	int day;
	int hour;
	int minute;
	int second;
	bool setTime;
}MTime;

typedef struct _GlogalExternVar
{
	SectionNode mSectionNodeArray[MAX_SECTION_SIZE];
	//加壳的导入表地址
	DWORD dwIATVirtualAddress;
	//加壳的tls数据大小
	DWORD dwTLSSize;
	//加壳的tls虚拟地址 rva
	DWORD dwTLSVirtualAddress;
	//加壳的原始oep
	HMODULE dwOrignalOEP;
	//重定位rva
	DWORD dwRelocationRva;

	DWORD dwBaseOfCode;

	HMODULE dwOrignalImageBase;
	DWORD dwPressSize;

	Password mPassword;
	MTime mTime;
}GlogalExternVar;



typedef HMODULE(WINAPI*PEGetModuleHandleW)(_In_opt_ LPCWSTR lpModuleName);

typedef HMODULE(WINAPI*PELoadLibraryExA)(_In_ LPCSTR lpLibFileName, HANDLE file, DWORD mode);

typedef  FARPROC(WINAPI *PEGetProcAddress)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);

typedef BOOL(WINAPI *LPVIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD); // VirtualProtect

typedef BOOL(WINAPI*PEVirtualFree)(LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD dwFreeType);

typedef LPVOID(WINAPI*PEVirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);

typedef HWND(WINAPI *PECreateWindowExW)(_In_ DWORD dwExStyle, _In_opt_ LPCWSTR lpClassName, _In_opt_ LPCWSTR lpWindowName, _In_ DWORD dwStyle, _In_ int X, _In_ int Y, _In_ int nWidth, _In_ int nHeight, _In_opt_ HWND hWndParent, _In_opt_ HMENU hMenu, _In_opt_ HINSTANCE hInstance, _In_opt_ LPVOID lpParam);

typedef WORD(WINAPI* PERegisterClassExW)(_In_ CONST WNDCLASSEXW *lpWndClass);

typedef BOOL(WINAPI* PEShowWindow)(_In_ HWND hWnd, _In_ int nCmdShow);

typedef BOOL(WINAPI* PEUpdateWindow)(_In_ HWND hWnd);

typedef BOOL(WINAPI* PEGetMessageW)(_Out_ LPMSG lpMsg, _In_opt_ HWND hWnd, _In_ UINT wMsgFilterMin, _In_ UINT wMsgFilterMax);

typedef BOOL(WINAPI* PETranslateMessage)(_In_ CONST MSG *lpMsg);

typedef LRESULT(WINAPI* PEDispatchMessageW)(_In_ CONST MSG *lpMsg);

typedef  LRESULT(WINAPI* PEDefWindowProcW)(_In_ HWND hWnd, _In_ UINT Msg, _In_ WPARAM wParam, _In_ LPARAM lParam);

typedef VOID(WINAPI *PEPostQuitMessage)(_In_ int nExitCode);

typedef VOID(WINAPI* PEExitProcess)(_In_ UINT uExitCode);

typedef BOOL(WINAPI* PEDestroyWindow)(_In_ HWND hWnd);

typedef HINSTANCE(*PEShellExecute)(_In_opt_ HWND    hwnd, _In_opt_ char* lpOperation, _In_     char* lpFile, _In_opt_ char* lpParameters, _In_opt_ char* lpDirectory, _In_     INT     nShowCmd);

typedef BOOL(WINAPI* PESetPriorityClass)(_In_ HANDLE hProcess, _In_ DWORD dwPriorityClass);

typedef BOOL(WINAPI* PESetThreadPriority)(_In_ HANDLE hThread, _In_ int nPriority);

typedef DWORD(WINAPI* PEGetModuleFileNameA)(_In_opt_ HMODULE hModule, LPSTR lpFilename, _In_ DWORD nSize);

typedef HANDLE (WINAPI *PECreateFileA)(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
);

typedef HANDLE(WINAPI* PECreateFileW)(_In_ LPCWSTR lpFileName, _In_ DWORD dwDesiredAccess, _In_ DWORD dwShareMode, _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes, _In_ DWORD dwCreationDisposition, _In_ DWORD dwFlagsAndAttributes, _In_opt_ HANDLE hTemplateFile);

typedef BOOL(WINAPI* PEWriteFile)(_In_ HANDLE hFile, _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer, _In_ DWORD nNumberOfBytesToWrite, _Out_opt_ LPDWORD lpNumberOfBytesWritten, _Inout_opt_ LPOVERLAPPED lpOverlapped);

typedef BOOL(WINAPI *PECloseHandle)(_In_ HANDLE hObject);

typedef UINT(WINAPI* PEGetDlgItemTextA)(_In_ HWND hDlg, _In_ int nIDDlgItem, _Out_writes_(cchMax) LPSTR lpString, _In_ int cchMax);

typedef VOID(WINAPI* PEGetLocalTime)(_Out_ LPSYSTEMTIME lpSystemTime);

typedef int (WINAPI* PEMessageBoxW)(_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType);

typedef HANDLE(WINAPI* PECreateThread)(_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, _In_ SIZE_T dwStackSize, _In_ LPTHREAD_START_ROUTINE lpStartAddress, _In_opt_ __drv_aliasesMem LPVOID lpParameter, _In_ DWORD dwCreationFlags, _Out_opt_ LPDWORD lpThreadId);

typedef VOID(WINAPI* PESleep)(_In_ DWORD dwMilliseconds);

typedef BOOL(WINAPI* PEDuplicateHandle)(_In_ HANDLE hSourceProcessHandle, _In_ HANDLE hSourceHandle, _In_ HANDLE hTargetProcessHandle, _Outptr_ LPHANDLE lpTargetHandle, _In_ DWORD dwDesiredAccess, _In_ BOOL bInheritHandle, _In_ DWORD dwOptions);

typedef HANDLE(WINAPI* PEGetCurrentThread)(VOID);

typedef HANDLE(WINAPI* PEGetCurrentProcess)(VOID);

typedef BOOL(WINAPI* PETerminateThread)(_In_ HANDLE hThread, _In_ DWORD dwExitCode);

typedef DWORD(WINAPI *PEGetTempPathA)(DWORD nBufferLength, LPSTR lpBuffer);

typedef LPTOP_LEVEL_EXCEPTION_FILTER(WINAPI* PESetUnhandledExceptionFilter)(_In_opt_ LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);

typedef struct _SHELLWINDOWSINF
{
	HWND hWnd;
	HMENU Id;
}SHELLWINDOWSINF, *PSHELLWINDOWSINF;
typedef struct _Apier
{
	PEGetProcAddress GetProcAddress;
	PELoadLibraryExA LoadLibraryExA;
	PEGetModuleHandleW GetModuleHandleW;
	LPVIRTUALPROTECT VirtualProtect;
	PEVirtualFree VirtualFree;
	PEVirtualAlloc VirtualAlloc;

	PEDefWindowProcW DefWindowsProcW;
	PERegisterClassExW RegisterClassExW;
	PECreateWindowExW CreateWindowExW;
	PEShowWindow ShowWindow;
	PEUpdateWindow UpdateWindow;
	PEGetMessageW GetMessageW;
	PETranslateMessage TranslateMessage;
	PEDispatchMessageW DispatchMessageW;

	PEExitProcess ExitProcess;
	PEPostQuitMessage PostQuitMessage;
	PEDestroyWindow DestroyWindow;
	PEShellExecute ShellExecute;
	PESetPriorityClass SetPriorityClass;
	PESetThreadPriority SetThreadPriority;
	PEGetModuleFileNameA GetModuleFileNameA;
	PECreateFileA CreateFileA;
	PECreateFileW CreateFileW;
	PEWriteFile WriteFile;
	PECloseHandle CloseHandle;
	PEGetDlgItemTextA GetDlgItemTextA;
	PEGetLocalTime GetLocalTime;
	PEMessageBoxW MessageBoxW;
	PECreateThread CreateThread;
	PESleep Sleep;
	PEDuplicateHandle DuplicateHandle;
	PEGetCurrentThread GetCurrentThread;
	PEGetCurrentProcess GetCurrentProcess;
	PETerminateThread TerminateThread;
	PESetUnhandledExceptionFilter SetUnhandledExceptionFilter;
	PEGetTempPathA GetTempPathA;
	HMODULE ImageBase;
	PIMAGE_TLS_DIRECTORY pTLSDirectory;
	HWND ParentHwnd;
	SHELLWINDOWSINF ExeWindowsInf[3];
}Apier, *PApier;

