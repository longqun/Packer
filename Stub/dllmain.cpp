// Dll.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "info.h"
#pragma comment(linker, "/MERGE:.data=.text")
#pragma comment(linker, "/MERGE:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE") 
#pragma comment(linker,"/ENTRY:MyMain")
#include "aplib.h"
#pragma comment(lib, "aplib.lib")

#ifndef IMAGE_SIZEOF_BASE_RELOCATION 
// Vista SDKs no longer define IMAGE_SIZEOF_BASE_RELOCATION!? 
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION)) 
#endif 
#define _DLL_SAMPLE
#ifdef __cplusplus
extern "C" {
#endif

#ifdef _DLL_SAMPLE
#define DLL_SAMPLE_API __declspec(dllexport)
#else
#define DLL_SAMPLE_API __declspec(dllimport)
#endif
	DLL_SAMPLE_API  GlogalExternVar g_globalVar;
#undef DLL_SAMPLE_API

#ifdef __cplusplus
}
#endif

#define APP_NAME_W L"Packer"

//打印日志位置，修改这个地方
#define LOG_PATH L"D:/log.txt"
//生成自动删除文件名称
#define DEL_BAT_NAME "del.bat"
#define NUM_STR "0123456789"
#define PING_STR "ping -n 3 127.0.0.1>nul \r\n"
#define DEL_STR "\r\ndel "

#define BUF_SIZE 2048
#define INT_NUM_SIZE 33


//是否开始反调试代码
#define ANTI_REVERSE 0
//默认打开日志
#define SUPPORT_LOG 1

#if SUPPORT_LOG
#define LOGGER_MESSAGE(fmt, ...) mprintf("%s %d "fmt" \r\n", __FILE__, __LINE__,  ##__VA_ARGS__);
#else
#define LOGGER_MESSAGE(fmt, ...) 
#endif

static Apier s_apier;
static HANDLE s_log_handle = INVALID_HANDLE_VALUE;

struct MemoryNode {
	DWORD len;
	char buf[0];
};

void *mmalloc(DWORD len)
{
	len == 0 ? 1 : len;
	MemoryNode *node = (MemoryNode *)s_apier.VirtualAlloc(NULL, len + sizeof(MemoryNode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!node)
		return NULL;
	node->len = len;
	return node->buf;
}

void mfree(void *ptr)
{
	if (!ptr)
		return;
	MemoryNode *node = (MemoryNode *)((char *)ptr - sizeof(DWORD));
	s_apier.VirtualFree((void *)node, node->len, MEM_DECOMMIT);
}

void *mymemcpy(void* _Dst,
	void const* _Src,
	size_t      _Size)
{
	void *orignal = _Dst;
	for (size_t i = 0; i < _Size; i++)
	{
		((char*)_Dst)[i] = ((char*)_Src)[i];
	}
	return orignal;
}

char *ccpy(char *dst, const char *src, size_t size)
{
	for (size_t i = 0; i < size; i++)
	{
		dst[i] = src[i];
	}
	return dst;
}

int sstrlen(const char *buf)
{
	int i = 0;
	while (buf[i] != 0)
	{
		i++;
	}
	return i;
}

void memsetZero(void *src, size_t length)
{
	for (size_t i = 0; i < length; i++)
	{
		((char*)src)[i] = 0;
	}
}

static IMAGE_NT_HEADERS  *getNtHeader(HMODULE hModule) {

	IMAGE_DOS_HEADER* lpDosHeader = (IMAGE_DOS_HEADER*)hModule;
	return (IMAGE_NT_HEADERS*)(lpDosHeader->e_lfanew + (DWORD)hModule);
}

static IMAGE_SECTION_HEADER *getImageSectionHeader(HMODULE hModule)
{
	IMAGE_DOS_HEADER* lpDosHeader = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_NT_HEADERS* lpNtHeader = (IMAGE_NT_HEADERS*)(lpDosHeader->e_lfanew + (DWORD)hModule);
	return (IMAGE_SECTION_HEADER*)((DWORD)hModule +
		lpDosHeader->e_lfanew + sizeof(lpNtHeader->Signature) +
		sizeof(lpNtHeader->FileHeader) +
		lpNtHeader->FileHeader.SizeOfOptionalHeader);
}


/*
	remember VirtualFree
*/
static char  *int_to_str(int val)
{
	int left = 0;
	int counter = 0;
	int temp = val;
	char *ret = (char *)mmalloc(INT_NUM_SIZE);
	if (ret == NULL) {
		return NULL;
	}

	if (val < 0) {
		ret[0] = '-';
		++left;
		++counter;
	}

	if (temp == 0)
		++counter;

	while (temp) {
		temp /= 10;
		++counter;
	}

	if (counter > (INT_NUM_SIZE - 1)) {
		s_apier.VirtualFree(ret, INT_NUM_SIZE, MEM_DECOMMIT);
		return NULL;
	}

	temp = counter;
	while (left < temp) {
		ret[temp - 1] = NUM_STR[val % (sizeof(NUM_STR) - 1)];
		val /= 10;
		--temp;
	}
	ret[counter] = '\0';
	return ret;
}

static void mprintf(const char *fmt, ...)
{
	if (s_log_handle == INVALID_HANDLE_VALUE || fmt == NULL)
		return;
	int start = 0;
	va_list list;

	va_start(list, fmt);

	while (fmt[start] != '\0') {
		if (fmt[start] == '%') {
			switch (fmt[start + 1])
			{
			case 's':
			case 'S':
			{
				char *str = va_arg(list, char *);
				s_apier.WriteFile(s_log_handle, str, sstrlen(str), NULL, NULL);
			}
			break;
			case 'd':
			case 'D':
			{
				int val = va_arg(list, int);
				char *str = int_to_str(val);
				if (str != NULL) {
					s_apier.WriteFile(s_log_handle, str, sstrlen(str), NULL, NULL);
					mfree(str);
				}
			}
			break;
			case 'c':
			case 'C':
			{
				char ch = va_arg(list, char);
				s_apier.WriteFile(s_log_handle, &ch, sizeof(ch), NULL, NULL);
			}
			break;
			default:
			{
				s_apier.WriteFile(s_log_handle, &fmt[start], sizeof(char) * 2, NULL, NULL);
			}
			break;
			}
			++start;
		}
		else {
			s_apier.WriteFile(s_log_handle, &fmt[start], sizeof(char), NULL, NULL);
		}
		++start;
	}
	va_end(list);
}



static void initFunction();

static DWORD isDebug()
{
	DWORD value = 0;
	//OD 无效
	_asm
	{
		mov   eax, fs:18h     // TEB Self指针
		mov   eax, [eax + 30h]  // PEB
		movzx eax, [eax + 2]    // PEB->BeingDebugged
		mov   value, eax
	}
	return value;
}


static LONG WINAPI MyUnhandledExceptionFilter(struct _EXCEPTION_POINTERS *pei)
{
	pei->ContextRecord->Eip += 2;
	return EXCEPTION_CONTINUE_EXECUTION;
}

static LONG WINAPI MyUnhandledExceptionFilter1(struct _EXCEPTION_POINTERS *pei)
{
	return EXCEPTION_CONTINUE_SEARCH;
}

static bool isDebug1()
{
	s_apier.SetUnhandledExceptionFilter(MyUnhandledExceptionFilter);
	_asm
	{
		xor eax, eax
		jmp eax
	}
	return false;
}


_declspec (thread) LPCTSTR g_strTLS = L"Stub TLS DATA";
static void WINAPI TlsCallBack(PVOID dwDllHandle, DWORD dwReason, PVOID pReserved)
{
	initFunction();
	//开始反调试默认关闭
#if ANTI_REVERSE
	if (isDebug1())
	{
		_asm
		{
			xor eax, eax
			jmp eax
		}
	}

	s_apier.SetUnhandledExceptionFilter(MyUnhandledExceptionFilter1);
#endif
	g_strTLS = L"go";
}

#ifdef _M_IX86
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")
#else
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#endif
//创建TLS段
EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB")
const
#else
#pragma data_seg (".CRT$XLB")
#endif
PIMAGE_TLS_CALLBACK _tls_callback[] = { TlsCallBack, 0 };
#pragma data_seg ()
#pragma const_seg ()



static DWORD GetKernel32Base()
{
	DWORD dwKernel32Addr = 0;
	_asm
	{
		pushad
		xor ecx, ecx
		mov eax, fs:[0x30]
		mov eax, [eax + 0xc]
		mov esi, [eax + 0x1c]
		next_module :
					mov eax, [esi + 0x8]
					mov edi, [esi + 0x20]
					mov esi, [esi]
					cmp[edi + 12 * 2], cx
					jnz next_module
					mov dwKernel32Addr, eax
					popad
	}
	return dwKernel32Addr;
}

static DWORD GetGPAFunAddr()
{
	DWORD dwAddrBase = GetKernel32Base();

	// 1. 获取DOS头、NT头
	PIMAGE_DOS_HEADER pDos_Header;
	PIMAGE_NT_HEADERS pNt_Header;
	pDos_Header = (PIMAGE_DOS_HEADER)dwAddrBase;
	pNt_Header = (PIMAGE_NT_HEADERS)(dwAddrBase + pDos_Header->e_lfanew);

	// 2. 获取导出表项
	PIMAGE_DATA_DIRECTORY   pDataDir;
	PIMAGE_EXPORT_DIRECTORY pExport;
	pDataDir = pNt_Header->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
	pExport = (PIMAGE_EXPORT_DIRECTORY)(dwAddrBase + pDataDir->VirtualAddress);

	// 3. 获取导出表详细信息
	PDWORD pAddrOfFun = (PDWORD)(pExport->AddressOfFunctions + dwAddrBase);
	PDWORD pAddrOfNames = (PDWORD)(pExport->AddressOfNames + dwAddrBase);
	PWORD  pAddrOfOrdinals = (PWORD)(pExport->AddressOfNameOrdinals + dwAddrBase);

	// 4. 处理以函数名查找函数地址的请求，循环获取ENT中的函数名，并与传入值对比对，如能匹配上
	//    则在EAT中以指定序号作为索引，并取出其地址值。
	DWORD dwFunAddr = 0;
	for (DWORD i = 0; i < pExport->NumberOfNames; i++)
	{
		PCHAR lpFunName = (PCHAR)(pAddrOfNames[i] + dwAddrBase);
		if (strcmp(lpFunName, "GetProcAddress") == 0)
		{
			dwFunAddr = pAddrOfFun[pAddrOfOrdinals[i]] + dwAddrBase;
			return dwFunAddr;
		}
		if (i == pExport->NumberOfNames - 1)
			return 0;
	}
	return dwFunAddr;
}

/*
	初始化必要的函数信息
*/
void initFunction()
{
	HMODULE hKernel32 = (HMODULE)GetKernel32Base();
	s_apier.GetProcAddress = (PEGetProcAddress)GetGPAFunAddr();
	s_apier.LoadLibraryExA = (PELoadLibraryExA)s_apier.GetProcAddress((HMODULE)hKernel32, "LoadLibraryExA");
	s_apier.GetModuleHandleW = (PEGetModuleHandleW)s_apier.GetProcAddress((HMODULE)hKernel32, "GetModuleHandleW");
	s_apier.VirtualProtect = (LPVIRTUALPROTECT)s_apier.GetProcAddress((HMODULE)hKernel32, "VirtualProtect");
	s_apier.VirtualFree = (PEVirtualFree)s_apier.GetProcAddress((HMODULE)hKernel32, "VirtualFree");
	s_apier.VirtualAlloc = (PEVirtualAlloc)s_apier.GetProcAddress((HMODULE)hKernel32, "VirtualAlloc");
	s_apier.GetTempPathA = (PEGetTempPathA)s_apier.GetProcAddress((HMODULE)hKernel32, "GetTempPathA");

	HMODULE hUser32 = s_apier.LoadLibraryExA("user32.dll", NULL, 0);
	HMODULE hShell32 = s_apier.LoadLibraryExA("Shell32.dll", NULL, 0);
	s_apier.DefWindowsProcW = (PEDefWindowProcW)s_apier.GetProcAddress(hUser32, "DefWindowProcW");
	s_apier.RegisterClassExW = (PERegisterClassExW)s_apier.GetProcAddress(hUser32, "RegisterClassExW");
	s_apier.CreateWindowExW = (PECreateWindowExW)s_apier.GetProcAddress(hUser32, "CreateWindowExW");
	s_apier.ShowWindow = (PEShowWindow)s_apier.GetProcAddress(hUser32, "ShowWindow");
	s_apier.UpdateWindow = (PEUpdateWindow)s_apier.GetProcAddress(hUser32, "UpdateWindow");
	s_apier.GetMessageW = (PEGetMessageW)s_apier.GetProcAddress(hUser32, "GetMessageW");
	s_apier.TranslateMessage = (PETranslateMessage)s_apier.GetProcAddress(hUser32, "TranslateMessage");
	s_apier.DispatchMessageW = (PEDispatchMessageW)s_apier.GetProcAddress(hUser32, "DispatchMessageW");
	s_apier.ImageBase = (DWORD)s_apier.GetModuleHandleW(NULL);
	s_apier.PostQuitMessage = (PEPostQuitMessage)s_apier.GetProcAddress(hUser32, "PostQuitMessage");
	s_apier.ExitProcess = (PEExitProcess)s_apier.GetProcAddress((HMODULE)hKernel32, "ExitProcess");
	s_apier.DestroyWindow = (PEDestroyWindow)s_apier.GetProcAddress(hUser32, "DestroyWindow");
	s_apier.ShellExecute = (PEShellExecute)s_apier.GetProcAddress(hShell32, "ShellExecuteA");

	s_apier.SetPriorityClass = (PESetPriorityClass)s_apier.GetProcAddress((HMODULE)hKernel32, "SetPriorityClass");
	s_apier.SetThreadPriority = (PESetThreadPriority)s_apier.GetProcAddress((HMODULE)hKernel32, "SetThreadPriority");
	s_apier.GetModuleFileNameA = (PEGetModuleFileNameA)s_apier.GetProcAddress((HMODULE)hKernel32, "GetModuleFileNameA");

	s_apier.CreateFileA = (PECreateFileA)s_apier.GetProcAddress((HMODULE)hKernel32, "CreateFileA");
	s_apier.CreateFileW = (PECreateFileW)s_apier.GetProcAddress((HMODULE)hKernel32, "CreateFileW");
	s_apier.WriteFile = (PEWriteFile)s_apier.GetProcAddress((HMODULE)hKernel32, "WriteFile");
	s_apier.CloseHandle = (PECloseHandle)s_apier.GetProcAddress((HMODULE)hKernel32, "CloseHandle");
	s_apier.GetDlgItemTextA = (PEGetDlgItemTextA)s_apier.GetProcAddress(hUser32, "GetDlgItemTextA");
	s_apier.GetLocalTime = (PEGetLocalTime)s_apier.GetProcAddress((HMODULE)hKernel32, "GetLocalTime");
	s_apier.MessageBoxW = (PEMessageBoxW)s_apier.GetProcAddress(hUser32, "MessageBoxW");
	s_apier.CreateThread = (PECreateThread)s_apier.GetProcAddress(hKernel32, "CreateThread");
	s_apier.Sleep = (PESleep)s_apier.GetProcAddress(hKernel32, "Sleep");
	s_apier.DuplicateHandle = (PEDuplicateHandle)s_apier.GetProcAddress(hKernel32, "DuplicateHandle");
	s_apier.GetCurrentProcess = (PEGetCurrentProcess)s_apier.GetProcAddress(hKernel32, "GetCurrentProcess");
	s_apier.GetCurrentThread = (PEGetCurrentThread)s_apier.GetProcAddress(hKernel32, "GetCurrentThread");
	s_apier.TerminateThread = (PETerminateThread)s_apier.GetProcAddress(hKernel32, "TerminateThread");
	s_apier.SetUnhandledExceptionFilter = (PESetUnhandledExceptionFilter)s_apier.GetProcAddress(hKernel32, "SetUnhandledExceptionFilter");
	IMAGE_DOS_HEADER* lpDosHeader = (IMAGE_DOS_HEADER*)s_apier.ImageBase;
	IMAGE_NT_HEADERS* lpNtHeader = (IMAGE_NT_HEADERS*)(lpDosHeader->e_lfanew + (DWORD)s_apier.ImageBase);
	//rva
	s_apier.pTLSDirectory = (PIMAGE_TLS_DIRECTORY)(lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress + s_apier.ImageBase);

	s_log_handle = s_apier.CreateFileW(LOG_PATH, FILE_APPEND_DATA, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}





/*
	获取当前运行的进程地址
*/

static char *getExePath()
{
	char *buf = (char *)mmalloc(BUF_SIZE);
	if (!buf)
		return NULL;

	DWORD len = s_apier.GetModuleFileNameA(NULL, buf, BUF_SIZE);

	if (len >= BUF_SIZE) {
		mfree(buf);
		return NULL;
	}
	return buf;
}

/*
	生成临时bat文件字符串,使用mfree删除
*/
static char *getTempDelBatFilePath()
{
	DWORD path_len = s_apier.GetTempPathA(0, NULL);
	if (path_len == 0)
		return NULL;
	//temp_path + / + del.bat    sizeof(DEL_BAT_NAME) = 8
	path_len += sizeof(DEL_BAT_NAME) + 1;

	char *temp_file_path = (char *)mmalloc(path_len);
	if (!temp_file_path)
		return NULL;

	DWORD len = s_apier.GetTempPathA(path_len, temp_file_path);
	if (len == 0 || len >= path_len) {
		goto out;
	}

	if (temp_file_path[len - 1] != '\\' && temp_file_path[len - 1] == '/') {
		//没有以/ \结尾的时候处理一下
		temp_file_path[len++] = '/';
	}

	if (len + sizeof(DEL_BAT_NAME) > path_len)
		goto out;

	for (DWORD i = 0; i < sizeof(DEL_BAT_NAME); ++i) {
		temp_file_path[len++] = DEL_BAT_NAME[i];
	}

	return temp_file_path;
out:
	mfree(temp_file_path);
	return NULL;
}

/*
自删除逻辑
ping -n 3 127.0.0.1>nul
del  E:\code\2017\Shell\Win32Project1\Debug\Win32Project1.exe
del *.bat
*/
static int deleteSelf()
{
	int ret = 0;
	char *exe_path = NULL, *file_path = NULL;
	file_path = getTempDelBatFilePath();
	if (!file_path) {
		ret = -1;
		LOGGER_MESSAGE("build temp file path failed");
		goto out;
	}

	exe_path = getExePath();
	if (!exe_path) {
		ret = -1;
		LOGGER_MESSAGE("get exe path failed");
		goto out;
	}

	LOGGER_MESSAGE("temp path is %s", file_path);


	HANDLE bat_handle = s_apier.CreateFileA(file_path, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (bat_handle == INVALID_HANDLE_VALUE) {
		ret = -1;
		LOGGER_MESSAGE("Create temp file failed %s", file_path);
		goto out;
	}

	s_apier.WriteFile(bat_handle, PING_STR, sizeof(PING_STR) - 1, NULL, NULL);
	s_apier.WriteFile(bat_handle, DEL_STR, sizeof(DEL_STR) - 1, NULL, NULL);
	s_apier.WriteFile(bat_handle, exe_path, sstrlen(exe_path), NULL, NULL);
	s_apier.WriteFile(bat_handle, DEL_STR, sizeof(DEL_STR) - 1, NULL, NULL);
	s_apier.WriteFile(bat_handle, file_path, sstrlen(file_path), NULL, NULL);
	s_apier.CloseHandle(bat_handle);
	s_apier.ShellExecute(NULL, "open", file_path, NULL, NULL, SW_HIDE);

out:
	if (exe_path)
		mfree(exe_path);
	if (file_path)
		mfree(file_path);
	return ret;
}


/*
IMAGE_TLS_DIRECTORY中的地址就是虚拟地址直接用
*/
static void InitTLS(PIMAGE_TLS_DIRECTORY pFileTls, PIMAGE_TLS_DIRECTORY pStubTls)
{
	pStubTls->AddressOfIndex = pFileTls->AddressOfIndex;
	pStubTls->Alignment = pFileTls->Alignment;
	pStubTls->Characteristics = pFileTls->Characteristics;
	pStubTls->EndAddressOfRawData = pFileTls->EndAddressOfRawData;
	pStubTls->Reserved0 = pFileTls->Reserved0;
	pStubTls->Reserved1 = pFileTls->Reserved1;
	pStubTls->SizeOfZeroFill = pFileTls->SizeOfZeroFill;
	pStubTls->StartAddressOfRawData = pFileTls->StartAddressOfRawData;

	PIMAGE_TLS_CALLBACK* pTlsCallBack = (PIMAGE_TLS_CALLBACK*)pFileTls->AddressOfCallBacks;
	PIMAGE_TLS_CALLBACK* pStubCallBack = (PIMAGE_TLS_CALLBACK*)pStubTls->AddressOfCallBacks;
	if (pTlsCallBack && pStubCallBack)
	{
		if (!*pTlsCallBack)
		{
			*pStubCallBack = 0;
			return;
		}
		while (pTlsCallBack && *pTlsCallBack)
		{
			(*pTlsCallBack)((PVOID)s_apier.ImageBase, DLL_PROCESS_ATTACH, 0);
			*pStubCallBack = *pTlsCallBack;
			pStubCallBack++;
			pTlsCallBack++;
		}
	}
}

static int recoverIAT()
{
	LPVOID lpImageBase;
	IMAGE_NT_HEADERS* lpNtHeader;
	IMAGE_IMPORT_DESCRIPTOR* lpImportTable;

	HMODULE hModule = s_apier.GetModuleHandleW(NULL);
	if (hModule == NULL) {
		LOGGER_MESSAGE("GetModuleHandle failed");
		return -1;
	}

	lpNtHeader = getNtHeader(hModule);
	if (lpNtHeader == NULL) {
		LOGGER_MESSAGE("getNtHeader failed");
		return -1;
	}
	lpImageBase = (LPVOID)lpNtHeader->OptionalHeader.ImageBase;

	if (lpImageBase == NULL) {
		LOGGER_MESSAGE("imagebase == NULL");
		return -1;
	}

	//导入表处理
	lpImportTable = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD)lpImageBase + g_globalVar.dwIATVirtualAddress);

	while (lpImportTable && lpImportTable->Name)
	{
		DWORD* lpIAT;
		IMAGE_THUNK_DATA* lpThunkData;
		HMODULE hDll = s_apier.LoadLibraryExA((char*)(lpImportTable->Name + (DWORD)lpImageBase), NULL, 0);

		if (!hDll || lpImportTable->OriginalFirstThunk == 0 || lpImportTable->FirstThunk == 0)
		{
			lpImportTable++;
			continue;
		}

		//需要将函数地址写入的地方
		lpIAT = (DWORD*)(lpImportTable->FirstThunk + (DWORD)lpImageBase);
		lpThunkData = (IMAGE_THUNK_DATA*)((DWORD)lpImageBase + lpImportTable->OriginalFirstThunk);

		while (lpThunkData->u1.Ordinal != 0)
		{
			DWORD funName;
			DWORD dwOldProtect;
			//名字导出
			if ((lpThunkData->u1.Ordinal & 0x80000000) == 0)
			{
				IMAGE_IMPORT_BY_NAME* lpImprotName = (IMAGE_IMPORT_BY_NAME*)((DWORD)lpImageBase + lpThunkData->u1.Ordinal);
				funName = (DWORD)&(lpImprotName->Name);
			}
			else
			{
				funName = lpThunkData->u1.Ordinal & 0xffff;
			}

			s_apier.VirtualProtect(lpIAT, sizeof(void *), PAGE_EXECUTE_READWRITE, &dwOldProtect);
			*(lpIAT) = (DWORD)s_apier.GetProcAddress(hDll, (char*)funName);
			s_apier.VirtualProtect(lpIAT, sizeof(void *), dwOldProtect, NULL);
			lpIAT++;
			lpThunkData++;
		}
		lpImportTable++;
	}
	return 0;
}

typedef struct _TYPEOFFSET
{
	WORD offset : 12;			//偏移值
	WORD Type : 4;			//重定位属性(方式)
}TYPEOFFSET, *PTYPEOFFSET;

//修复原始重定位表
/*
【基址重定位位于数据目录表的第六项，共8 + N字节】
typedef struct _IMAGE_BASE_RELOCATION
{
	DWORD VirtualAddress; //重定位数据开始的RVA 地址
	DWORD SizeOfBlock;	  //重定位块得长度，标识重定向字段个数
	//WORD TypeOffset;      //重定项位数组相对虚拟RVA, 个数动态分配
}IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;

*/

int fixRelocation()
{
	DWORD dwImageBase;
	PIMAGE_BASE_RELOCATION	pReloc;

	if (g_globalVar.dwRelocationRva == 0)
		return 0;

	dwImageBase = (DWORD)s_apier.GetModuleHandleW(NULL);
	if (dwImageBase == NULL) {
		LOGGER_MESSAGE("GetModuleHandleW failed");
		return -1;
	}

	pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)dwImageBase + g_globalVar.dwRelocationRva);
	while (pReloc->VirtualAddress)
	{
		PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pReloc + 1);
		DWORD dwNumber = (pReloc->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2;
		for (size_t i = 0; i < dwNumber; i++)
		{
			if (*(PWORD)(&pTypeOffset[i]) == 0)
			{
				break;
			}
			DWORD dwRVA = pTypeOffset[i].offset + pReloc->VirtualAddress;
			DWORD dwAddressOfReloc = *(PDWORD)(dwImageBase + dwRVA);

			//设置修复后的重定向数据
			*(PDWORD)((DWORD)dwImageBase + dwRVA) = dwAddressOfReloc - g_globalVar.dwOrignalImageBase + dwImageBase;
		}
		pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pReloc + pReloc->SizeOfBlock);
	}
	return 0;
}



int decompress()
{
	int i = 0;
	char* lpPacked, *lpBuffer;			//压缩位置， 解压buf
	DWORD dwPackedSize, dwOutSize, distance = 0;;		//压缩大小， 解压大小 , 需要拷贝的偏移
	IMAGE_SECTION_HEADER *lpSecHeader;


	HMODULE hModule = s_apier.GetModuleHandleW(NULL);
	if (!hModule) {
		LOGGER_MESSAGE("GetModuleHandle Failed");
		return -1;
	}

	lpSecHeader = getImageSectionHeader(hModule);
	if (!lpSecHeader) {
		LOGGER_MESSAGE("getImageSectionHeader failed");
		return -1;
	}

	dwPackedSize = lpSecHeader->Misc.VirtualSize;

	//压缩的数据都放在第一个section
	lpPacked = ((char*)hModule + lpSecHeader->VirtualAddress);
	dwPackedSize = aPsafe_get_orig_size(lpPacked);


	//压缩和解压大小不一致
	if (g_globalVar.dwPressSize != dwPackedSize) {
		LOGGER_MESSAGE("compress size %d != packedsize %d", g_globalVar.dwPressSize, dwPackedSize);
		return -1;
	}

	lpBuffer = (char*)s_apier.VirtualAlloc(NULL, dwPackedSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpBuffer) {
		LOGGER_MESSAGE("alloc memory failed");
		return -1;
	}

	dwOutSize = aPsafe_depack(lpPacked, lpSecHeader->SizeOfRawData, lpBuffer, dwPackedSize);


	while (g_globalVar.mSectionNodeArray[i].SectionRva != 0 && i < MAX_SECTION_SIZE)
	{
		mymemcpy((void*)(s_apier.ImageBase + g_globalVar.mSectionNodeArray[i].SectionRva), lpBuffer + distance, g_globalVar.mSectionNodeArray[i].SizeOfRawData);
		distance += g_globalVar.mSectionNodeArray[i].SizeOfRawData;
		i++;
	}
	s_apier.VirtualFree(lpBuffer, dwPackedSize, MEM_DECOMMIT);
	return dwOutSize;
}

bool isPasswordCorrect(char *dest, char *src)
{
	if (dest == NULL || src == NULL)
		return false;

	int destLength = sstrlen(dest);
	int srcLength = sstrlen(src);
	if (destLength != srcLength)
		return false;
	for (int i = 0; i < destLength; i++)
	{
		if (dest[i] != src[i])
			return false;
	}
	return true;
}

void createWindowButton()
{
	s_apier.ExeWindowsInf[0].hWnd = s_apier.CreateWindowExW
	(WS_EX_TOPMOST, L"edit", NULL, WS_CHILD | WS_VISIBLE
		| WS_BORDER | ES_PASSWORD, 60, 29, 170, 22, s_apier.ParentHwnd, (HMENU)0
		, (HINSTANCE)s_apier.ImageBase, NULL);
	s_apier.ExeWindowsInf[1].hWnd = s_apier.CreateWindowExW
	(NULL, L"button", L"登录", WS_CHILD | WS_VISIBLE
		, 60, 80, 60, 30, s_apier.ParentHwnd, (HMENU)1, (HINSTANCE)s_apier.ImageBase, NULL);
	s_apier.ExeWindowsInf[2].hWnd = s_apier.CreateWindowExW
	(NULL, L"button", L"取消", WS_CHILD | WS_VISIBLE
		, 140, 80, 60, 30, s_apier.ParentHwnd, (HMENU)2, (HINSTANCE)s_apier.ImageBase, NULL);
}

LRESULT CALLBACK WinProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_CREATE:
		//createWindowButton();
		break;
	case  WM_COMMAND:
	{
		if ((1 == (0xFF & wParam)))
		{

			char buf[BUF_SIZE];
			int len = s_apier.GetDlgItemTextA(s_apier.ParentHwnd, 0, buf, BUF_SIZE);
			if (len == 0) {
				LOGGER_MESSAGE("input text invalid");
				break;
			}

			if (isPasswordCorrect(g_globalVar.mPassword.password, buf))
			{
				s_apier.DestroyWindow(s_apier.ParentHwnd);
				s_apier.PostQuitMessage(0);
			}
		}
		else if ((2 == (0xFF & wParam)))
		{
			s_apier.ExitProcess(0);
			return 0;
		}
	}
	break;
	case WM_CLOSE:
	{
		s_apier.ExitProcess(0);
		return 0;
	}
	break;
	case WM_GETMINMAXINFO:
		return 0;
	default:
		break;
	}
	return s_apier.DefWindowsProcW(hWnd, message, wParam, lParam);
}

void checkPassword()
{
	MSG msg;
	BOOL bRet;
	HWND hwnd;
	WNDCLASSEXW wcex;
	wcex.cbSize = sizeof(WNDCLASSEX);
	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = WinProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = (HINSTANCE)s_apier.ImageBase;
	wcex.hIcon = NULL;
	wcex.hCursor = NULL;
	wcex.hbrBackground = NULL;
	wcex.lpszMenuName = L"password";
	wcex.lpszClassName = L"password";
	wcex.hIconSm = NULL;

	s_apier.RegisterClassExW(&wcex);
	hwnd = s_apier.CreateWindowExW(NULL, L"password", L"输入试用密码", WS_OVERLAPPED | WS_CAPTION | WS_MINIMIZEBOX, 300, 200, 300, 180, NULL, NULL, (HINSTANCE)s_apier.ImageBase, NULL);
	s_apier.ParentHwnd = hwnd;
	if (!hwnd)
		return;
	createWindowButton();
	s_apier.ShowWindow(hwnd, SW_SHOWNORMAL);
	s_apier.UpdateWindow(hwnd);

	while ((bRet = s_apier.GetMessageW(&msg, NULL, 0, 0)) != 0)
	{
		if (bRet == -1)
			break;
		s_apier.TranslateMessage(&msg);
		s_apier.DispatchMessageW(&msg);
	}
}

bool isTimeout()
{
	SYSTEMTIME systemTime;
	s_apier.GetLocalTime(&systemTime);
	if (g_globalVar.mTime.year < systemTime.wYear)
		return true;
	if (g_globalVar.mTime.year > systemTime.wYear)
		return false;

	if (g_globalVar.mTime.month < systemTime.wMonth)
		return true;
	if (g_globalVar.mTime.month > systemTime.wMonth)
		return false;

	if (g_globalVar.mTime.day < systemTime.wDay)
		return true;
	if (g_globalVar.mTime.day > systemTime.wDay)
		return false;

	if (g_globalVar.mTime.hour < systemTime.wHour)
		return true;
	if (g_globalVar.mTime.hour > systemTime.wHour)
		return false;

	if (g_globalVar.mTime.minute < systemTime.wMinute)
		return true;
	if (g_globalVar.mTime.minute > systemTime.wMinute)
		return false;
	if (g_globalVar.mTime.second < systemTime.wSecond)
		return true;
	if (g_globalVar.mTime.second > systemTime.wSecond)
		return false;

	return true;
}

DWORD WINAPI ThreadFun(LPVOID pM)
{

	HANDLE parentThread = pM;
	while (true)
	{
		if (isTimeout())
		{
			s_apier.MessageBoxW(NULL, L"超过使用期限即将删除!", L"Packer", MB_ICONERROR);
			//s_apier.TerminateThread(parentThread, 0);
			deleteSelf();
			s_apier.ExitProcess(-1);
		}
		s_apier.Sleep(5000);
	}
	return 0;
}


static DWORD go;
void __declspec(naked)  MyMain()
{
	__asm pushad
	__asm pushfd
	//解压数据

	LOGGER_MESSAGE("start");
	if (decompress() < 0) {
		LOGGER_MESSAGE("decompress error");
		goto failed;
	}

	LOGGER_MESSAGE("after decompress");

	//修复重定向
	if (fixRelocation() < 0) {
		LOGGER_MESSAGE("fixRelocation failed");
		goto failed;
	}

	LOGGER_MESSAGE("after relocation");

	//检测密码
	if (g_globalVar.mPassword.setPassword)
		checkPassword();

	//是否有限制时间
	if (g_globalVar.mTime.setTime)
	{
		HANDLE hThread;

		s_apier.DuplicateHandle(s_apier.GetCurrentProcess(), s_apier.GetCurrentThread(), s_apier.GetCurrentProcess(), &hThread, 0, FALSE, DUPLICATE_SAME_ACCESS);
		s_apier.CreateThread(NULL, 0, ThreadFun, hThread, 0, NULL);
	}

	//恢复IAT
	recoverIAT();

	LOGGER_MESSAGE("after RecoverIAT");

	//看是否有TLS函数 如果有 则调用  
	if (g_globalVar.dwTLSVirtualAddress != 0)
		InitTLS((PIMAGE_TLS_DIRECTORY)(g_globalVar.dwTLSVirtualAddress + s_apier.ImageBase), s_apier.pTLSDirectory);

	LOGGER_MESSAGE("after InitTLS");

	//转交控制权
	go = g_globalVar.dwOrignalOEP + s_apier.ImageBase;

	LOGGER_MESSAGE("end");
	__asm popfd;
	__asm popad;
	__asm jmp go;

failed:
	s_apier.MessageBoxW(NULL, L"Error happend", APP_NAME_W, 0);
	s_apier.ExitProcess(-1);

}
