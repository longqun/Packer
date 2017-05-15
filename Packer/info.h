#pragma once
#include "windows.h"
#include "stdio.h"
#include "string"
#define GET_DOS_HEADER(x) ((PIMAGE_DOS_HEADER)(x))
#define GET_NT_HEADER(x) ((PIMAGE_NT_HEADERS)((DWORD)GET_DOS_HEADER(x)->e_lfanew + (DWORD)(x)))
#define GET_SECTION_HEADER(x) IMAGE_FIRST_SECTION(x)

struct FileMapStruct
{
public:
	FileMapStruct()
	{
		m_lpFileData = NULL;
		m_hFile = NULL;
		length = 0;
	}
public:
	DWORD length;
	char* m_lpFileData;
	FILE* m_hFile;
};


struct PEstruct
{
public:
	PEstruct()
	{
		m_lpDosHeader = NULL;
		m_lpNtHeader = NULL;
		m_lpSecHeader = NULL;
		m_lpBaseReloc = NULL;
		m_lpImport = NULL;
		m_lpThunkData = NULL;
		m_ImprotName = NULL;
	}
public:
	IMAGE_DOS_HEADER* m_lpDosHeader;
	IMAGE_NT_HEADERS* m_lpNtHeader;
	IMAGE_SECTION_HEADER* m_lpSecHeader;
	IMAGE_BASE_RELOCATION* m_lpBaseReloc;
	IMAGE_IMPORT_DESCRIPTOR* m_lpImport;
	IMAGE_THUNK_DATA* m_lpThunkData;
	IMAGE_IMPORT_BY_NAME* m_ImprotName;
	FileMapStruct m_FileMapTag;
};

struct MySecInfo
{
public:
	MySecInfo()
	{
		RtlZeroMemory(&m_SecHeader, sizeof(m_SecHeader));
		m_lpSecData = NULL;
		m_isNeedPress = true;
	}
	~MySecInfo()
	{
	}
public:
	IMAGE_SECTION_HEADER m_SecHeader;
	char* m_lpSecData;
	bool m_isNeedPress;
};

typedef struct _SectionNode
{
	//解压区段
	DWORD SizeOfRawData;
	DWORD SectionRva;
}SectionNode;

typedef struct _Password
{
	bool isSetPassword;
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

typedef struct _Info
{
	bool setPassword;
	std::string strPassword;
	bool setTime;
	MTime time;
}Info;
typedef struct _GlogalExternVar
{
	SectionNode mSectionNodeArray[16];
	//加壳的导入表地址
	DWORD dwIATVirtualAddress;
	//加壳的tls数据大小
	DWORD dwTLSSize;
	//加壳的tls虚拟地址 rva
	DWORD dwTLSVirtualAddress;
	//加壳的原始oep
	DWORD dwOrignalOEP;
	//重定位rva
	DWORD dwRelocationRva;

	DWORD dwBaseOfCode;

	DWORD dwOrignalImageBase;
	DWORD dwPressSize;

	Password mPassword;
	MTime mTime;
}GlogalExternVar;


typedef struct _TYPEOFFSET
{
	WORD offset : 12;			//偏移值
	WORD Type : 4;			//重定位属性(方式)
}TYPEOFFSET, *PTYPEOFFSET;

typedef struct _GlobalApplet
{
	//选择的文件
	std::string filePath;
	//设置密码相关属性
	Info info;
	//加载界面的窗口句柄
	HWND loadingHwnd;
	//是否加壳成功
	bool success;
}GlobalApplet;

//保存全局信息
extern GlobalApplet gApplet;

