#pragma once

// PackerDlg.h : 头文件
//


#include "vector"
#include "info.h"
#include "afxcmn.h"

// Task 对话框
class Task 
{
	// 构造
public:
	Task();	// 标准构造函数
	~Task();
protected:
	
protected:
	void SetPEStruct(char *fileBuf, PEstruct &peStruct);
	DWORD RVA2FA(char * lpFileBuffer, int RVA);
	PVOID GetExpVarAddr(const char * strVarName);
	void StoreSectionInfo(char *bufFile, std::vector<MySecInfo*>&vec);
	DWORD Align(DWORD dwAlign, DWORD dwValue);
	MySecInfo * GetSecInfoByRVA(DWORD dwRVA, DWORD dwAlign, std::vector<MySecInfo*>& vec);
	DWORD GetTargetImageSize(std::vector<MySecInfo*>& vec);
	DWORD GetPressSize(std::vector<MySecInfo*>& vec);
	void CopyPressData(char * lpDest, char * lpSrc, std::vector<MySecInfo*>& vec);
	int CompressData(LPVOID lpSoure, LPVOID * lpOutDest, DWORD dwLength);
	void AddSec(char * lpSecName, DWORD dwFileSize, LPVOID lpFileData);
	
	void GetResRVA(char * lpFileData, DWORD & dwRVA, DWORD & dwSize);
	void FixRsrc(MySecInfo * lpResSecInfo);
	void SetPressDataDir();
	void ClearDataDir(char * lpFileData);
	void fixStubRelocation();
	
	
	
	void SetGlobalVar(DWORD dwPressSize);
	void SaveFile(const char *name);
	void CopyToTargetFile(DWORD dwAfterPressSize, MySecInfo * lpResSecInfo, DWORD dwTargetFileAlignment, DWORD & dwShell);
	void AddTargetSection(MySecInfo * lpResSecInfo, DWORD dwAfterPressSize);
	DWORD CopyToDestMemory(DWORD dwFileSize);

	static UINT ThreadCallBack(void *param);
public:
	void Start(const char * path);
	void Pack(const std::string &path);
	void SetDateAndPassword();
	LPVOID m_lpPressData;
	DWORD m_dwPressSize;
	std::vector<MySecInfo*> m_TargetSecVector;
	std::vector<MySecInfo*> m_ShellSecVector;
	std::vector<MySecInfo*> m_PressSecVector;
	PEstruct m_TargetPeTag; //被压缩的PE
	PEstruct m_ShellPeTag; //dll写的shell
	PEstruct m_PressPeTag; //生成的PE
	
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	HWND m_hwnd;
};
