#include "windows.h"
#include "stdafx.h"
#include "util.h"
#include "string"
 HWND g_hwnd;
//生成内存文件 不使用win32
bool CreateFileMapStruct(const  char*path,FileMapStruct & fileMapStruct)
{
	fileMapStruct.m_hFile = fopen(path,"rb+");
	fseek(fileMapStruct.m_hFile,0,SEEK_END);
	fileMapStruct.length = ftell(fileMapStruct.m_hFile);
	fseek(fileMapStruct.m_hFile, 0, SEEK_SET);
 	char *fileBuf = (char*)new char[fileMapStruct.length];
	fread(fileBuf,sizeof(char),fileMapStruct.length, fileMapStruct.m_hFile);
	fileMapStruct.m_lpFileData = fileBuf;
	fclose(fileMapStruct.m_hFile);
	return isPEEXE32(fileBuf);
}

bool isPEEXE32(const char *fileData)
{
	if (GET_DOS_HEADER(fileData)->e_magic != 0x5a4d)
	{
		AfxMessageBox("不是一个有效的PE文件");
		return false;
	}
	if (GET_NT_HEADER(fileData)->Signature != 0x4550)
	{
		AfxMessageBox("不是一个有效的PE文件");
		return false;
	}
	if (GET_NT_HEADER(fileData)->OptionalHeader.Magic != 0x10b)
	{
		AfxMessageBox("不是一个有效的PE文件");
		return false;
	}
	return true;
}

int __cdecl ProgressCallBack(unsigned int insize, unsigned int inpos, unsigned int outpos, void * cbparam)
{
	SendMessageA(g_hwnd, WM_UPDATE,inpos,insize);
	return 1;
}

void replaceStringA(std::string & path)
{
	int pos;
	while ((pos = path.find("\\"))!=std::string::npos)
	{
		path[pos]='/';
	}
}
