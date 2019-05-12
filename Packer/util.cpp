#include "windows.h"
#include "stdafx.h"
#include "util.h"
#include "string"

#define RB_TYPE "rb+"
#define INT_OFFSET 32

#define PE_MAGIC_WORD 0x5a4d
#define PE_SIGNATRUE 0x4550


int64_t getFileSize(HANDLE h_file) {
	ASSERT(h_file != INVALID_HANDLE_VALUE);

	if (h_file == INVALID_HANDLE_VALUE)
		return -1;

	DWORD dw_high = 0;
	DWORD dw_size = ::GetFileSize(h_file, &dw_high);
	if (dw_size == INVALID_FILE_SIZE && GetLastError() != NO_ERROR)
		return -1;
	__int64 size = ((int64_t)dw_high << INT_OFFSET) + dw_size;
	return size;
}

int64_t getFileSize(const char *path) {
	ASSERT(path != NULL);
	if (path == NULL)
		return -1;

	WIN32_FILE_ATTRIBUTE_DATA fileAttr;
	if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fileAttr))
		return -1;
	int64_t size = ((int64_t)fileAttr.nFileSizeHigh << INT_OFFSET) + fileAttr.nFileSizeLow;
	return size;
}


int CreateFileMemoryMap(const char *path, FileMapStruct &file_map_struct) {
	char *error_msg = NULL;

	ASSERT(path != NULL);
	if (path == NULL) {
		error_msg = "path is NULL";
		goto error;
	}
	
	file_map_struct.m_hFile = fopen(path, RB_TYPE);
	ASSERT(file_map_struct.m_hFile != NULL);
	if (file_map_struct.m_hFile == NULL) {
		error_msg = "fopen failed";
		goto error;;
	}

	file_map_struct.length = getFileSize(path);
	if (file_map_struct.length == -1) {
		error_msg = "file size return -1";
		goto error;
	}

	char *file_buf = new char[file_map_struct.length];
	ASSERT(file_buf != NULL);
	if (file_buf == NULL) {
		error_msg = "new failed";
		goto error;
	}

	size_t read_size = fread(file_buf, sizeof(char), file_map_struct.length, file_map_struct.m_hFile);
	ASSERT(read_size == file_map_struct.length);
	if (read_size != file_map_struct.length) {
		error_msg = "read failed";
		goto error;
	}

	file_map_struct.m_lpFileData = file_buf;
	return 0;

error:
	MessageBoxA(NULL, error_msg, "提示", MB_ICONERROR);
	return -1;
}


//TODO 增加判断只有exe文件
bool isPEFile(const char *buf) {
	ASSERT(buf != NULL);
	if (GET_DOS_HEADER(buf)->e_magic != PE_MAGIC_WORD)
	{
		AfxMessageBox("不是一个有效的PE文件");
		return false;
	}
	if (GET_NT_HEADER(buf)->Signature != 0x4550)
	{
		AfxMessageBox("不是一个有效的PE文件");
		return false;
	}
#ifdef _WIN64
	if (GET_NT_HEADER(buf)->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		AfxMessageBox("只支持64位exe程序加壳");
		return false;
	}
#else
	if (GET_NT_HEADER(buf)->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		AfxMessageBox("只支持32位exe程序加壳");
		return false;
	}
#endif
	return true;
}

//生成内存文件 不使用win32
bool CreateFileMapStruct(const  char*path, FileMapStruct & fileMapStruct)
{
	fileMapStruct.m_hFile = fopen(path, "rb+");
	if (fileMapStruct.m_hFile == NULL)
	{
		MessageBoxA(NULL, "文件打开失败!", "提示", MB_ICONERROR);
		return false;
	}
	fseek(fileMapStruct.m_hFile, 0, SEEK_END);
	fileMapStruct.length = ftell(fileMapStruct.m_hFile);
	fseek(fileMapStruct.m_hFile, 0, SEEK_SET);
	char *fileBuf = (char*)new char[fileMapStruct.length];
	fread(fileBuf, sizeof(char), fileMapStruct.length, fileMapStruct.m_hFile);
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
#ifdef _WIN64
	if (GET_NT_HEADER(fileData)->OptionalHeader.Magic != 0x10b)
	{
		AfxMessageBox("只支持64位exe程序加壳");
		return false;
	}
#else
	if (GET_NT_HEADER(fileData)->OptionalHeader.Magic != 0x10b)
	{
		AfxMessageBox("只支持32位exe程序加壳");
		return false;
	}
#endif // _WIN64

	return true;
}

int __cdecl ProgressCallBack(unsigned int insize, unsigned int inpos, unsigned int outpos, void * cbparam)
{
	//SendMessageA(g_hwnd, WM_UPDATE,inpos,insize);
	return 1;
}

void replaceStringA(std::string & path)
{
	int pos;
	while ((pos = path.find("\\")) != std::string::npos)
	{
		path[pos] = '/';
	}
}
