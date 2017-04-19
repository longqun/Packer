
// PackerDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "Packer.h"
#include "Task.h"
#include "afxdialogex.h"
#include "util.h"
#include "vector"
#include "aplib.h"
#pragma comment(lib, "aplib.lib")
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


GlogalExternVar *g_GlobalExternVar;


Task::Task(HWND  hwnd)
{
	m_hwnd= hwnd;
}

Task::~Task()
{
	for (auto temp = m_TargetSecVector.begin(); temp != m_TargetSecVector.end(); temp++)
	{
		if (*temp != NULL)
		{
			delete [](*temp)->m_lpSecData;
			(*temp)->m_lpSecData = NULL;
		}
		delete *temp;
	}
	for (auto temp = m_ShellSecVector.begin(); temp != m_ShellSecVector.end(); temp++)
	{
		if (*temp != NULL)
		{
			delete [](*temp)->m_lpSecData;
			(*temp)->m_lpSecData = NULL;
		}
		delete *temp;
	}

	for (auto temp = m_PressSecVector.begin(); temp != m_PressSecVector.end(); temp++)
	{
		if(*temp != NULL)
		{
			delete [](*temp)->m_lpSecData;
			(*temp)->m_lpSecData = NULL;
		}
		delete *temp;
	}
	if (m_lpPressData != NULL)
		delete []m_lpPressData;
	if (m_TargetPeTag.m_FileMapTag.m_lpFileData != NULL)
		delete []m_TargetPeTag.m_FileMapTag.m_lpFileData;
	if (m_PressPeTag.m_FileMapTag.m_lpFileData != NULL)
		delete[]m_PressPeTag.m_FileMapTag.m_lpFileData;
	if(m_ShellPeTag.m_FileMapTag.m_lpFileData!=NULL)
		delete []m_ShellPeTag.m_FileMapTag.m_lpFileData;
}

void Task::SetPEStruct(char *fileBuf, PEstruct &peStruct)
{
	peStruct.m_lpDosHeader = GET_DOS_HEADER(fileBuf);
	peStruct.m_lpNtHeader = GET_NT_HEADER(fileBuf);
	peStruct.m_lpSecHeader = GET_SECTION_HEADER(peStruct.m_lpNtHeader);
}

DWORD Task::RVA2FA(char* lpFileBuffer, int RVA)
{
	PEstruct thePEStruct;
	thePEStruct.m_lpDosHeader = (IMAGE_DOS_HEADER*)lpFileBuffer;
	thePEStruct.m_lpNtHeader = (IMAGE_NT_HEADERS*)(thePEStruct.m_lpDosHeader->e_lfanew + (DWORD)lpFileBuffer);

	int nSecCount = thePEStruct.m_lpNtHeader->FileHeader.NumberOfSections;
	int nOptionalHeaderSize = thePEStruct.m_lpNtHeader->FileHeader.SizeOfOptionalHeader;
	//节区偏移等于doshead + stub + sizeof(Signature) + sizeof(IMAGE_FILE_HEADER) + nOptionalHeaderSize
	int nSecOffset = thePEStruct.m_lpDosHeader->e_lfanew + \
		sizeof(thePEStruct.m_lpNtHeader->Signature) + \
		sizeof(IMAGE_FILE_HEADER) + \
		nOptionalHeaderSize;

	int VirtualAddress = 0;
	int VirtualSize = 0;
	int leftsize = 0;
	int nSectionAlign = thePEStruct.m_lpNtHeader->OptionalHeader.SectionAlignment;
	thePEStruct.m_lpSecHeader = (IMAGE_SECTION_HEADER*)(nSecOffset + lpFileBuffer);
	for (int n = 0; nSecCount > 0; nSecCount--)
	{
		VirtualAddress = thePEStruct.m_lpSecHeader->VirtualAddress;
		VirtualSize = thePEStruct.m_lpSecHeader->Misc.VirtualSize;
		int leftsize = VirtualSize % nSectionAlign;
		if (leftsize != 0)
		{
			leftsize = nSectionAlign - leftsize;
		}
		VirtualSize += leftsize;
		if (RVA < VirtualAddress + VirtualSize)
		{
			break;
		}
		thePEStruct.m_lpSecHeader++;
	}
	if (nSecCount == 0)
	{
		return 0;
	}
	DWORD FA = RVA - VirtualAddress + thePEStruct.m_lpSecHeader->PointerToRawData;
	if (FA > thePEStruct.m_lpSecHeader->PointerToRawData + thePEStruct.m_lpSecHeader->SizeOfRawData)
	{
		return 0;
	}
	return FA;
}

PVOID Task::GetExpVarAddr(const char * strVarName)
{
	PIMAGE_EXPORT_DIRECTORY lpExport = (PIMAGE_EXPORT_DIRECTORY)(m_ShellPeTag.m_FileMapTag.m_lpFileData + RVA2FA(m_ShellPeTag.m_FileMapTag.m_lpFileData, (m_ShellPeTag.m_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)));

	// 2、循环读取导出表输出项的输出函数，并依次与szVarName做比对，如果相同，则取出相对应的函数地址
	for (DWORD i = 0; i < lpExport->NumberOfNames; i++)
	{
		PDWORD pNameAddr = (PDWORD)(m_ShellPeTag.m_FileMapTag.m_lpFileData + RVA2FA(m_ShellPeTag.m_FileMapTag.m_lpFileData, lpExport->AddressOfNames));
		PCHAR strTempName = (PCHAR)(m_ShellPeTag.m_FileMapTag.m_lpFileData + RVA2FA(m_ShellPeTag.m_FileMapTag.m_lpFileData, pNameAddr[i]));
		if (!strcmp(strVarName, strTempName))
		{
			PDWORD pFunAddr = (PDWORD)(m_ShellPeTag.m_FileMapTag.m_lpFileData + RVA2FA(m_ShellPeTag.m_FileMapTag.m_lpFileData, lpExport->AddressOfFunctions));
			return (PVOID)(m_ShellPeTag.m_FileMapTag.m_lpFileData + RVA2FA(m_ShellPeTag.m_FileMapTag.m_lpFileData, pFunAddr[i]));
		}
	}
	return 0;
}

void Task::StoreSectionInfo(char *bufFile, std::vector<MySecInfo*>&vec)
{
	IMAGE_NT_HEADERS* pImageNtHeader = GET_NT_HEADER(bufFile);
	PIMAGE_SECTION_HEADER pImageSectionHeader = GET_SECTION_HEADER(pImageNtHeader);
	DWORD nCount = pImageNtHeader->FileHeader.NumberOfSections;
	for (int i = 0; i < nCount; i++)
	{
		MySecInfo *lpSecInfo = new MySecInfo;
		lpSecInfo->m_SecHeader = *pImageSectionHeader;
		lpSecInfo->m_lpSecData = new char[pImageSectionHeader->SizeOfRawData];
		memcpy(lpSecInfo->m_lpSecData, pImageSectionHeader->PointerToRawData + bufFile, pImageSectionHeader->SizeOfRawData);
		vec.push_back(lpSecInfo);
		pImageSectionHeader++;
	}
}

DWORD Task::Align(DWORD dwAlign, DWORD dwValue)
{
	DWORD dwLeft = 0;

	if (dwValue % dwAlign != 0)
	{
		dwLeft = dwAlign - dwValue % dwAlign;
	}
	return dwValue + dwLeft;
}

MySecInfo* Task::GetSecInfoByRVA(DWORD dwRVA, DWORD dwAlign, std::vector<MySecInfo*>&vec)
{
	std::vector<MySecInfo*>::iterator it = vec.begin();
	while (it != vec.end())
	{
		if (dwRVA < Align(dwAlign, (*it)->m_SecHeader.Misc.VirtualSize) + (*it)->m_SecHeader.VirtualAddress
			&& dwRVA >= (*it)->m_SecHeader.VirtualAddress)
		{
			return (*it);
		}
		it++;
	}
	return NULL;
}

DWORD Task::GetTargetImageSize(std::vector<MySecInfo*>&vec)
{
	DWORD dwImageSize = 0;
	std::vector<MySecInfo*>::iterator it = vec.begin();
	while (it != vec.end())
	{
		dwImageSize += Align(m_TargetPeTag.m_lpNtHeader->OptionalHeader.SectionAlignment, (*it)->m_SecHeader.Misc.VirtualSize);
		it++;
	}
	dwImageSize += Align(m_TargetPeTag.m_lpNtHeader->OptionalHeader.SectionAlignment, m_TargetPeTag.m_lpNtHeader->OptionalHeader.SizeOfHeaders);
	return dwImageSize;
}

DWORD Task::GetPressSize(std::vector<MySecInfo*>&vec)
{
	DWORD dwPressSize = 0;
	std::vector<MySecInfo*>::iterator it = vec.begin();
	while (it != vec.end())
	{
		//去除不能压缩的区段(资源)
		if ((*it)->m_isNeedPress == true)
		{
			dwPressSize += (*it)->m_SecHeader.SizeOfRawData;
		}
		it++;
	}
	return dwPressSize;
}

void Task::CopyPressData(char* lpDest, char *lpSrc, std::vector<MySecInfo*>&vec)
{
	DWORD dwCurPos = 0;
	std::vector<MySecInfo*>::iterator it = vec.begin();
	while (it != vec.end())
	{
		if ((*it)->m_isNeedPress == true)
		{
			memcpy(lpDest + dwCurPos, lpSrc + (*it)->m_SecHeader.PointerToRawData,
				(*it)->m_SecHeader.SizeOfRawData);
			dwCurPos += (*it)->m_SecHeader.SizeOfRawData;
		}
		it++;
	}
}
int Task::CompressData(LPVOID lpSoure, LPVOID* lpOutDest, DWORD dwLength)
{
	byte* workmem = NULL;
	byte* lpDest = NULL;

	if ((lpDest = (byte *)malloc(aP_max_packed_size(dwLength))) == NULL ||
		(workmem = (byte *)malloc(aP_workmem_size(dwLength))) == NULL)
	{
		AfxMessageBox("ERR: not enough memory\n");
		return 1;
	}
	int nOutSize = aPsafe_pack(lpSoure, lpDest, dwLength, workmem, ProgressCallBack, NULL);
	if (nOutSize == APLIB_ERROR)
	{
		AfxMessageBox("\nERR: an error occured while compressing\n");
		return -1;
	}
	*lpOutDest = lpDest;
	if (workmem != NULL)
	{
		free(workmem);
	}
	return nOutSize;
}

void Task::AddSec(char* lpSecName, DWORD dwFileSize, LPVOID lpFileData)
{
	PEstruct PeStruct;
	PeStruct.m_lpDosHeader = (IMAGE_DOS_HEADER*)lpFileData;
	PeStruct.m_lpNtHeader = (IMAGE_NT_HEADERS*)((DWORD)lpFileData + PeStruct.m_lpDosHeader->e_lfanew);
	PeStruct.m_lpSecHeader = (IMAGE_SECTION_HEADER*)((DWORD)lpFileData + PeStruct.m_lpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER)
		+ PeStruct.m_lpNtHeader->FileHeader.SizeOfOptionalHeader);
	DWORD dwRVA = Align(PeStruct.m_lpNtHeader->OptionalHeader.SectionAlignment, PeStruct.m_lpNtHeader->OptionalHeader.SizeOfHeaders);
	DWORD dwFASize = PeStruct.m_lpNtHeader->OptionalHeader.SizeOfHeaders;
	DWORD nSecCount = PeStruct.m_lpNtHeader->FileHeader.NumberOfSections;
	DWORD i = 0;
	while (i < nSecCount)
	{

		DWORD dwVirtualSize = Align(PeStruct.m_lpNtHeader->OptionalHeader.SectionAlignment, PeStruct.m_lpSecHeader->Misc.VirtualSize);
		dwRVA += dwVirtualSize;
		dwFASize += Align(PeStruct.m_lpNtHeader->OptionalHeader.FileAlignment, PeStruct.m_lpSecHeader->SizeOfRawData);
		PeStruct.m_lpSecHeader++;
		i++;
	}


	IMAGE_SECTION_HEADER secheader = { 0 };
	strcpy((char*)secheader.Name, lpSecName);
	secheader.PointerToRawData = dwFASize;
	secheader.SizeOfRawData = Align(PeStruct.m_lpNtHeader->OptionalHeader.FileAlignment, dwFileSize);
	secheader.VirtualAddress = dwRVA;
	if (nSecCount == 0)
	{
		secheader.Misc.VirtualSize = GetTargetImageSize(m_TargetSecVector);
	}
	else
	{
		secheader.Misc.VirtualSize = Align(PeStruct.m_lpNtHeader->OptionalHeader.SectionAlignment, dwFileSize);;
	}
	secheader.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

	PeStruct.m_lpNtHeader->FileHeader.NumberOfSections++;
	*PeStruct.m_lpSecHeader = secheader;

}


void Task::Init(const char *path)
{
	bool isPE=CreateFileMapStruct(path, m_TargetPeTag.m_FileMapTag);
	if (!isPE)
		return;

	CreateFileMapStruct("E:/code/2017/Stub/Release/Stub.dll", m_ShellPeTag.m_FileMapTag);

	SetPEStruct(m_TargetPeTag.m_FileMapTag.m_lpFileData, m_TargetPeTag);

	SetPEStruct(m_ShellPeTag.m_FileMapTag.m_lpFileData, m_ShellPeTag);

	StoreSectionInfo(m_TargetPeTag.m_FileMapTag.m_lpFileData, m_TargetSecVector);
	StoreSectionInfo(m_ShellPeTag.m_FileMapTag.m_lpFileData, m_ShellSecVector);
}

void Task::GetResRVA(char* lpFileData, DWORD& dwRVA, DWORD& dwSize)
{
	PEstruct PeStruct;
	PeStruct.m_lpDosHeader = (IMAGE_DOS_HEADER*)lpFileData;
	PeStruct.m_lpNtHeader = (IMAGE_NT_HEADERS*)((DWORD)lpFileData + PeStruct.m_lpDosHeader->e_lfanew);
	PeStruct.m_lpSecHeader = (IMAGE_SECTION_HEADER*)((DWORD)lpFileData + PeStruct.m_lpDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER)
		+ PeStruct.m_lpNtHeader->FileHeader.SizeOfOptionalHeader);
	DWORD dwVASize = PeStruct.m_lpSecHeader->VirtualAddress;
	DWORD dwFASize = PeStruct.m_lpSecHeader->PointerToRawData;
	DWORD nSecCount = PeStruct.m_lpNtHeader->FileHeader.NumberOfSections;
	DWORD i = 0;
	while (i < nSecCount)
	{
		if (strcmp((char*)PeStruct.m_lpSecHeader->Name, ".rsrc") == 0)
		{
			dwRVA = PeStruct.m_lpSecHeader->VirtualAddress;
			dwSize = PeStruct.m_lpSecHeader->Misc.VirtualSize;
			return;
		}
		PeStruct.m_lpSecHeader++;
		i++;
	}
	dwRVA = 0;
	dwSize = 0;
}

void Task::FixRsrc(MySecInfo *lpResSecInfo)
{
	//修正资源表
	DWORD dwResRVA;
	DWORD dwSize;
	if (lpResSecInfo != NULL)
	{
		GetResRVA(m_PressPeTag.m_FileMapTag.m_lpFileData, dwResRVA, dwSize);
		DWORD dwResFA = RVA2FA(m_PressPeTag.m_FileMapTag.m_lpFileData, dwResRVA);
		IMAGE_RESOURCE_DIRECTORY* lpIMAGE_RESOURCE_DIRECTORY = (IMAGE_RESOURCE_DIRECTORY*)(m_PressPeTag.m_FileMapTag.m_lpFileData + dwResFA);
		WORD nCount = lpIMAGE_RESOURCE_DIRECTORY->NumberOfIdEntries + lpIMAGE_RESOURCE_DIRECTORY->NumberOfNamedEntries;
		IMAGE_RESOURCE_DIRECTORY_ENTRY* lpRESOURCE_DIRECTORY = (struct _IMAGE_RESOURCE_DIRECTORY_ENTRY *)(lpIMAGE_RESOURCE_DIRECTORY + 1);
		int n = sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
		for (int i = 0; i < nCount; i++)
		{
			if (lpRESOURCE_DIRECTORY->DataIsDirectory == 1)
			{
				//第二层目录
				DWORD RESOURCEAdder = lpRESOURCE_DIRECTORY->OffsetToDirectory + (DWORD)lpIMAGE_RESOURCE_DIRECTORY;
				IMAGE_RESOURCE_DIRECTORY* lpSecond = (IMAGE_RESOURCE_DIRECTORY*)RESOURCEAdder;
				IMAGE_RESOURCE_DIRECTORY_ENTRY* lpSecond2 = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(lpSecond + 1);
				for (int l = 0; l < lpSecond->NumberOfNamedEntries; l++)
				{
					//第三层数据
					IMAGE_RESOURCE_DIRECTORY* lpThrid = (IMAGE_RESOURCE_DIRECTORY*)(lpSecond2->OffsetToDirectory + (DWORD)lpIMAGE_RESOURCE_DIRECTORY);
					IMAGE_RESOURCE_DIRECTORY_ENTRY* lpThridEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(lpThrid + 1);
					for (int k = 0; k < lpThrid->NumberOfIdEntries; k++)
					{
						DWORD* lpDwAddress = (DWORD*)(lpThridEntry->OffsetToData + (DWORD)lpIMAGE_RESOURCE_DIRECTORY);
						//修改偏移 = 基址 + 差值
						*lpDwAddress = dwResRVA + *lpDwAddress - lpResSecInfo->m_SecHeader.VirtualAddress;
						lpThridEntry++;
					}
					lpSecond2++;
				}
				for (int j = 0; j < lpSecond->NumberOfIdEntries; j++)
				{
					//第三层数据
					IMAGE_RESOURCE_DIRECTORY* lpThrid = (IMAGE_RESOURCE_DIRECTORY*)(lpSecond2->OffsetToDirectory + (DWORD)lpIMAGE_RESOURCE_DIRECTORY);
					IMAGE_RESOURCE_DIRECTORY_ENTRY* lpThridEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(lpThrid + 1);
					for (int k = 0; k < lpThrid->NumberOfIdEntries; k++)
					{
						DWORD* lpDwAddress = (DWORD*)(lpThridEntry->OffsetToData + (DWORD)lpIMAGE_RESOURCE_DIRECTORY);
						//修改偏移 = 基址 + 差值
						*lpDwAddress = dwResRVA + *lpDwAddress - lpResSecInfo->m_SecHeader.VirtualAddress;
						lpThridEntry++;
					}
					lpSecond2++;
				}

			}
			lpRESOURCE_DIRECTORY++;
		}
	}
}

MySecInfo * GetSecInfoByName(const char *name, std::vector<MySecInfo*>&vec)
{
	for (int i = 0; i < vec.size(); i++)
	{
		if (strcmp(name, (char*)vec[i]->m_SecHeader.Name) == 0)
		{
			return vec[i];
		}
	}
	return NULL;
}

void Task::SetPressDataDir()
{
	m_PressPeTag.m_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = GetSecInfoByName(".reloc", m_PressSecVector)->m_SecHeader.VirtualAddress;
	m_PressPeTag.m_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = m_ShellPeTag.m_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;


	if (GetSecInfoByName(".rsrc", m_PressSecVector) != NULL)
	{
		m_PressPeTag.m_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = GetSecInfoByName(".rsrc", m_PressSecVector)->m_SecHeader.VirtualAddress;
		m_PressPeTag.m_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = GetSecInfoByName(".rsrc", m_PressSecVector)->m_SecHeader.SizeOfRawData;
	}

	MySecInfo *secInfo = GetSecInfoByRVA(m_ShellPeTag.m_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, m_ShellPeTag.m_lpNtHeader->OptionalHeader.SectionAlignment, m_ShellSecVector);

	DWORD dwTLSSize = m_ShellPeTag.m_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
	DWORD dwOffset = m_ShellPeTag.m_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress - secInfo->m_SecHeader.VirtualAddress;
	m_PressPeTag.m_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = dwOffset + GetSecInfoByName(".Shell", m_PressSecVector)->m_SecHeader.VirtualAddress;
	m_PressPeTag.m_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = dwTLSSize;

}

void Task::ClearDataDir(char* lpFileData)
{
	PEstruct peStruct;
	peStruct.m_lpDosHeader = (IMAGE_DOS_HEADER*)lpFileData;
	peStruct.m_lpNtHeader = (IMAGE_NT_HEADERS*)(lpFileData + peStruct.m_lpDosHeader->e_lfanew);
	DWORD dwDataDirCount = peStruct.m_lpNtHeader->OptionalHeader.NumberOfRvaAndSizes;
	for (int i = 0; i < dwDataDirCount; i++)
	{
		peStruct.m_lpNtHeader->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
		peStruct.m_lpNtHeader->OptionalHeader.DataDirectory[i].Size = 0;
	}
}

void Task::fixStubRelocation()
{
	DWORD dwDllRelocRVA = m_ShellPeTag.m_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD dwDllRelocFA = RVA2FA((char*)m_ShellPeTag.m_FileMapTag.m_lpFileData, dwDllRelocRVA);
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(m_ShellPeTag.m_FileMapTag.m_lpFileData + RVA2FA(m_ShellPeTag.m_FileMapTag.m_lpFileData, m_ShellPeTag.m_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
	m_PressPeTag.m_lpSecHeader = GET_SECTION_HEADER(GET_NT_HEADER(m_PressPeTag.m_FileMapTag.m_lpFileData));
	MySecInfo *lpShellRelocSection = m_ShellSecVector[4];
	DWORD j = 0;
	while (pReloc->SizeOfBlock)
	{
		PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pReloc + 1);
		DWORD dwNumber = (pReloc->SizeOfBlock - 8) / 2;
		for (int i = 0; i < dwNumber; i++)
		{
			if (*(PWORD)(&pTypeOffset[i]) == 0)
			{
				break;
			}
			DWORD dwRVA = pTypeOffset[i].offset + pReloc->VirtualAddress;
			DWORD dwAddressOfReloc = *(PDWORD)((DWORD)m_ShellPeTag.m_FileMapTag.m_lpFileData + RVA2FA(m_ShellPeTag.m_FileMapTag.m_lpFileData, dwRVA));


			MySecInfo*info = GetSecInfoByRVA(dwAddressOfReloc - m_ShellPeTag.m_lpNtHeader->OptionalHeader.ImageBase, m_ShellPeTag.m_lpNtHeader->OptionalHeader.SectionAlignment, m_ShellSecVector);
			if (strcmp((char*)info->m_SecHeader.Name, ".text") == 0)
			{
				DWORD result = *(PDWORD)((DWORD)m_ShellPeTag.m_FileMapTag.m_lpFileData + RVA2FA(m_ShellPeTag.m_FileMapTag.m_lpFileData, dwRVA)) =
					dwAddressOfReloc - m_ShellPeTag.m_lpNtHeader->OptionalHeader.ImageBase + m_TargetPeTag.m_lpNtHeader->OptionalHeader.ImageBase + m_PressPeTag.m_lpSecHeader[1].VirtualAddress - info->m_SecHeader.VirtualAddress;
			}
			else if (strcmp((char*)info->m_SecHeader.Name, ".tls") == 0)
			{
				DWORD result = *(PDWORD)((DWORD)m_ShellPeTag.m_FileMapTag.m_lpFileData + RVA2FA(m_ShellPeTag.m_FileMapTag.m_lpFileData, dwRVA)) =
					dwAddressOfReloc - m_ShellPeTag.m_lpNtHeader->OptionalHeader.ImageBase + m_TargetPeTag.m_lpNtHeader->OptionalHeader.ImageBase + m_PressPeTag.m_lpSecHeader[2].VirtualAddress - info->m_SecHeader.VirtualAddress;
			}
			else
			{
				DWORD result = *(PDWORD)((DWORD)m_ShellPeTag.m_FileMapTag.m_lpFileData + RVA2FA(m_ShellPeTag.m_FileMapTag.m_lpFileData, dwRVA)) =
					dwAddressOfReloc - m_ShellPeTag.m_lpNtHeader->OptionalHeader.ImageBase + m_TargetPeTag.m_lpNtHeader->OptionalHeader.ImageBase + m_PressPeTag.m_lpSecHeader[3].VirtualAddress - info->m_SecHeader.VirtualAddress;
			}
		}

		MySecInfo *info = GetSecInfoByRVA(pReloc->VirtualAddress, m_ShellPeTag.m_lpNtHeader->OptionalHeader.SectionAlignment, m_ShellSecVector);
		if (strcmp((char*)info->m_SecHeader.Name, ".text") == 0)
		{
			DWORD dwOffset = pReloc->VirtualAddress - info->m_SecHeader.VirtualAddress;
			pReloc->VirtualAddress = m_PressPeTag.m_lpSecHeader[1].VirtualAddress + dwOffset;
		}
		else
		{
			DWORD dwOffset = pReloc->VirtualAddress - info->m_SecHeader.VirtualAddress;
			pReloc->VirtualAddress = m_PressPeTag.m_lpSecHeader[2].VirtualAddress + dwOffset;
		}
		pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pReloc + pReloc->SizeOfBlock);
	}

}



void Task::Pack(const std::string &path)
{
	//获取目标区段对齐值和文件对齐值
	DWORD dwTargetSectionAlignment = m_TargetPeTag.m_lpNtHeader->OptionalHeader.SectionAlignment;
	DWORD dwTargetFileAlignment = m_TargetPeTag.m_lpNtHeader->OptionalHeader.FileAlignment;

	//资源数据
	DWORD dwResRVA = m_TargetPeTag.m_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
	MySecInfo* lpResSecInfo = NULL;

	//导出变量
	g_GlobalExternVar = (GlogalExternVar*)GetExpVarAddr("g_globalVar");
	//设置参数

	if (dwResRVA != 0)
	{
		lpResSecInfo = GetSecInfoByRVA(dwResRVA, m_TargetPeTag.m_lpNtHeader->OptionalHeader.SectionAlignment, m_TargetSecVector);
		lpResSecInfo->m_isNeedPress = false;
	}
	//映射文件大小
	DWORD dwTargetImageSize = GetTargetImageSize(m_TargetSecVector);
	//需要压缩的区块大小
	DWORD dwPressSize = GetPressSize(m_TargetSecVector);
	//将原始压缩了的区块数据复制到目标内存中
	DWORD dwAfterPressSize = CopyToDestMemory(dwPressSize);
	DWORD dwResFileSize = 0;
	//对其资源块
	if (lpResSecInfo != NULL)
	{
		dwResFileSize = Align(dwTargetFileAlignment, lpResSecInfo->m_SecHeader.SizeOfRawData);
	}
	//文件大小
	DWORD dwFileSize = m_TargetPeTag.m_lpNtHeader->OptionalHeader.SizeOfHeaders +
		Align(dwTargetFileAlignment, dwAfterPressSize) + Align(dwTargetFileAlignment, m_ShellPeTag.m_lpNtHeader->OptionalHeader.SizeOfCode) +
		dwResFileSize + Align(dwTargetFileAlignment, m_ShellSecVector[1]->m_SecHeader.SizeOfRawData) + Align(dwTargetFileAlignment, m_ShellSecVector[2]->m_SecHeader.SizeOfRawData + m_ShellSecVector[4]->m_SecHeader.SizeOfRawData);
	m_dwPressSize = dwFileSize;


	m_PressPeTag.m_FileMapTag.m_lpFileData = new char[dwFileSize];
	RtlZeroMemory(m_PressPeTag.m_FileMapTag.m_lpFileData, dwFileSize);
	//复制文件头
	memcpy(m_PressPeTag.m_FileMapTag.m_lpFileData, m_TargetPeTag.m_FileMapTag.m_lpFileData, m_TargetPeTag.m_lpNtHeader->OptionalHeader.SizeOfHeaders);

	m_PressPeTag.m_lpNtHeader = GET_NT_HEADER(m_PressPeTag.m_FileMapTag.m_lpFileData);
	m_PressPeTag.m_lpDosHeader = GET_DOS_HEADER(m_PressPeTag.m_FileMapTag.m_lpFileData);

	DWORD dwResSize = 0;
	if (lpResSecInfo != 0)
	{
		dwResSize = Align(dwTargetSectionAlignment, lpResSecInfo->m_SecHeader.SizeOfRawData);
	}

	//内存映像大小
	DWORD dwImageSize = Align(dwTargetSectionAlignment, m_PressPeTag.m_lpNtHeader->OptionalHeader.SizeOfHeaders) +
		dwTargetImageSize +
		Align(dwTargetSectionAlignment, m_ShellPeTag.m_lpNtHeader->OptionalHeader.SizeOfCode) +
		dwResSize +
		//代码段
		Align(dwTargetSectionAlignment, m_ShellSecVector[1]->m_SecHeader.SizeOfRawData) +
		//tls段
		Align(dwTargetSectionAlignment, m_ShellSecVector[2]->m_SecHeader.SizeOfRawData) +
		Align(dwTargetSectionAlignment, m_ShellSecVector[4]->m_SecHeader.SizeOfRawData);

	m_PressPeTag.m_lpNtHeader->OptionalHeader.SizeOfImage = dwImageSize;
	m_PressPeTag.m_lpNtHeader->FileHeader.NumberOfSections = 0;
	//添加需要添加的区段
	AddTargetSection(lpResSecInfo, dwAfterPressSize);

	//修复Stub重定位
	fixStubRelocation();
	//记录需要重新复制的地方
	DWORD dwShell = 0;
	//将Stub 复制到最终内存中
	CopyToTargetFile(dwAfterPressSize, lpResSecInfo, dwTargetFileAlignment, dwShell);
	StoreSectionInfo(m_PressPeTag.m_FileMapTag.m_lpFileData, m_PressSecVector);

	ClearDataDir(m_PressPeTag.m_FileMapTag.m_lpFileData);

	SetPressDataDir();

	//设置入口点
	m_PressPeTag.m_lpNtHeader->OptionalHeader.AddressOfEntryPoint
		= m_ShellPeTag.m_lpNtHeader->OptionalHeader.AddressOfEntryPoint - m_ShellPeTag.m_lpNtHeader->OptionalHeader.BaseOfCode + m_PressSecVector[1]->m_SecHeader.VirtualAddress;

	//修复资源块
	FixRsrc(lpResSecInfo);
	SetGlobalVar(dwPressSize);

	//重新复制Shell段
	memcpy((m_PressPeTag.m_FileMapTag.m_lpFileData + dwShell),
		(LPVOID)((DWORD)m_ShellPeTag.m_FileMapTag.m_lpFileData + RVA2FA((char*)m_ShellPeTag.m_FileMapTag.m_lpFileData, m_ShellPeTag.m_lpNtHeader->OptionalHeader.BaseOfCode)),
		m_ShellPeTag.m_lpNtHeader->OptionalHeader.SizeOfCode);

	std::string sFileName = path.substr(0, path.length() - 4);
	sFileName += "_Pack.exe";
	SaveFile(sFileName.c_str());
	MessageBoxW(NULL,L"加壳成功",L"Packer",0);
}

void Task::SetGlobalVar(DWORD dwPressSize)
{
	g_GlobalExternVar->dwOrignalOEP = m_TargetPeTag.m_lpNtHeader->OptionalHeader.AddressOfEntryPoint;
	g_GlobalExternVar->dwRelocationRva = m_TargetPeTag.m_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	g_GlobalExternVar->dwPressSize = dwPressSize;
	g_GlobalExternVar->dwIATVirtualAddress = m_TargetPeTag.m_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	g_GlobalExternVar->dwOrignalImageBase = m_TargetPeTag.m_lpNtHeader->OptionalHeader.ImageBase;
	g_GlobalExternVar->dwTLSVirtualAddress = m_TargetPeTag.m_lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
	RtlZeroMemory(g_GlobalExternVar->mSectionNodeArray, sizeof(g_GlobalExternVar->mSectionNodeArray));
	int tempi = 0;
	for (int i = 0; i < m_TargetSecVector.size(); i++)
	{
		if (m_TargetSecVector[i]->m_isNeedPress)
		{
			g_GlobalExternVar->mSectionNodeArray[tempi].SectionRva = m_TargetSecVector[i]->m_SecHeader.VirtualAddress;
			g_GlobalExternVar->mSectionNodeArray[tempi].SizeOfRawData = m_TargetSecVector[i]->m_SecHeader.SizeOfRawData;
			tempi++;
		}
	}
}

void Task::SaveFile(const char * name)
{
	FILE *lpPressFilefd = fopen(name, "wb");
	fwrite(m_PressPeTag.m_FileMapTag.m_lpFileData, sizeof(char), m_dwPressSize, lpPressFilefd);
	fclose(lpPressFilefd);
}

void Task::CopyToTargetFile(DWORD dwAfterPressSize, MySecInfo * lpResSecInfo, DWORD dwTargetFileAlignment, DWORD & dwShell)
{
	DWORD dwCurPos = m_PressPeTag.m_lpNtHeader->OptionalHeader.SizeOfHeaders;
	memcpy((m_PressPeTag.m_FileMapTag.m_lpFileData + dwCurPos),
		m_lpPressData,
		dwAfterPressSize);

	//拷贝.Shell区段
	dwCurPos += Align(dwTargetFileAlignment, dwAfterPressSize);
	dwShell = dwCurPos;

	memcpy((m_PressPeTag.m_FileMapTag.m_lpFileData + dwCurPos),
		(LPVOID)((DWORD)m_ShellPeTag.m_FileMapTag.m_lpFileData + RVA2FA((char*)m_ShellPeTag.m_FileMapTag.m_lpFileData, m_ShellPeTag.m_lpNtHeader->OptionalHeader.BaseOfCode)),
		m_ShellPeTag.m_lpNtHeader->OptionalHeader.SizeOfCode);

	//拷贝Stub tls CRT 
	dwCurPos += Align(dwTargetFileAlignment, m_ShellPeTag.m_lpNtHeader->OptionalHeader.SizeOfCode);
	memcpy((m_PressPeTag.m_FileMapTag.m_lpFileData + dwCurPos), (LPVOID)((DWORD)m_ShellPeTag.m_FileMapTag.m_lpFileData + RVA2FA((char*)m_ShellPeTag.m_FileMapTag.m_lpFileData, m_ShellSecVector[1]->m_SecHeader.VirtualAddress)), m_ShellSecVector[1]->m_SecHeader.SizeOfRawData);

	dwCurPos += Align(dwTargetFileAlignment, m_ShellSecVector[1]->m_SecHeader.SizeOfRawData);
	memcpy((m_PressPeTag.m_FileMapTag.m_lpFileData + dwCurPos), (LPVOID)((DWORD)m_ShellPeTag.m_FileMapTag.m_lpFileData + RVA2FA((char*)m_ShellPeTag.m_FileMapTag.m_lpFileData, m_ShellSecVector[2]->m_SecHeader.VirtualAddress)), m_ShellSecVector[2]->m_SecHeader.SizeOfRawData);
	dwCurPos += Align(dwTargetFileAlignment, m_ShellSecVector[2]->m_SecHeader.SizeOfRawData);

	memcpy((m_PressPeTag.m_FileMapTag.m_lpFileData + dwCurPos), (LPVOID)((DWORD)m_ShellPeTag.m_FileMapTag.m_lpFileData + RVA2FA((char*)m_ShellPeTag.m_FileMapTag.m_lpFileData, m_ShellSecVector[4]->m_SecHeader.VirtualAddress)), m_ShellSecVector[4]->m_SecHeader.SizeOfRawData);
	dwCurPos += Align(dwTargetFileAlignment, m_ShellSecVector[4]->m_SecHeader.SizeOfRawData);

	//拷贝.rsrc区段
	if (lpResSecInfo != NULL)
	{
		memcpy((m_PressPeTag.m_FileMapTag.m_lpFileData + dwCurPos),
			(m_TargetPeTag.m_FileMapTag.m_lpFileData + lpResSecInfo->m_SecHeader.PointerToRawData),
			lpResSecInfo->m_SecHeader.SizeOfRawData);
		dwCurPos += Align(dwTargetFileAlignment, lpResSecInfo->m_SecHeader.SizeOfRawData);
	}
}

void Task::AddTargetSection(MySecInfo * lpResSecInfo, DWORD dwAfterPressSize)
{
	AddSec(".OldDat", dwAfterPressSize, m_PressPeTag.m_FileMapTag.m_lpFileData);
	AddSec(".Shell", m_ShellPeTag.m_lpNtHeader->OptionalHeader.SizeOfCode, m_PressPeTag.m_FileMapTag.m_lpFileData);
	AddSec((char*)m_ShellSecVector[1]->m_SecHeader.Name, m_ShellSecVector[1]->m_SecHeader.SizeOfRawData, m_PressPeTag.m_FileMapTag.m_lpFileData);
	AddSec((char*)m_ShellSecVector[2]->m_SecHeader.Name, m_ShellSecVector[2]->m_SecHeader.SizeOfRawData, m_PressPeTag.m_FileMapTag.m_lpFileData);
	//reloc
	AddSec((char*)m_ShellSecVector[4]->m_SecHeader.Name, m_ShellSecVector[4]->m_SecHeader.SizeOfRawData, m_PressPeTag.m_FileMapTag.m_lpFileData);
	if (lpResSecInfo != NULL)
	{
		AddSec(".rsrc", lpResSecInfo->m_SecHeader.SizeOfRawData, m_PressPeTag.m_FileMapTag.m_lpFileData);
	}
}

DWORD Task::CopyToDestMemory(DWORD dwPressSize)
{
	char *lpDestData = new char[dwPressSize];

	RtlZeroMemory(lpDestData, dwPressSize);

	CopyPressData(lpDestData, m_TargetPeTag.m_FileMapTag.m_lpFileData, m_TargetSecVector);

	DWORD dwAfterPressSize = CompressData(lpDestData, &m_lpPressData, dwPressSize);

	if (dwAfterPressSize == APLIB_ERROR)
	{
		return 0;
	}
	if (lpDestData != NULL)
	{
		delete lpDestData;
		lpDestData = NULL;
	}
	return dwAfterPressSize;
}

UINT Task::ThreadCallBack(void * param)
{
	return 0;
}

extern DWORD dwTotal;
extern DWORD dwCompressSize;


void Task::OnTimer(UINT_PTR nIDEvent)
{
	
}
