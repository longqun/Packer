#pragma once
#include "stdafx.h"
#include "Packer.h"
#include "afxdialogex.h"
#include "util.h"
#include <vector>
#include <string>

using std::string;


#include "aplib.h"
#ifdef _WIN64
#pragma comment(lib, "./lib/x64/aplib.lib")
#else
#pragma comment(lib, "./lib/x86/aplib.lib")
#endif // _WIN64
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


class PEPacker {
	PEPacker(const char *pe_file_path);


private:
	const string m_pe_file_path;
};