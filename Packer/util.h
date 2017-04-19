#pragma once
#include "info.h"
#include "string"
bool CreateFileMapStruct(const  char*path, FileMapStruct & fileMapStruct);
bool isPEEXE32(const char *fileData);
void replaceStringA(std::string & path);
 int __cdecl ProgressCallBack(unsigned int insize, unsigned int inpos, unsigned int outpos, void *cbparam);