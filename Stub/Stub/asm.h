#pragma once
extern "C"
{
	void * GetPeb();
	void JmpFunc(void *ptr);
}