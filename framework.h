#pragma once

#define WIN32_LEAN_AND_MEAN             // Исключите редко используемые компоненты из заголовков Windows
// Файлы заголовков Windows
#include <windows.h>
#include <vector>
#include <string>
#include <assert.h>
#include <thread>

struct ModuleInfo
{
	HMODULE handle;
	uintptr_t base;
	uintptr_t end;
	size_t size;
};

void memwrite(uintptr_t adr, uintptr_t ptr, size_t size);
bool FindModuleByName(const char* name, ModuleInfo* module);
uintptr_t FindPattern(const char* signature, uintptr_t start, uintptr_t end, int offset);