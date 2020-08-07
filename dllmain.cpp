// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"

ModuleInfo hw;

static char szCodecName[]	= { 'v','o','i','c','e','_','s','p','e','e','x' };
static int bUseSteam		= false;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		if (GetLastError() == ERROR_ALREADY_EXISTS)
			return FALSE;

		if (FindModuleByName("hw.dll", &hw))
		{
			// signed int __cdecl Voice_Init(_BYTE *pCodecName, int quality)
			/*
			.text:01DC29E6 FF 15 C8 C4 E1 01                       call    ds:SteamUser
			.text:01DC29EC 85 C0                                   test    eax, eax
			.text:01DC29EE 0F 95 C0                                setnz   al
			.text:01DC29F1 84 C0                                   test    al, al
			.text:01DC29F3 A2 18 DE E5 01                          mov     bUseSteam, al
			*/
			{
				auto ptr = FindPattern("85 C0 0F 95 C0 84 C0", hw.base, hw.end, -0x06);

				if (ptr) // replace game bUseSteam to my value
				{
					char write[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0x90 };
					*(PDWORD)&write[1] = bUseSteam;
					memwrite(ptr, (uintptr_t)write, sizeof(write)); // mov eax, myval
				}
			}

			//signed int __usercall CL_Parse_VoiceInit@<eax>(int a1@<ebx>)
			/*
			.text:01D1ED60                         CL_Parse_VoiceInit proc near            ; DATA XREF: .data:01E3B628↓o
			.text:01D1ED60 E8 4B BD 00 00                          call    sub_1D2AAB0
			.text:01D1ED65 E8 66 BB 00 00                          call    sub_1D2A8D0
			.text:01D1ED6A 50                                      push    eax
			.text:01D1ED6B 68 1C CF E6 01                          push    offset unk_1E6CF1C
			.text:01D1ED70 E8 2B 3C 0A 00                          call    Voice_Init
			.text:01D1ED75 83 C4 08                                add     esp, 8
			.text:01D1ED78 C3                                      retn
			.text:01D1ED78                         CL_Parse_VoiceInit endp
			*/
			{
				auto ptr = FindPattern("E8 ? ? ? ? E8 ? ? ? ? ? 68 ? ? ? ? E8 ? ? ? ? 83 C4 08 C3", hw.base, hw.end, 0xC); // 68 ? ? ? ?

				if (ptr)
				{
					char write[] = { 0x00, 0x00, 0x00, 0x00 };
					*(PDWORD)&write[0] = (DWORD)&szCodecName;
					memwrite(ptr, (uintptr_t)write, sizeof(write)); // push myval
				}
			}

			//FreeLibrary(hModule);

			return TRUE;
		}
	}

	return FALSE;
}

void memwrite(uintptr_t adr, uintptr_t ptr, size_t size)
{
	DWORD dwOldProtect;
	VirtualProtect(LPVOID(adr), size, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy(LPVOID(adr), LPVOID(ptr), size);
	VirtualProtect(LPVOID(adr), size, dwOldProtect, &dwOldProtect);
}

bool FindModuleByName(const char* name, ModuleInfo* module)
{
	assert(module);

	if (!name || !strlen(name))
		return false;

	HMODULE handle = GetModuleHandle(name);

	if (!handle || handle == INVALID_HANDLE_VALUE)
		return false;

	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)handle;
	IMAGE_NT_HEADERS* pe = (IMAGE_NT_HEADERS*)((uintptr_t)dos + (uintptr_t)dos->e_lfanew);

	if (pe->Signature != IMAGE_NT_SIGNATURE)
		return false;

	module->handle = handle;
	module->base = (uintptr_t)handle;
	module->size = (uintptr_t)pe->OptionalHeader.SizeOfImage;
	module->end = module->base + module->size - sizeof(uintptr_t);

	return true;
}

uintptr_t FindPattern(const char* signature, uintptr_t start, uintptr_t end, int offset)
{
	static auto pattern_to_byte = [](const char* pattern)
	{
		auto bytes = std::vector<int>{};
		auto start = const_cast<char*>(pattern);
		auto end = const_cast<char*>(pattern) + strlen(pattern);

		for (auto current = start; current < end; ++current)
		{
			if (*current == '?')
			{
				++current;
				if (*current == '?')
					++current;

				bytes.push_back(-1);
			}
			else
				bytes.push_back(strtoul(current, &current, 16));
		}

		return bytes;
	};

	if (start && end)
	{
		const auto pattern = pattern_to_byte(signature);
		const auto patternBytes = pattern.data();
		const auto patternLength = pattern.size();

		bool up = false;

		if (end < start)
			up = true;

		if (!up)
		{
			for (auto i = start; i < end - patternLength; ++i)
			{
				bool found = true;

				for (auto j = 0u; j < patternLength; ++j)
				{
					if (patternBytes[j] != -1 && (CHAR)patternBytes[j] != *(PCHAR)(i + j))
					{
						found = false;
						break;
					}
				}

				if (found)
					return i + offset;
			}
		}
		else
		{
			for (auto i = start; i > end - patternLength; --i)
			{
				bool found = true;

				for (auto j = 0u; j < patternLength; ++j)
				{
					if (patternBytes[j] != -1 && (CHAR)patternBytes[j] != *(PCHAR)(i + j))
					{
						found = false;
						break;
					}
				}

				if (found)
					return i + offset;
			}
		}
	}

	return 0;
}

