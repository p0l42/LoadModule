#pragma once

#include <windows.h>
#include <iostream>
#include <winternl.h>

#define KRNL32 0xf7bbd765276ca16b

class WhosModule {

public:
	WhosModule(LPCSTR filePath) {
		getModuleRaw(filePath);
		getImageSize();
		getSectionNumber();
		getHeaderSize();
		getSectionBase();
		getImageBase();
		this->_module_mem = loadModule();
		fixRelocation();
		//showIAT();
		findUtilAPI();
		fixIAT();
	}
	~WhosModule() {
		free(this->_module_raw);
		free(this->_module_mem);
	}

	void getModuleRaw(LPCSTR filePath) {

		LPOFSTRUCT pOf = (LPOFSTRUCT)malloc(sizeof(OFSTRUCT));
		HANDLE hFile = (HANDLE)OpenFile(filePath, pOf, OF_READ);
		if (hFile == INVALID_HANDLE_VALUE) {
			printf("Error Code: %d\n", GetLastError());
			return;
		}
		DWORD dwFileSize = GetFileSize(hFile, NULL);
		_module_raw = (PBYTE)malloc(dwFileSize);
		ZeroMemory(_module_raw, dwFileSize);
		DWORD dwByteToRead = dwFileSize;
		DWORD dwByteReads = 0;
		PBYTE tmpBuffer = _module_raw;
		do {
			ReadFile(hFile, tmpBuffer, dwByteToRead, &dwByteReads, NULL);
			dwByteToRead -= dwByteReads;
			tmpBuffer += dwByteReads;
		} while (dwByteToRead > 0);
		CloseHandle(hFile);

	}

	void getImageSize() {

		if (!this->_module_raw) {
			printf("Module is Not Read\n");
			return;
		}
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)_module_raw;
		PIMAGE_OPTIONAL_HEADER pOp = (PIMAGE_OPTIONAL_HEADER)(_module_raw + pDos->e_lfanew + 0x18);
		this->_image_size = pOp->SizeOfImage;

	}

	void getImageBase() {
		if (!this->_module_raw) {
			printf("Module is Not Read\n");
			return;
		}
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)_module_raw;
		PIMAGE_OPTIONAL_HEADER pOp = (PIMAGE_OPTIONAL_HEADER)(_module_raw + pDos->e_lfanew + 0x18);
		this->_image_base = pOp->ImageBase;
	}

	void getSectionNumber() {
		if (!this->_module_raw) {
			printf("Module is Not Read\n");
			return;
		}
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)_module_raw;
		PIMAGE_FILE_HEADER pF = (PIMAGE_FILE_HEADER)(_module_raw + pDos->e_lfanew + 0x4);
		this->_section_num = pF->NumberOfSections;
	}

	void getHeaderSize() {
		if (!this->_module_raw) {
			printf("Module is Not Read\n");
			return;
		}
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)_module_raw;
		PIMAGE_OPTIONAL_HEADER pOp = (PIMAGE_OPTIONAL_HEADER)(_module_raw + pDos->e_lfanew + 0x18);
		this->_header_size = pOp->SizeOfHeaders;
	}

	void getSectionBase() {
		if (!this->_module_raw) {
			printf("Module is Not Read\n");
			return;
		}
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)_module_raw;
		PIMAGE_FILE_HEADER pF = (PIMAGE_FILE_HEADER)(_module_raw + pDos->e_lfanew + 0x4);
		PIMAGE_OPTIONAL_HEADER pOp = (PIMAGE_OPTIONAL_HEADER)(_module_raw + pDos->e_lfanew + 0x18);
		this->_section_base = (PBYTE)pOp + pF->SizeOfOptionalHeader;
	}

	PBYTE loadModule() {

		PBYTE pImageBase = NULL;
		pImageBase = (PBYTE)VirtualAlloc((LPVOID)NULL, this->_image_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		/*DWORD tmp = this->_image_base;
		do {

			tmp += 0x10000000;
		} while (pImageBase == NULL);*/

		ZeroMemory(pImageBase, this->_image_size);
		PBYTE tmpBuffer = pImageBase;
		PBYTE tmpSrc = this->_module_raw;
		//copy headers and tables;
		//1.headers
		memcpy(tmpBuffer, tmpSrc, this->_header_size);

		//2.tables
		PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)this->_section_base;
		for (int i = 0; i < this->_section_num; i++) {
			//copy sections
			DWORD dwVirtualAddr = pSection->VirtualAddress;
			DWORD dwSize = pSection->SizeOfRawData;
			DWORD dwFileAddr = pSection->PointerToRawData;
			memcpy(tmpBuffer + dwVirtualAddr, tmpSrc + dwFileAddr, dwSize);
			pSection += 1;
		}

		return pImageBase;
	}

	void fixRelocation() {
		if (!this->_module_mem) {
			printf("Module is Not Load\n");
			return;
		}
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)this->_module_mem;
		PIMAGE_OPTIONAL_HEADER pOp = (PIMAGE_OPTIONAL_HEADER)(_module_mem + pDos->e_lfanew + 0x18);
		IMAGE_DATA_DIRECTORY stReloc = (IMAGE_DATA_DIRECTORY)pOp->DataDirectory[5];
		PBYTE pReloc = this->_module_mem + stReloc.VirtualAddress;
		PBYTE pImageBase = this->_module_mem;
		while (*((PDWORD)pReloc)) {
			DWORD dwOffset = *((PDWORD)pReloc);
			DWORD dwRelocSize = *((PDWORD)pReloc + 1);
			DWORD dwFixNumber = (dwRelocSize - 8) / 2;
			PWORD pFix = (PWORD)(pReloc + 8);
			for (int i = 0; i < dwFixNumber; i++) {
				WORD wFix = *pFix; //may cause crash
				WORD high = wFix & 0xf000;
				WORD low = wFix & 0x0fff;
				if (high == 0xa000) {
					PDWORD64 dwAddr = (PDWORD64)(pImageBase + dwOffset + low);
					//printf("address at %llx\n", dwAddr);
					//printf("before: %llx\n", *dwAddr);
					*dwAddr += (DWORD64)pImageBase - this->_image_base;
					//printf("after: %llx\n", *dwAddr);
				}
				pFix += 1;
			}
			pReloc += dwRelocSize;
		}
	}

	void fixIAT() {
		if (!this->_module_mem) {
			printf("Module is Not Load\n");
			return;
		}
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)this->_module_mem;
		PIMAGE_OPTIONAL_HEADER pOp = (PIMAGE_OPTIONAL_HEADER)(_module_mem + pDos->e_lfanew + 0x18);
		IMAGE_DATA_DIRECTORY stImport = (IMAGE_DATA_DIRECTORY)pOp->DataDirectory[1];
		PBYTE pImageBase = (PBYTE)this->_module_mem;
		PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pImageBase + stImport.VirtualAddress);
		while (pImport->OriginalFirstThunk || pImport->FirstThunk) {
			//char* buffer = (char*)malloc(100);
			std::string buffer = std::string("C:\\Windows\\System32\\") + std::string((char*)pImageBase + pImport->Name);
			HMODULE hModule = LoadLibraryA(buffer.c_str());
			PDWORD64 pInt = (PDWORD64) (pImageBase + pImport->OriginalFirstThunk);
			PDWORD64 pIat = (PDWORD64)(pImageBase + pImport->FirstThunk);
			while (*pInt) {
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(pImageBase + *pInt);
				LPVOID pFuncAddr = GetProcAddress(hModule, pName->Name);
				*pIat = (DWORD64)pFuncAddr;
				pInt += 1;
				pIat += 1;
			}
			pImport += 1;
		}

	}

	//This function will not be used in programs, 
	//just used for detecting whether the IAT should be fixed 
	void showIAT() {
		if (!this->_module_mem) {
			printf("Module is Not Load\n");
			return;
		}
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)this->_module_mem;
		PIMAGE_OPTIONAL_HEADER pOp = (PIMAGE_OPTIONAL_HEADER)(_module_mem + pDos->e_lfanew + 0x18);
		IMAGE_DATA_DIRECTORY stImport = (IMAGE_DATA_DIRECTORY)pOp->DataDirectory[1];
		PBYTE pImageBase = (PBYTE)this->_module_mem;
		PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pImageBase + stImport.VirtualAddress);
		while (pImport->OriginalFirstThunk || pImport->FirstThunk) {
			printf("=========================================\n");
			printf("INT Address: %llx\n", pImageBase + pImport->OriginalFirstThunk);
			printf("IAT Address: %llx\n", pImageBase + pImport->FirstThunk);
			printf("Dll Name: %s\n", (pImageBase + pImport->Name));
			pImport += 1;
		}
	}

	PBYTE getExports() {
		if (!this->_module_mem) {
			printf("Module is Not Load\n");
			return NULL;
		}
		PBYTE pImageBase = (PBYTE)this->_module_mem;
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)this->_module_mem;
		PIMAGE_OPTIONAL_HEADER pOp = (PIMAGE_OPTIONAL_HEADER)(_module_mem + pDos->e_lfanew + 0x18);
		IMAGE_DATA_DIRECTORY stExport = (IMAGE_DATA_DIRECTORY)pOp->DataDirectory[0];
		PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pImageBase + stExport.VirtualAddress);
		PDWORD pAddressOfNames = (PDWORD)(pImageBase + pExport->AddressOfNames);
		PDWORD pAddressOfFunctions = (PDWORD)(pImageBase + pExport->AddressOfFunctions);
		PWORD pAddressOfOrdianls = (PWORD)(pImageBase + pExport->AddressOfNameOrdinals);
		PBYTE pFuncAddr = NULL;
		for (int i = 0; i < pExport->NumberOfNames; i++) {
			PBYTE pFuncName = pImageBase + pAddressOfNames[i];
			pFuncAddr = pImageBase + pAddressOfFunctions[pAddressOfOrdianls[i]];
			//printf("%s : %llx\n", pFuncName, pFuncAddr);
			if (!strcmp((char*)pFuncName, "CreateThread")) {
				break;
			}
		}
		return pFuncAddr;
	}

	DWORD64 Hash(UNICODE_STRING ModuleName) {
		PWSTR pString = ModuleName.Buffer;
		DWORD64 result = 0;
		std::hash<std::wstring> hash_str;
		result = hash_str(pString);
		return result;
	}

	//TODO: x86 arch
	void findUtilAPI() {
		PPEB pPeb = (PPEB)__readgsqword(0x60);
		PPEB_LDR_DATA pLDR = (PPEB_LDR_DATA)pPeb->Ldr;
		LIST_ENTRY ModuleInMem = pLDR->InMemoryOrderModuleList;
		PLDR_DATA_TABLE_ENTRY pModule = (PLDR_DATA_TABLE_ENTRY)((PBYTE)ModuleInMem.Flink - 0x10);
		this->_load_library = NULL;
		this->_get_proc = NULL;
		while (pModule->DllBase) {
			if (Hash(pModule->FullDllName) == KRNL32) {
				PBYTE pImageBase = (PBYTE)pModule->DllBase;
				PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)this->_module_mem;
				PIMAGE_OPTIONAL_HEADER pOp = (PIMAGE_OPTIONAL_HEADER)(_module_mem + pDos->e_lfanew + 0x18);
				IMAGE_DATA_DIRECTORY stExport = (IMAGE_DATA_DIRECTORY)pOp->DataDirectory[0];
				PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pImageBase + stExport.VirtualAddress);
				PDWORD pAddressOfNames = (PDWORD)(pImageBase + pExport->AddressOfNames);
				PDWORD pAddressOfFunctions = (PDWORD)(pImageBase + pExport->AddressOfFunctions);
				PWORD pAddressOfOrdianls = (PWORD)(pImageBase + pExport->AddressOfNameOrdinals);
				PBYTE pFuncAddr = NULL;
				for (int i = 0; i < pExport->NumberOfNames; i++) {
					if (this->_load_library && this->_get_proc) {
						break;
					}
					PBYTE pFuncName = pImageBase + pAddressOfNames[i];
					pFuncAddr = pImageBase + pAddressOfFunctions[pAddressOfOrdianls[i]];
					//printf("%s : %llx\n", pFuncName, pFuncAddr);
					if (!strcmp((char*)pFuncName, "LoadLibraryA")) {
						this->_load_library = pFuncAddr;
					}else if (!strcmp((char*)pFuncName, "GetProcAddressA")) {
						this->_get_proc = pFuncAddr;
					}
				}
				break;
			}
			pModule = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pModule->InMemoryOrderLinks.Flink - 0x10);
		}
	}


private:
	PBYTE _module_raw;
	DWORD _image_size;
	DWORD _image_base;
	DWORD _section_num;
	DWORD _header_size;
	PBYTE _section_base;
	PBYTE _module_mem;
	LPVOID _load_library;
	LPVOID _get_proc;
	INT _key;
};