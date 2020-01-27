typedef VOID(NTAPI* _RtlInsertInvertedFunctionTable)(PVOID ImageBase, ULONG SizeOfImage);
_RtlInsertInvertedFunctionTable RtlInsertInvertedFunctionTable = nullptr;


BOOL EnableExceptions(DWORD Base)
{
	PIMAGE_DOS_HEADER pDOSHeader;
	PIMAGE_NT_HEADERS pNTHeader;
	PIMAGE_OPTIONAL_HEADER pOptHeader;

	pDOSHeader = (PIMAGE_DOS_HEADER)(Base);

	if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDOSHeader + pDOSHeader->e_lfanew);

	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return false;

	pOptHeader = (PIMAGE_OPTIONAL_HEADER)&pNTHeader->OptionalHeader;

	if (pOptHeader->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return false;

	RtlInsertInvertedFunctionTable( (PVOID)( Base ), pOptHeader->SizeOfImage );

}

void Initialize() 
{
	auto ntdll = (char*)( tools->FindModuleHandle("ntdll.dll") );

	RtlInsertInvertedFunctionTable = (_RtlInsertInvertedFunctionTable)( tools->FindPattern(ntdll, 0x7FFFFFFF, 
	(PCHAR)"\x8B\xFF\x55\x8B\xEC\x83\xEC\x0C\x53\x56\x57\x8D\x45\xF8\x8B\xFA", (PCHAR)"xxxxxxxxxxxxxxxx") );

	if (!RtlInsertInvertedFunctionTable)
	{
		throw std::runtime_error("Error: FunctionTable not found!");
		TerminateProcess(NtCurrentProcess(), EXIT_FAILURE);
	}

}

BOOL APIENTRY DllMain(PVOID Instance, UINT Reason, PVOID Reserved)
{

	if( Reason == DLL_PROCESS_ATTACH )
	{
		hInstance = (DWORD)(Instance);
		CreateThread(NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>( Initialize ), NULL, NULL, NULL);
	}

	return TRUE;
}