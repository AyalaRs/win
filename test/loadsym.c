#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

//#include <imagehlp.h>
#define DBG 1
#define MAX_SYM_NAME            2000
enum SymTagEnum{
    SymTagNull,
    SymTagExe,
    SymTagCompiland,
    SymTagCompilandDetails,
    SymTagCompilandEnv,
    SymTagFunction,
    SymTagBlock,
    SymTagData,
    SymTagAnnotation,
    SymTagLabel,
    SymTagPublicSymbol,
    SymTagUDT,
    SymTagEnum,
    SymTagFunctionType,
    SymTagPointerType,
    SymTagArrayType,
    SymTagBaseType,
    SymTagTypedef,
    SymTagBaseClass,
    SymTagFriend,
    SymTagFunctionArgType,
    SymTagFuncDebugStart,
    SymTagFuncDebugEnd,
    SymTagUsingNamespace,
    SymTagVTableShape,
    SymTagVTable,
    SymTagCustom,
    SymTagThunk,
    SymTagCustomType,
    SymTagManagedType,
    SymTagDimension,
    SymTagMax
};

typedef struct _SYMBOL_INFOW {
    ULONG       SizeOfStruct;
    ULONG       TypeIndex;        // Type Index of symbol
    ULONG64     Reserved[2];
    ULONG       Index;
    ULONG       Size;
    ULONG64     ModBase;          // Base Address of module comtaining this symbol
    ULONG       Flags;
    ULONG64     Value;            // Value of symbol, ValuePresent should be 1
    ULONG64     Address;          // Address of symbol including base address of module
    ULONG       Register;         // register holding value or pointer to value
    ULONG       Scope;            // scope of the symbol
    ULONG       Tag;              // pdb classification
    ULONG       NameLen;          // Actual length of name
    ULONG       MaxNameLen;
    wchar_t       Name[1];          // Name of symbol
} SYMBOL_INFOW, *PSYMBOL_INFOW;

typedef enum _IMAGEHLP_SYMBOL_TYPE_INFO {
    TI_GET_SYMTAG,
    TI_GET_SYMNAME,
    TI_GET_LENGTH,
    TI_GET_TYPE,
    TI_GET_TYPEID,
    TI_GET_BASETYPE,
    TI_GET_ARRAYINDEXTYPEID,
    TI_FINDCHILDREN,
    TI_GET_DATAKIND,
    TI_GET_ADDRESSOFFSET,
    TI_GET_OFFSET,
    TI_GET_VALUE,
    TI_GET_COUNT,
    TI_GET_CHILDRENCOUNT,
    TI_GET_BITPOSITION,
    TI_GET_VIRTUALBASECLASS,
    TI_GET_VIRTUALTABLESHAPEID,
    TI_GET_VIRTUALBASEPOINTEROFFSET,
    TI_GET_CLASSPARENTID,
    TI_GET_NESTED,
    TI_GET_SYMINDEX,
    TI_GET_LEXICALPARENT,
    TI_GET_ADDRESS,
    TI_GET_THISADJUST,
    TI_GET_UDTKIND,
    TI_IS_EQUIV_TO,
    TI_GET_CALLING_CONVENTION,
    TI_IS_CLOSE_EQUIV_TO,
    TI_GTIEX_REQS_VALID,
    TI_GET_VIRTUALBASEOFFSET,
    TI_GET_VIRTUALBASEDISPINDEX,
    TI_GET_IS_REFERENCE,
    TI_GET_INDIRECTVIRTUALBASECLASS,
    IMAGEHLP_SYMBOL_TYPE_INFO_MAX,
} IMAGEHLP_SYMBOL_TYPE_INFO;

typedef struct _TI_FINDCHILDREN_PARAMS {
    ULONG Count;
    ULONG Start;
    ULONG ChildId[1];
} TI_FINDCHILDREN_PARAMS;

typedef BOOL
(__stdcall *pfnSymInitializeW)(
    __in HANDLE hProcess,
    __in_opt PCWSTR UserSearchPath,
    __in BOOL fInvadeProcess
    );
typedef DWORD
(__stdcall *pfnSymSetOptions)(
    __in DWORD   SymOptions
    );
typedef BOOL
(CALLBACK *PSYM_ENUMERATESYMBOLS_CALLBACKW)(
    __in PSYMBOL_INFOW pSymInfo,
    __in ULONG SymbolSize,
    __in_opt PVOID UserContext
    );
typedef BOOL
(__stdcall *pfnSymEnumTypesByNameW)(
    __in HANDLE hProcess,
    __in ULONG64 BaseOfDll,
    __in_opt PCWSTR mask,
    __in PSYM_ENUMERATESYMBOLS_CALLBACKW EnumSymbolsCallback,
    __in_opt PVOID UserContext
    );
typedef BOOL
(__stdcall *pfnSymSetSearchPathW)(
    __in HANDLE hProcess,
    __in_opt PCWSTR SearchPath
    );

typedef BOOL
(__stdcall *pfnSymCleanup)(
    __in HANDLE hProcess
    );
typedef BOOL
(__stdcall *pfnSymGetTypeInfo)(
    __in HANDLE hProcess,
    __in DWORD64 ModBase,
    __in ULONG TypeId,
    __in IMAGEHLP_SYMBOL_TYPE_INFO GetType,
    __out PVOID pInfo
    );
typedef DWORD64
(__stdcall *pfnSymLoadModuleExW)(
    __in HANDLE hProcess,
    __in_opt HANDLE hFile,
    __in_opt PCWSTR ImageName,
    __in_opt PCWSTR ModuleName,
    __in DWORD64 BaseOfDll,
    __in DWORD DllSize,
    __in_opt PVOID Data,
    __in_opt DWORD Flags
    );

pfnSymSetOptions       SymSetOptions;
pfnSymInitializeW      SymInitializeW;
pfnSymEnumTypesByNameW SymEnumTypesByNameW;
pfnSymSetSearchPathW   SymSetSearchPathW;
pfnSymCleanup          SymCleanup;
pfnSymGetTypeInfo      SymGetTypeInfo;
pfnSymLoadModuleExW    SymLoadModuleExW;

#if DBG
typedef BOOL
(__stdcall *pfnSymInitialize)(
    __in HANDLE hProcess,
    __in_opt PCSTR UserSearchPath,
    __in BOOL fInvadeProcess
    );

typedef BOOL
(__stdcall *pfnSymSetSearchPath)(
    __in HANDLE hProcess,
    __in_opt PCSTR SearchPath
    );
typedef DWORD64
(__stdcall *pfnSymLoadModule64)(
    IN  HANDLE          hProcess,
    IN  HANDLE          hFile,
    IN  PSTR            ImageName,
    IN  PSTR            ModuleName,
    IN  DWORD64         BaseOfDll,
    IN  DWORD           DllSize
    );
typedef BOOL
(CALLBACK *PSYM_ENUMSYMBOLS_CALLBACK64)(
    PSTR SymbolName,
    DWORD64 SymbolAddress,
    ULONG SymbolSize,
    PVOID UserContext
    );
typedef BOOL
(__stdcall *pfnSymEnumerateSymbols64)(
    IN HANDLE                       hProcess,
    IN ULONG64                      BaseOfDll,
    IN PSYM_ENUMSYMBOLS_CALLBACK64  EnumSymbolsCallback,
    IN PVOID                        UserContext
    );
pfnSymInitialize         SymInitialize;
pfnSymSetSearchPath      SymSetSearchPath;
pfnSymLoadModule64       SymLoadModule64;
pfnSymEnumerateSymbols64 SymEnumerateSymbols64;
#endif


typedef struct _TYPESYM_MATCHESW{
	wchar_t * sym;
	ULONG  typeindex;
	ULONG  rev1;
	ULONG64 addr;
	ULONG  count;
	DWORD64 BaseOfDll;
	HANDLE hProcess;
	SYMBOL_INFOW info;
	wchar_t fn[MAX_SYM_NAME-1];
}TYPESYM_MATCHES,*PTYPESYM_MATCHES;



ULONG     cc        =0;
ULONG     tag       =0;
ULONG64   len       =0;
wchar_t*  pfn       =NULL;
ULONG     off       =0;
ULONG     typeid[32]={0};
ULONG     symindex  =0;
ULONG     child_tag      =0;
wchar_t*  child_pfn      =NULL;
ULONG	  child_type     =0;
ULONG	  child_typeid   =0;
ULONG     child_symindex =0;
ULONG64	  child_length   =0;
ULONG	  child_count    =0;
ULONG	  child_basetype =0;
ULONG	  child_arraytyp =0;
ULONG	  child_datakind =0;
ULONG	  child_bitpos   =0;
ULONG	  child_data     =0;


        

void dumptype(HANDLE process,ULONG64 base,ULONG TypeIndex,int tab,int viewchildlevel)
{
	TI_FINDCHILDREN_PARAMS* p;
	int status;
	int i,k;
	
	status =
	SymGetTypeInfo(process,base,TypeIndex,TI_GET_CHILDRENCOUNT,&cc);
	if (!status)
		goto done;
	p = malloc((cc+2)*sizeof(ULONG));
	if (!p)
		goto done;
	p->Count=cc;
	p->Start=0;
	
	status =
	SymGetTypeInfo(process,base,TypeIndex,TI_FINDCHILDREN,p);
	if (!status)
		goto done;
	for (i=0;i<p->Count;i++)
	{
		status =
		SymGetTypeInfo(process,base,p->ChildId[i],TI_GET_OFFSET,&off);
		status =
		SymGetTypeInfo(process,base,p->ChildId[i],TI_GET_SYMNAME,&pfn);
		printf("% *s%08X %ws",tab,"",off,pfn);
		if (!viewchildlevel)
		{	
			printf("\n");
			continue;
		}

		status =
		SymGetTypeInfo(process,base,p->ChildId[i],TI_GET_TYPEID,&child_typeid);
		
		status =
		SymGetTypeInfo(process,base,child_typeid,TI_GET_SYMTAG,&child_tag);
next:
		switch (child_tag)
		{
			case SymTagArrayType:
				status =
				SymGetTypeInfo(process,base,child_typeid,TI_GET_COUNT,&child_count);
				
				printf("  [%d] ",child_count);
				
				status =
				SymGetTypeInfo(process,base,child_typeid,TI_GET_TYPEID,&child_typeid);
				
				status =
				SymGetTypeInfo(process,base,child_typeid,TI_GET_SYMTAG,&child_tag);
				goto next;
			case SymTagPointerType:
				status =
				SymGetTypeInfo(process,base,child_typeid,TI_GET_TYPEID,&child_typeid);
				status =
				SymGetTypeInfo(process,base,child_typeid,TI_GET_SYMNAME,&child_pfn);
				if (status)
				{
					int k;
					printf(" ptr struct %ws\n",child_pfn);
					if (viewchildlevel <2)
						continue;
					for (k=1;k<32 && typeid[k];k++)
					{
						status =
						SymGetTypeInfo(process,base,typeid[k],TI_GET_SYMNAME,&pfn);
						if (status && !_wcsicmp(pfn,child_pfn))
							continue;
					}
					/*
					for (k=0;k<IMAGEHLP_SYMBOL_TYPE_INFO_MAX;k++)
					{
						status =
						SymGetTypeInfo(process,base,typeid,k,&child_data);
						if (status)
							printf("parent_data %d %08X\n",k,child_data);
						if (k==TI_GET_SYMNAME)
							printf("%ws\n",child_data);
					}
					for (k=0;k<IMAGEHLP_SYMBOL_TYPE_INFO_MAX;k++)
					{
						status =
						SymGetTypeInfo(process,base,child_typeid,k,&child_data);
						if (status)
							printf("child_data %d %08X %ws\n",k,child_data);
						if (k==TI_GET_SYMNAME)
							printf("%ws\n",child_data);
					}
					
					*/
					status =
					SymGetTypeInfo(process,base,child_typeid,TI_GET_SYMTAG,&child_tag);
					goto next;
				}
				status =
				SymGetTypeInfo(process,base,child_typeid,TI_GET_SYMTAG,&child_tag);
				printf(" ptr");
				goto next;
			case SymTagUDT:
				for (k=1;k<32;k++)
				{	
					if (!typeid[k])
					{
						typeid[k] = child_typeid;
						break;
					}
				}
				status =
				SymGetTypeInfo(process,base,child_typeid,TI_GET_SYMNAME,&child_pfn);
				printf(" struct %ws\n",child_pfn);
				typeid[0]+=1;
				if (k<32 && typeid[0]<5)
					dumptype(process,base,child_typeid,tab+2,viewchildlevel);
				typeid[0]-=1;
				break;
			case SymTagEnum:
				status =
				SymGetTypeInfo(process,base,child_typeid,TI_GET_SYMNAME,&child_pfn);
				printf(" enum %ws\n",child_pfn);
				break;
			case SymTagBaseType:
				status =
				SymGetTypeInfo(process,base,p->ChildId[i],TI_GET_LENGTH,&child_length);
				status =
				SymGetTypeInfo(process,base,p->ChildId[i],TI_GET_BITPOSITION,&child_bitpos);
				if (status)
				{
					printf(" pos %d, %d bit\n",child_bitpos,child_length);
					continue;
				}
				status =
				SymGetTypeInfo(process,base,child_typeid,TI_GET_LENGTH,&child_length);
				status =
				SymGetTypeInfo(process,base,child_typeid,TI_GET_BASETYPE,&child_basetype);
				switch (child_basetype)
				{
					case 0xE:
						if (child_length == 4)
							printf("  Uint4B\n");
						else if (child_length==8)
							printf("  Uint8B\n");
						else
							printf("  ?????%d %08X\n",child_basetype,child_length);
						break;
					case 0xD:
						if (child_length == 4)
							printf("  Int4B\n");
						else if (child_length==8)
							printf("  Int8B\n");
						else
							printf("  ?????%d %08X\n",child_basetype,child_length);
						break;
					case 0x7:
						if (child_length == 8)
							printf("  Uint8B\n");
						else if (child_length == 4)
							printf("  Uint4B\n");
						else if (child_length==2)
							printf("  Uint2B\n");
						else if (child_length==1)
							printf("  UChar\n");
						else
							printf("  ?????%d %08X\n",child_basetype,child_length);
						break;
					case 0x3:
						if (child_length == 2)
							printf("  WChar\n");
						else if (child_length==1)
							printf("  Char\n");
						else
							printf("  ?????%d %08X\n",child_basetype,child_length);
						break;
					case 0x1:
						if (child_length == 0)
							printf("  void\n");
						break;
					default:
						printf("  ?????%d %08X\n",child_basetype,child_length);
						break;
				}
				break;
			default:
				printf("\n");
				break;
		}	
	}
done:
	free(p);
}

TYPESYM_MATCHES tsm={0};

#if DBG

CALLBACK
FindLocal(
	PSTR SymbolName,
    DWORD64 SymbolAddress,
    ULONG SymbolSize,
    PVOID UserContext
    )
{
	
	printf("%016I64X\n  %s\n",SymbolAddress,SymbolName);
	return 1;
}

#else
CALLBACK
FindLocal(
    __in PSYMBOL_INFOW pSymInfo,
    __in ULONG SymbolSize,
    __in_opt PVOID UserContext
)
{
	PTYPESYM_MATCHES tsmp = (PTYPESYM_MATCHES)UserContext;
	
	if (!_wcsicmp((wchar_t*)&pSymInfo->Name,tsmp->sym))
	{
		RtlMoveMemory(&tsmp->info,pSymInfo,sizeof(*pSymInfo));
		return 0;
	}
	return 1;
}
#endif

#if DBG
int main()
{
	int status;
	DWORD64 mod;
	HANDLE hProcess;
	char* tag[2];
	int i;

	HMODULE lib_dbghelp =
	LoadLibrary("F:\\win\\private\\sdktools\\obj\\i386\\dbghelp.dll");
	if (!lib_dbghelp)
	{
		printf("...........\n");
		goto done;
	}
	SymInitialize= (pfnSymInitialize)
	GetProcAddress(lib_dbghelp,"SymInitialize");
	
	SymSetOptions = (pfnSymSetOptions)
	GetProcAddress(lib_dbghelp,"SymSetOptions");
	
	SymSetSearchPath = (pfnSymSetSearchPath)
	GetProcAddress(lib_dbghelp,"SymSetSearchPath");

	SymCleanup = (pfnSymCleanup)
	GetProcAddress(lib_dbghelp,"SymCleanup");
	
	SymLoadModule64 = (pfnSymLoadModule64)
	GetProcAddress(lib_dbghelp,"SymLoadModule64");
	
	SymEnumerateSymbols64 = (pfnSymEnumerateSymbols64)
	GetProcAddress(lib_dbghelp,"SymEnumerateSymbols64");
	
	hProcess =
	OpenProcess(PROCESS_ALL_ACCESS,FALSE,GetCurrentProcessId());

	SymSetOptions(0x1032277 | 0x80000000);
	status=
	SymInitialize(hProcess,NULL,FALSE);
	if (!status)
	{
		printf("SymInitialize fault\n");
		goto done;
	}
	status=
	SymSetSearchPath(hProcess,
					"symbols");
	if (!status)
	{
		printf("SymSetSearchPath fault\n");
		goto done;
	}
	
	tag[0] = "loadsym.exe";
	tag[1] = "ntdll.dll";
	//RetrievePdbInfo LocatePdb
	for (i=0;i<2;i++)
	{
		char buf[MAX_PATH];
		char* tagp;
		DWORD64 BaseOfDll=(DWORD64)
		GetModuleHandle(tag[i]);

		if (i)
		{
			printf("BaseOfDll %016I64X\n",BaseOfDll);
			GetSystemDirectory(buf,sizeof(buf));
			strcat(buf,"\\");
			strcat(buf,tag[i]);
			printf("%s\n",buf);
			tagp = &buf[0];
		}
		else
			tagp = tag[i];

		system("pause");
		mod=
		SymLoadModule64(hProcess,
						NULL,
						tagp,
						NULL,
						BaseOfDll,
						0);
						
		if (!mod)
		{
			printf("SymLoadModule64 fault %08X\n",GetLastError());
			continue;
		}
#if DBG
		if (IsDebuggerPresent())
			__debugbreak();
#endif
		status=
		SymEnumerateSymbols64(hProcess,
							BaseOfDll,
							&FindLocal,
							NULL
							);
		
	}
done:	
	system("pause");
	return 0;
}
#else
int main()
{	
	int status;
	DWORD64 mod;
	DWORD64 BaseOfDll;
	HANDLE hProcess;
	/*
	
	*/
	HMODULE lib_dbghelp =
#if defined(_WIN64)
	LoadLibrary(".\\x64\\dbghelp.dll");
#elif defined(_WIN32)
	LoadLibrary(".\\x86\\dbghelp.dll");
#else
	LoadLibrary(".\\dbghelp.dll");
#endif
	if (!lib_dbghelp)
	{
		printf("...........\n");
		goto done;
	}
	SymInitializeW= (pfnSymInitializeW)
	GetProcAddress(lib_dbghelp,"SymInitializeW");
	
	SymSetOptions = (pfnSymSetOptions)
	GetProcAddress(lib_dbghelp,"SymSetOptions");
	
	SymEnumTypesByNameW = (pfnSymEnumTypesByNameW)
	GetProcAddress(lib_dbghelp,"SymEnumTypesByNameW");
	
	SymSetSearchPathW = (pfnSymSetSearchPathW)
	GetProcAddress(lib_dbghelp,"SymSetSearchPathW");

	SymCleanup = (pfnSymCleanup)
	GetProcAddress(lib_dbghelp,"SymCleanup");
	
	SymGetTypeInfo = (pfnSymGetTypeInfo)
	GetProcAddress(lib_dbghelp,"SymGetTypeInfo");
	
	SymLoadModuleExW = (pfnSymLoadModuleExW)
	GetProcAddress(lib_dbghelp,"SymLoadModuleExW");
	
	hProcess =
	OpenProcess(PROCESS_ALL_ACCESS,FALSE,GetCurrentProcessId());
	BaseOfDll = (DWORD64)GetModuleHandle("ntdll.dll");
	printf("BaseOfDll %016I64X\n",BaseOfDll);
	
	SymSetOptions(0x1032277);
	status=
	SymInitialize(hProcess,NULL,FALSE);
	if (!status)
	{
		printf("SymInitialize fault\n");
		goto done;
	}
	status=
	SymSetSearchPathW(hProcess,
					L"SRV*symbol*http://msdl.microsoft.com/download/symbols/");
	if (!status)
	{
		printf("SymSetSearchPathW fault\n");
		goto done;
	}
	
	mod=
	SymLoadModuleExW(hProcess,
					NULL,
					L"ntdll.dll",
					NULL,
					BaseOfDll,
					0,
					0,
					0
					);
	if (!mod)
	{
		printf("SymLoadModuleExW fault %08X\n",GetLastError());
		goto done;
	}
	
	tsm.sym = L"_TEB";
	status=
	SymEnumTypesByNameW(hProcess,
						BaseOfDll,
						tsm.sym,
						&FindLocal,
						&tsm
						);
	printf("TypeIndex %08X\n",tsm.info.TypeIndex);
	memset(&typeid,0,sizeof(typeid));
	dumptype(hProcess,
			BaseOfDll,
			tsm.info.TypeIndex,
			0,
			2);
	SymCleanup(hProcess);
	CloseHandle(hProcess);
done:
	system("pause");
	return 0;
}

#endif
