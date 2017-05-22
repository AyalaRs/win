#include "prefast.h"
#include "windows.h"

#include <io.h>
#include <stdio.h>
#include <stdlib.h>

#include "crtwrap.h"
#include "pdbrtl.h"


pfnWow64EnableWow64FsRedirection  _imp__Wow64EnableWow64FsRedirection;
#define Wow64EnableWow64FsRedirection _imp__Wow64EnableWow64FsRedirection

pfnWow64DisableWow64FsRedirection _imp__Wow64DisableWow64FsRedirection;
#define Wow64DisableWow64FsRedirection _imp__Wow64DisableWow64FsRedirection

pfnWow64RevertWow64FsRedirection  _imp__Wow64RevertWow64FsRedirection;
#define Wow64RevertWow64FsRedirection _imp__Wow64RevertWow64FsRedirection


RTL_INIT pfninitialized = Uninitialized;


inline void RTL_PFN_INIT()
{
	if (pfninitialized==Uninitialized)
	{
		HMODULE libkernel32 = GetModuleHandle("kernel32");
		if (!libkernel32)
			goto RTL_PFN_INIT_DONE;
		_imp__Wow64EnableWow64FsRedirection= (pfnWow64EnableWow64FsRedirection)
						GetProcAddress(libkernel32,"Wow64EnableWow64FsRedirection");
		_imp__Wow64DisableWow64FsRedirection= (pfnWow64DisableWow64FsRedirection)
						GetProcAddress(libkernel32,"Wow64DisableWow64FsRedirection");
		_imp__Wow64RevertWow64FsRedirection= (pfnWow64RevertWow64FsRedirection)
						GetProcAddress(libkernel32,"Wow64RevertWow64FsRedirection");
		if (_imp__Wow64EnableWow64FsRedirection  && 
			_imp__Wow64DisableWow64FsRedirection &&
			_imp__Wow64RevertWow64FsRedirection
			)
			pfninitialized = InitializeSuccess;
		else
RTL_PFN_INIT_DONE:
			pfninitialized = InitializeFault;
	
	}
}



FILE *  
PDB_wfsopen(const wchar_t *wszPath, const wchar_t *wszMode, int shflag)
{
	PVOID OlValue;
	BOOL  __Value;
	FILE* file=NULL;
	
	RTL_PFN_INIT();
	
	if (wszPath && *wszPath)
	{
		if (pfninitialized = InitializeSuccess)
		{
			__Value=
			Wow64DisableWow64FsRedirection(&OlValue);
		}
		
		file = 
		_wfsopen(wszPath,wszMode,shflag);
		
		if (__Value)
		{
			Wow64RevertWow64FsRedirection(OlValue);
		}
	}
	return file;
}

wchar_t * 
PDB_wfullpath(__out_ecount(maxlen) wchar_t *wszFullpath, const wchar_t *wszPath, size_t maxlen)

{
	PVOID OlValue;
	BOOL  __Value;
	wchar_t* path=NULL;
	
	RTL_PFN_INIT();
	
	if (wszPath && *wszPath)
	{
		if (pfninitialized = InitializeSuccess)
		{
			__Value=
			Wow64DisableWow64FsRedirection(&OlValue);
		}
		
		path = 
		_wfullpath(wszFullpath,wszPath,maxlen);
		
		if (__Value)
		{
			Wow64RevertWow64FsRedirection(OlValue);
		}
	}
	return path;
}


errno_t __cdecl PDB_wdupenv_s(_Deref_out_opt_z_ wchar_t **pwszDest, size_t * pcchDest, const wchar_t *wszVarName)
{
  wchar_t *envp; 

  envp = _wgetenv(wszVarName);
  if ( envp )
  {
    if ( pcchDest )
      *pcchDest = wcslen(envp) + 1;
    *pwszDest = _wcsdup(envp);
  }
  else
  {
    *pwszDest = 0;
    if (pcchDest )
      *pcchDest = 0;
  }
  return 0;
}
















