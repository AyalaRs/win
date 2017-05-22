#pragma once
#ifndef _CRTWRAP_H_
#define _CRTWRAP_H_

#include <stdio.h>

#ifndef _countof
#define _countof(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#endif

#ifndef _TRUNCATE
#define _TRUNCATE ((size_t)-1)
#endif

#ifndef rsize_t
#define rsize_t size_t
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _WSTDLIBP_DEFINED_S
#define _WSTDLIBP_DEFINED_S


int __cdecl _wsplitpath_s(__in_z const wchar_t * _FullPath,
		__out_ecount_z_opt(_DriveSizeInWords) wchar_t * _Drive,
		__in size_t _DriveSizeInWords,
		__out_ecount_z_opt(_DirSizeInWords) wchar_t * _Dir,
		__in size_t _DirSizeInWords,
		__out_ecount_z_opt(_FilenameSizeInWords) wchar_t * _Filename,
		__in size_t _FilenameSizeInWords,
		__out_ecount_z_opt(_ExtSizeInWords) wchar_t * _Ext,
		__in size_t _ExtSizeInWords);
		
int __cdecl _wmakepath_s(__out_ecount_z(_SizeInWords) wchar_t * _PathResult,
				__in_opt size_t _SizeInWords,
				__in_z_opt const wchar_t * _Drive,
				__in_z_opt const wchar_t * _Dir,
				__in_z_opt const wchar_t * _Filename,
				__in_z_opt const wchar_t * _Ext);
				
int __cdecl wcsncat_s(__inout_ecount_z(_DstSize) wchar_t * _Dst,
			__in size_t _DstSize,
			__in_z const wchar_t * _Src,
			__in size_t _MaxCount);

#endif


#ifndef _WSTDLIB_DEFINED_S
#define _WSTDLIB_DEFINED_S

int __cdecl _wdupenv_s(__deref_out_ecount_z_opt(*_BufferSizeInWords) wchar_t **_Buffer, 
					__out_opt size_t *_BufferSizeInWords, 
					__in_z const wchar_t *_VarName);
int __cdecl _snwprintf_s(__out_ecount_z(_DstSizeInWords) wchar_t * _DstBuf, 
					__in size_t _DstSizeInWords, 
					__in size_t _MaxCount,
					 __in_z __format_string const wchar_t * _Format, 
					 ...);

int __cdecl wcscat_s(__inout_ecount_z(_DstSize) wchar_t * _Dst,
			__in rsize_t _DstSize,
			const wchar_t * _Src);

int __cdecl wcscpy_s(__out_ecount_z(_DstSize) wchar_t * _Dst,
			__in rsize_t _DstSize,
			__in_z const wchar_t * _Src);

int __cdecl wcsncpy_s(__out_ecount_z(_DstSize) wchar_t * _Dst,
          __in rsize_t _DstSize,
          __in_z const wchar_t * _Src,
          __in rsize_t _MaxCount);



int __cdecl strcpy_s(__out_ecount_z(_DstSize) char * _Dst,
			__in rsize_t _DstSize,
			__in_z const char * _Src);

int __cdecl strncpy_s(__out_ecount_z(_DstSize) char * _Dst,
		  __in rsize_t _DstSize,
		  __in_z_opt const char * _Src,
		  __in rsize_t _MaxCount);

int __cdecl strcat_s(__inout_ecount_z(_DstSize) char * _Dst,
			__in rsize_t _DstSize,
			__in_z const char * _Src);

int __cdecl swprintf_s(__out_ecount_z(_SizeInWords) wchar_t * _Dst,
				__in size_t _SizeInWords,
				__in_z __format_string const wchar_t * _Format,
				...);
int __cdecl sprintf_s(__out_bcount_z(_DstSize) char * _DstBuf,
			__in size_t _DstSize,
			__in_z __format_string const char * _Format,
			...);

int __cdecl _snprintf_s(__out_bcount_z(_DstSize) char * _DstBuf, 
						__in size_t _DstSize, __in size_t _MaxCount, 
						__in_z __format_string const char * _Format, 
						...);


#endif
#ifdef __cplusplus
}
#endif

#ifdef _M_IX86

FILE *PDB_wfsopen(const wchar_t *wszPath, const wchar_t *wszMode, int shflag);
wchar_t *PDB_wfullpath(__out_ecount(maxlen) wchar_t *wszFullpath, const wchar_t *wszPath, size_t maxlen);

#else   // !_M_IX86

#define PDB_wfsopen _wfsopen
#define PDB_wfullpath _wfullpath

#endif  // !_M_IX86

#ifdef _CRT_ALTERNATIVE_INLINES

errno_t __cdecl PDB_wdupenv_s(_Deref_out_opt_z_ wchar_t **pwszDest, size_t * pcchDest, const wchar_t *wszVarName);

#else

#define PDB_wdupenv_s _wdupenv_s

#endif
#endif