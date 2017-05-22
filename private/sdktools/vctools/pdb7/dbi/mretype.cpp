//-----------------------------------------------------------------------------
//	MreType.cpp
//
//  Copyright (C) 1995, Microsoft Corporation
//
//  Purpose:
//		implement the type diff'ing code for MRE
//
//  Functions/Methods present:
//		MRE::GenerateClassChangeFromTypes
//
//  Revision History:
//
//	[]		15-Jan-1995		Dans	Created
//
//-----------------------------------------------------------------------------
#include "pdbimpl.h"


static const _TCHAR szUnnamed[] = _TEXT("__unnamed");

// this code basically lifted from dumpsym7.c from cvdump (PrintNumeric)
unsigned
CbGetNumericData ( PCV pv, DWORD & dwVal ) {
	unsigned		uIndex;
	unsigned		len;
	const ushort *	pus = (const ushort *)pv;

	dwVal = 0;
	uIndex = *pus++;
	if( uIndex < LF_NUMERIC ){
		dwVal = uIndex;
		return 2;
		}
	switch ( uIndex ) {
		case LF_CHAR:
			dwVal = *((const char *)pus);
			return 2 + sizeof(char);

		case LF_SHORT:
			dwVal = *((const short *)pus);
			return 2 + sizeof(short);

		case LF_USHORT:
			dwVal = *((const ushort *)pus);
			return 2 + sizeof(ushort);

		case LF_LONG:
			dwVal = *((const long UNALIGNED *)pus);
			return 2 + sizeof(long);

		case LF_ULONG:
			dwVal = *((const ulong UNALIGNED *)pus);
			return 2 + sizeof(ulong);

		case LF_REAL32:
			//dblTmp = *((float UNALIGNED *)(pus));
			return 2 + 4;

		case LF_REAL64:
			//dblTmp = *((double UNALIGNED *)(pus));
			return 2 + 8;

		case LF_REAL80:
			//ldblTmp = *((long double UNALIGNED *)(pus));
			return 2 + 10;

		case LF_REAL128:
			//ldblTmp = *((long double UNALIGNED *)(pus));
			return 2 + 16;

		case LF_VARSTRING:
			len = *pus++;
			return len + 4;

		default:
			return 2;
		}
	}
