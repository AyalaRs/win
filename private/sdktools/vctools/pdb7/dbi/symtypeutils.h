//SymTypeUtils - utilities to navigate through the cv sym and type records
#ifndef __SymTypeUtils_H_
#define __SymTypeUtils_H_

#ifdef __cplusplus
extern "C" {
#endif

CB cbNumField(PB pb);

BOOL getNumField(PB pb, PB pbOut);

SZ szUDTName(PB pb);


ST stUDTName(PB pb);

ST stMemberName(lfEasy *pleaf);

TYPTYPE *ConvertLeaftoType(lfEasy *pleaf);


BOOL fDecomposeQualName(_In_ ST st, _Inout_ char rg[257], _Out_opt_ SZ *pszClassName, _Out_opt_ SZ *pszMemberName);

BOOL FindMemberByNameAndLeafIndexInFlist(lfEasy *ptypeFlist, SZ_CONST szMember, lfEasy **ppleaf, unsigned short *legal_leaves, int leaf_cnt);

BOOL FindMethodInMList(lfMethodList *pleaf, TI tiFunc, mlMethod ** ppmlMethod);

TI tiFListFromUdt(TYPTYPE *ptype);

BOOL fMemberOfClass(TPI *ptpi, _In_ ST st, lfEasy **ppleaf, TI *ptiClass);

wchar_t *SZNameFromTSRecord(PTYPE ptype, wchar_t *wszNameBuf, size_t cchNameBuf);

#ifdef __cplusplus
}
#endif

#endif
