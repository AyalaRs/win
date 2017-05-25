#include "pdbimpl.h"
#include "namemap.h"

PDB_IMPORT_EXPORT(BOOL) NameMap::open(PDB* ppdb, BOOL fWrite, OUT NameMap** ppnm) {
	

	NMP* pnmp = new NMP;
	if (pnmp) {
		if (pnmp->open(ppdb, fWrite)) {
			*ppnm = pnmp;
			return TRUE;
		} else
			delete pnmp;
	}

	return FALSE;
}
extern "C" const char szStreamNameMap[];


BOOL NMP::open(PDB* ppdb, BOOL fWrite) {	
	if (!ppdb->OpenStream(szStreamNameMap, &pstream))
		return FALSE;

	CB cb = pstream->QueryCb();
	if (cb > 0) {
		// reload NMT from stream
		if (!nmt.reload(pstream))
			return FALSE;

	} else {
		// Nothing to do; nmt is already satisfactorily empty.
	}
	
	if (!fWrite) {
		// if read-only, release stream; will not subsequently update the PDB.
		pstream->Release();
		pstream = 0;
	}

	return TRUE;
}

BOOL NMP::commit() {
	BOOL ok = TRUE;
	if (pstream) ok = nmt.save(pstream);
	return ok;
}

BOOL NMP::close() {
	BOOL ok = commit();
	delete this;
	return ok;
}

BOOL NMP::isValidNi(NI ni){
	return nmt.isValidNi(ni);
}


BOOL NMP::getNiW(_In_z_ const wchar_t* sz, OUT NI* pni) {
	__debugbreak();
	return TRUE; 
}
BOOL NMP::getNameW(NI ni, OUT wchar_t* szName, IN OUT size_t * pcch) {
		__debugbreak();
	return TRUE; 
}
BOOL NMP::containsW(_In_z_ const wchar_t *sz, OUT NI* pni) {
		__debugbreak();
	return TRUE; 
}
BOOL NMP::containsUTF8(_In_z_ const char* sz, OUT NI* pni) {
		__debugbreak();
	return TRUE; 
}
BOOL NMP::getNiUTF8(_In_z_ const char *sz, OUT NI* pni) {
		__debugbreak();
	return TRUE; 
}
BOOL NMP::getNameA(NI ni, _Post_z_ OUT const char ** psz) {
		__debugbreak();
	return TRUE; 
}
BOOL NMP::getNameW2(NI ni, _Post_z_ OUT const wchar_t ** pwsz){
		__debugbreak();
	return TRUE; 
}
