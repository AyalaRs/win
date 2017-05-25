#ifndef __NAMEMAP_INCLUDED__
#define __NAMEMAP_INCLUDED__

#ifndef __PDBIMPL_INCLUDED__
#include "pdbimpl.h"
#endif
#ifndef __NMT_INCLUDED__
#include "dbiimpl.h"
#endif

class NMP : public NameMap {
public:
	NMP() {
		pstream = 0;
	}
	~NMP() {
		if (pstream) {
			pstream->Release();
			pstream = 0;
		}
	}
	BOOL open(PDB* ppdb, BOOL fWrite);
	BOOL commit();
	BOOL close();
	BOOL getNi(SZ_CONST sz, OUT NI* pni) {
		return nmt.addNiForSz(sz, pni);
	}
	BOOL getName(NI ni, OUT SZ_CONST* psz) {
		return !!(*psz = nmt.szForNi(ni));
	}
	BOOL contains(SZ_CONST sz, OUT NI* pni) {
		NI ni = nmt.niForSz(sz);
		if (pni)
			*pni = ni;
		return ni != niNil;
	}
	BOOL getEnumNameMap(OUT Enum** ppenum) {
		return !!(*ppenum = new EnumNMT(nmt));
	}
	BOOL reinitialize() {
		// NYI;
		assert(0);
		return TRUE;
	}
	BOOL isValidNi(NI ni) ;
	BOOL getNiW(_In_z_ const wchar_t* sz, OUT NI* pni) ;
	BOOL getNameW(NI ni, _Out_opt_capcount_(*pcch) OUT wchar_t* szName, IN OUT size_t * pcch) ;
	BOOL containsW(_In_z_ const wchar_t *sz, OUT NI* pni) ;
	BOOL containsUTF8(_In_z_ const char* sz, OUT NI* pni) ;
	BOOL getNiUTF8(_In_z_ const char *sz, OUT NI* pni) ;
	BOOL getNameA(NI ni, _Pre_notnull_ _Post_z_ OUT const char ** psz) ;
	BOOL getNameW2(NI ni, _Pre_notnull_ _Post_z_ OUT const wchar_t ** pwsz) ;
private:
	Stream* pstream;	// NameMap stream on disk, non-0 if update on close.
						//  (e.g. if opened for write)
	NMT nmt;
};

#endif // !__NAMEMAP_INCLUDED__
