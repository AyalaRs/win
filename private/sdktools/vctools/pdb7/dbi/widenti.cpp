#include "prefast.h"

#include "pdbimpl.h"
#include "dbiimpl.h"



unsigned __fastcall
MapLeaf16To32 ( unsigned leaf16 )
{
	__debugbreak();
	return 0;
}

unsigned __fastcall
MapLeafStToSz(unsigned short leaf)
{

	unsigned T;
	switch (leaf)
	{
		case LF_TYPESERVER_ST :
			T = LF_TYPESERVER ;
			break;
		case LF_ENUMERATE_ST :
			T = LF_ENUMERATE ;
			break;
		case LF_ARRAY_ST :
			T = LF_ARRAY ;
			break;
		case LF_CLASS_ST :
			T = LF_CLASS ;
			break;
		case LF_STRUCTURE_ST :
			T = LF_STRUCTURE ;
			break;
		case LF_UNION_ST :
			T = LF_UNION ;
			break;
		case LF_ENUM_ST :
			T = LF_ENUM ;
			break;
		case LF_DIMARRAY_ST :
			T = LF_DIMARRAY ;
			break;
		case LF_PRECOMP_ST :
			T = LF_PRECOMP ;
			break;
		case LF_ALIAS_ST :
			T = LF_ALIAS ;
			break;
		case LF_DEFARG_ST :
			T = LF_DEFARG ;
			break;
		case LF_FRIENDFCN_ST :
			T = LF_FRIENDFCN ;
			break;
		case LF_MEMBER_ST :
			T = LF_MEMBER ;
			break;
		case LF_STMEMBER_ST :
			T = LF_STMEMBER ;
			break;
		case LF_METHOD_ST :
			T = LF_METHOD ;
			break;
		case LF_NESTTYPE_ST :
			T = LF_NESTTYPE ;
			break;
		case LF_ONEMETHOD_ST :
			T = LF_ONEMETHOD ;
			break;
		case LF_NESTTYPEEX_ST :
			T = LF_NESTTYPEEX ;
			break;
		case LF_MEMBERMODIFY_ST :
			T = LF_MEMBERMODIFY ;
			break;
		case LF_MANAGED_ST :
			T = LF_MANAGED ;
			break;
		default:
			T = leaf;
			break;
	}
	return T;
}
unsigned __fastcall
MapSymRecStToSz(unsigned short sym)
{
	unsigned S;
	switch (sym)
	{
		case S_MANYREG2_ST :
			S =  S_MANYREG2;
			break ;
		case S_COMPILE2_ST :
			S =  S_COMPILE2;
			break ;
		case S_GTHREAD32_ST :
			S =  S_GTHREAD32;
			break ;
		case S_GPROCMIPS_ST :
			S =  S_GPROCMIPS;
			break ;
		case S_LPROCMIPS_ST :
			S =  S_LPROCMIPS;
			break ;
		case S_LOCALSLOT_ST :
			S =  S_LOCALSLOT;
			break ;
		case S_PARAMSLOT_ST :
			S =  S_PARAMSLOT;
			break ;
		case S_GPROCIA64_ST :
			S =  S_GPROCIA64;
			break ;
		case S_LPROCIA64_ST :
			S =  S_LPROCIA64;
			break ;
		case S_GMANPROC_ST :
			S =  S_GMANPROC;
			break ;
		case S_LMANPROC_ST :
			S =  S_LMANPROC;
			break ;
		case S_LMANDATA_ST :
			S =  S_LMANDATA;
			break ;
		case S_GMANDATA_ST :
			S =  S_GMANDATA;
			break ;
		case S_MANFRAMEREL_ST :
			S =  S_MANFRAMEREL;
			break ;
		case S_MANREGISTER_ST :
			S =  S_MANREGISTER;
			break ;
		case S_MANSLOT_ST :
			S =  S_MANSLOT;
			break ;
		case S_MANMANYREG_ST :
			S =  S_MANMANYREG;
			break ;
		case S_MANREGREL_ST :
			S =  S_MANREGREL;
			break ;
		case S_MANMANYREG2_ST :
			S =  S_MANMANYREG2;
			break ;
		case S_UNAMESPACE_ST :
			S =  S_UNAMESPACE;
			break ;
		case S_LTHREAD32_ST :
			S =  S_LTHREAD32;
			break ;
		case S_MANYREG_ST :
			S =  S_MANYREG;
			break ;
		case S_COBOLUDT_ST :
			S =  S_COBOLUDT;
			break ;
		case S_BPREL32_ST :
			S =  S_BPREL32;
			break ;
		case S_LDATA32_ST :
			S =  S_LDATA32;
			break ;
		case S_GDATA32_ST :
			S =  S_GDATA32;
			break ;
		case S_PUB32_ST :
			S =  S_PUB32;
			break ;
		case S_GPROC32_ST :
			S =  S_GPROC32;
			break ;
		case S_LPROC32_ST :
			S =  S_LPROC32;
			break ;
		case S_REGREL32_ST :
			S =  S_REGREL32;
			break ;
		case S_UDT_ST :
			S = S_UDT;
			break ;
		case S_DATAREF_ST :
			S =  S_DATAREF;
			break ;
		case S_LPROCREF_ST :
			S =  S_LPROCREF;
			break ;
		case S_REGISTER_ST :
			S =  S_REGISTER;
			break ;
		case S_CONSTANT_ST :
			S =  S_CONSTANT;
			break ;
		case S_PROCREF_ST :
			S =  S_PROCREF;
			break ;
		case S_OBJNAME_ST :
			S =  S_OBJNAME;
			break ;
		case S_THUNK32_ST :
			S =  S_THUNK32;
			break ;
		case S_BLOCK32_ST :
			S =  S_BLOCK32;
			break ;
		case S_WITH32_ST :
			S =  S_WITH32;
			break ;
		case S_LABEL32_ST :
			S =  S_LABEL32;
			break ;
		default :
			S = sym ;
			break ;
	}
	return S;
}
unsigned __fastcall
MapSymRec16To32 ( unsigned rectyp16 )
{
	__debugbreak();
	return 0;
}



bool __fastcall
fNeedsSzConversion(PSYM sym)
{
	return sym->rectyp != MapSymRecStToSz(sym->rectyp);
}

bool __fastcall
fIsStRefSym(PTYPE typ)
{
	return fNeedsSzConversion((PSYM)&typ->data);
}

bool __fastcall
fIsStFieldList(PTYPE typ)
{
	TypeTiIter tii(typ);
	PB pleaf;
	for (;;)
	{
		pleaf = tii.pbCurField();
		if (*pleaf > LF_ST_MAX)
			return false;
		if (*pleaf != MapLeafStToSz(*pleaf))
			return true;
		if (!tii.nextField())
			return false;
	}
}

bool __fastcall
fNeedsSzConversion(PTYPE typ)
{
	bool ret;
	switch (typ->leaf)
	{
		case LF_FIELDLIST:
			ret = fIsStFieldList(typ);
			break;
		case LF_REFSYM:
			ret = fIsStRefSym(typ);
			break;
		default:
			ret = typ->leaf != MapLeafStToSz(typ->leaf);
			break;
	}
	return ret;
}

bool __fastcall
fIsRefSym(PSYM psym)
{
	switch (MapSymRecStToSz(psym->rectyp))
	{
		case S_PROCREF: 
		case S_DATAREF: 
		case S_LPROCREF:
		case S_ANNOTATIONREF:
		case S_TOKENREF:
			return true;
		default:
			return false;
	}
}

bool __fastcall
fConvertSymRecStToSz(PSYM typ)
{
	__debugbreak();
	return false;
}

bool __fastcall
fSymIsData(PSYM typ)
{
	__debugbreak();
	return false;
}

bool __fastcall
fConvertTypeRecStToSz(PTYPE typ)
{
	__debugbreak();
	return false;
}

CB __fastcall
cbForSymNB10(PSYM psym)
{
  return cbForSym(psym);
}

CB __fastcall
cbForSymNB09(PSYM psym)
{
  return psym->reclen + sizeof(psym->reclen);
}

struct WTI : public WidenTi
{
public:
	~WTI();
	WTI(unsigned int,int);
	
    virtual void 
	release() {}

    virtual BYTE /* TYPTYPE */ *
    pTypeWidenTi ( TI ti16, BYTE /* TYPTYPE */ * ) {return 0;}

    virtual BYTE /* SYMTYPE */ *
    pSymWidenTi ( BYTE /* SYMTYPE */ * ) {return 0;}

    virtual BOOL
    fTypeWidenTiNoCache ( BYTE * pbTypeDst, BYTE * pbTypeSrc, long & cbDst ) {return 0;}

    virtual BOOL
    fSymWidenTiNoCache ( BYTE * pbSymDst, BYTE * pbSymSrc, long & cbDst ) {return 0;}

    virtual BOOL
    fTypeNeedsWidening ( BYTE * pbType ) {
		return fNeeds16bitConversion((PTYPE)pbType);
	}

    virtual BOOL
    fSymNeedsWidening ( BYTE * pbSym ) {
		return fNeeds16bitConversion((PSYM)pbSym);
	}

    virtual BOOL
    freeRecord ( void * ) {return 0;}

    // symbol block converters/query.  symbols start at doff from pbSymIn,
    // converted symbols will go at sci.pbSyms + doff, cbSyms are all including
    // doff.
    virtual BOOL
        fQuerySymConvertInfo (
        SymConvertInfo &    sciOut,
        BYTE *              pbSym,
        long                cbSym,
        int                 doff =0
        ) {return 0;}

    virtual BOOL
    fConvertSymbolBlock (
        SymConvertInfo &    sciOut,
        BYTE *              pbSymIn,
        long                cbSymIn,
        int                 doff =0
        ) {return 0;}
private:
	POOL_Align4  
	wPool;
	
	Map<unsigned int,void *,LHcNi,void,CriticalSectionNop>
	wMap;
	
	CB (__fastcall *pfnCbFosym)(PSYM psym);
};



WTI::~WTI() 
{
	wMap.~Map();
	wPool.~POOL_Align4();
}

WTI::WTI(unsigned int cTypeInitialCache,int fNB10Syms) :
		 wPool(),
		 wMap(cTypeInitialCache)
{
	pfnCbFosym = (CB (__fastcall *)(PSYM psym))(fNB10Syms ? &cbForSymNB10 : &cbForSymNB09);
}

int __cdecl
WidenTi::fCreate
(struct WidenTi *& ppwti,
		 unsigned int cTypeInitialCache,
		 int fNB10Syms
)
{
	
	ppwti = new WTI(cTypeInitialCache,fNB10Syms);
	return ppwti!=NULL;
}




