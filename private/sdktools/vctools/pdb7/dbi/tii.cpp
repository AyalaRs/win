// Type Index Iterator implementation
// (enumerates type index fields in symbols and types)

#include "prefast.h"
#define CVR_IMP
#include "cvr.h"
#include "assert_.h"
#include "trace.h"
typedef USHORT HASH;

void NYI();

////////////////////////////////////////////////////////////////////////////////////
// Build tables to run symbol TI and type TI iterators.

static PB pbNum(void* pv);
static PB pbName(void* pv);
static ST stManyRegName(PSYM psym);
static ST stProcRefName(PSYM psym);
static ST stConstantName(PSYM psym);

static PB pbOneMethodNameSt(lfOneMethod *plf);
static PB pbOneMethodNameSz(lfOneMethod *plf);
static PB pbOneMethodNameSt_16t(lfOneMethod_16t *plf);

#if defined(_DEBUG)
#define S(x) x
#else
#define S(x) 0
#endif

// include pass one: define rgibtiX tables ("group of byte offsets to ti's in an X")


#define off(s, m) ((IB)(offsetof(s, m)))


#define pbEndFn(s,e) PB pbEnd##s(void* pv) { lf##s* p = (lf##s*)pv; return (PB)(e); }                   
#define t0(l)
#define t0m(l, s, e)             pbEndFn(s,e)
#define t1(l, s, m1)             IB rgibti##s[] = { off(lf##s, m1) };
#define t1m(l, s, m1, e)         IB rgibti##s[] = { off(lf##s, m1) }; pbEndFn(s,e)
#define t1x(l, s, m1)
#define t2(l, s, m1, m2)         IB rgibti##s[] = { off(lf##s, m1),  off(lf##s, m2) };
#define t2m(l, s, m1, m2, e)     IB rgibti##s[] = { off(lf##s, m1),  off(lf##s, m2) }; pbEndFn(s,e)
#define t2x(l, s, m1, m2)
#define t3(l, s, m1, m2, m3)     IB rgibti##s[] = { off(lf##s, m1),  off(lf##s, m2), off(lf##s, m3) };
#define t4(l, s, m1, m2, m3, m4) IB rgibti##s[] = { off(lf##s, m1),  off(lf##s, m2), off(lf##s, m3), off(lf##s, m4) };
#define tf(l, f)                 extern TI* Pti##f(PTYPE ptype, int iib, PB* ppb, PB pbEnd);
#define tn(l, s, n, m)           IB rgibti##s[] = { off(lf##s, n),   off(lf##s, m) };

const int iibNTypes = 0;         /* rgibti...[iibNTypes] == 'n' above */
const int iibRgti   = 1;         /* rgibti...[iibRgti]   == 'm' above */

#define s0(s, gf)
#define s0n(s, st, gf)         
#define s0f(s, gf, f)          
#define s1(s, st, m1, gf)            IB rgibti##st[] = { off(st, m1), (IB)(-1) };
#define s1f(s, st, m1, gf, f)        IB rgibti##st[] = { off(st, m1), (IB)(-1) };
#define s1x(s, st, m1, gf)
#define s2(s, st, m1, m2, gf)        IB rgibti##st[] = { off(st, m1), off(st, m2), (IB)(-1) };
#define s2x(s, st, m1, m2, gf)

#include "cvinfo.dat"

#undef t0
#undef t0m
#undef t1
#undef t1m
#undef t1x
#undef t2
#undef t2m
#undef t2x
#undef t3
#undef t4
#undef tf
#undef tn

#undef s0
#undef s0n
#undef s0f
#undef s1
#undef s1x
#undef s1f
#undef s2
#undef s2x

// include pass two: build the master type/TI table


#define cibMac          5
#define cibFunction     cibMac
#define cibNTypes       (cibMac+1)

#define t0(l)                     { l, S(#l), 0, 0 },
#define t0m(l, s, e)              { l, S(#l), 0, 0, 0, pbEnd##s },
#define t1(l, s, m1)              { l, S(#l), 1, rgibti##s, 0, 0 },
#define t1m(l, s, m1, e)          { l, S(#l), 1, rgibti##s, 0, pbEnd##s },
#define t1x(l, s, m1)             { l, S(#l), 1, rgibti##s, 0, 0 },
#define t2(l, s, m1, m2)          { l, S(#l), 2, rgibti##s, 0, 0 },
#define t2m(l, s, m1, m2, e)      { l, S(#l), 2, rgibti##s, 0, pbEnd##s },
#define t2x(l, s, m1, m2)         { l, S(#l), 2, rgibti##s, 0, pbEnd##s },
#define t3(l, s, m1, m2, m3)      { l, S(#l), 3, rgibti##s, 0, 0 },
#define t4(l, s, m1, m2, m3, m4)  { l, S(#l), 4, rgibti##s, 0, 0 },
#define tf(l, f)                  { l, S(#l), cibFunction, 0, Pti##f, 0 },
#define tn(l, s, n, m)            { l, S(#l), cibNTypes, rgibti##s, 0, 0 },

#define s0(s, gf)
#define s0n(s, st, gf)         
#define s0f(s, gf, f)          
#define s1(s, st, m1, gf)
#define s1f(s, st, m1, gf, f)
#define s1x(s, st, m1, gf)
#define s2(s, st, m1, m2, gf)
#define s2x(s, st, m1, m2, gf)


TYTI rgtyti[] = {
    #include "cvinfo.dat"
};
const int itytiMax = sizeof(rgtyti)/sizeof(rgtyti[0]);

#undef t0
#undef t0m
#undef t1
#undef t1m
#undef t1x
#undef t2
#undef t2m
#undef t2x
#undef t3
#undef t4
#undef tf
#undef tn

#undef s0
#undef s0n         
#undef s0f         
#undef s1
#undef s1x
#undef s1f
#undef s2
#undef s2x

// include pass three: build the master symbol/TI table

#define t0(l)
#define t0m(l, s, e)
#define t1(l, s, m1)
#define t1m(l, s, m1, e)
#define t1x(l, s, m1)
#define t2(l, s, m1, m2)
#define t2m(l, s, m1, m2, e)
#define t2x(l, s, m1, m2)
#define t3(l, s, m1, m2, m3)
#define t4(l, s, m1, m2, m3, m4)
#define tf(l, f)
#define tn(l, s, n, m)

#define s0(s, gf)              { s, S(#s), 0, 0, gf, 0, 0, 0 },
#define s0n(s, st, gf)         { s, S(#s), off(st, name), 0, gf, 0, 0, 0 },
#define s0f(s, gf, f)          { s, S(#s), 0, &f, gf, 0, 0, 0 },
#define s1(s, st, m1, gf)      { s, S(#s), off(st, name), 0, gf, 0, 1, &rgibti##st[0] },
#define s1f(s, st, m1, gf, f)  { s, S(#s), 0, &f, gf, 0, 1, rgibti##st },
#define s1x(s, st, m1, gf)     { s, S(#s), off(st, name), 0, gf, 0, 1, rgibti##st },
#define s2(s, st, m1, m2, gf)  { s, S(#s), 0, 0, gf, 0, 2, rgibti##st },
#define s2x(s, st, m1, m2, gf) { s, S(#s), 0, 0, gf, 0, 2, rgibti##st },

SYTI rgsyti[] = {
#include "cvinfo.dat"
};

const int isytiMax = sizeof(rgsyti)/sizeof(rgsyti[0]);

#undef t0
#undef t0m
#undef t1
#undef t1m
#undef t1x
#undef t2
#undef t2m
#undef t2x
#undef t3
#undef t4
#undef tf
#undef tn

#undef s0
#undef s0n         
#undef s0f         
#undef s1
#undef s1x
#undef s1f
#undef s2
#undef s2x


// Return the number of bytes in the numeric field which pb addresses.
static CB cbNum(PB pb)
{
    USHORT leaf = *(USHORT*)pb;
    if (leaf < LF_NUMERIC)
        return sizeof(leaf);
    else switch (leaf) {
    case LF_CHAR:
        return sizeof(leaf) + sizeof(char);
    case LF_SHORT:
        return sizeof(leaf) + sizeof(short);
    case LF_USHORT:
        return sizeof(leaf) + sizeof(USHORT);
    case LF_LONG:
        return sizeof(leaf) + sizeof(long);
    case LF_ULONG:
        return sizeof(leaf) + sizeof(ULONG);
    default:
        assert(0);
        return 0;
    }
}

// Return the address of the byte following the numeric field which pv addresses.
static PB pbNum(void* pv)
{
    PB pb = (PB)pv;
    return pb + cbNum(pb);
}

// Return the address of the byte following the (length preceded) name field which pv addresses.
static PB pbName(void* pv)
{
    PB pb = (PB)pv;
    return pb + *pb + 1;
}

// Return the address of the byte following the (length preceded) name field in a
// lfOneMethod record
static PB pbOneMethodNameSt_16t(lfOneMethod_16t *plf)
{
    return pbName((char *)(plf->vbaseoff)  + 
        ((plf->attr.mprop == CV_MTintro) ? sizeof (unsigned long) : 0));
}
static PB pbOneMethodNameSt(lfOneMethod *plf)
{
    return pbName((char *)(plf->vbaseoff)  + 
        ((plf->attr.mprop == CV_MTintro) ? sizeof (unsigned long) : 0));
}
static PB pbOneMethodNameSz(lfOneMethod *plf)
{
    return (PB)(char *)(plf->vbaseoff  + strlen((char *)plf->vbaseoff));
}
// Return the address of the byte following the (length preceded) name field in a
// lfOneMethod record

//////////////////////////////////////////////////////////////////////////////
// Perfect hashing of type leaf's and symbol rectyp's

#define hashTypeLeafMax ( \
                LF_ENDOFLEAFRECORD - LF_TYPESERVER + 1 + \
                LF_MANAGED_ST - LF_BCLASS + 1 + \
                LF_DIMVARLU - LF_SKIP + 1 + \
                LF_OEM2 - LF_MODIFIER + 1 + \
                LF_MEMBERMODIFY_16t - LF_BCLASS_16t + 1 + \
                LF_REFSYM - LF_SKIP_16t + 1 +  \
                LF_TYPESERVER_ST  + 1)


// Return the perfect hash of the type record leaf.
//
// Note: depends upon cvinfo.h LF_* assignments being grouped
//   (0..LF_TYPESERVER_ST, LF_SKIP_16t..LF_REFSYM, LF_BCLASS_16t..LF_MEMBERMODIFY_16t)
//
HASH __fastcall hashTypeLeaf(USHORT leaf){

    if (leaf <= LF_TYPESERVER_ST)
        return leaf;
    
    if (leaf <  LF_SKIP_16t)
        return 0;
    
    if (leaf <= LF_REFSYM)
        return leaf - LF_SKIP_16t + LF_TYPESERVER_ST + 1;
    
    if (leaf < LF_BCLASS_16t)
        return 0;

    if (leaf <= LF_MEMBERMODIFY_16t)
        return leaf - LF_BCLASS_16t + 
                LF_REFSYM - LF_SKIP_16t + 1 + 
                LF_TYPESERVER_ST + 1;

    if (leaf < LF_MODIFIER)
        return 0;
    
    if (leaf <= LF_OEM2)
        return leaf - LF_MODIFIER +
                LF_MEMBERMODIFY_16t - LF_BCLASS_16t + 1 +
                LF_REFSYM - LF_SKIP_16t + 1 + 
                LF_TYPESERVER_ST + 1;
    if (leaf < LF_SKIP)
        return 0;
    
    if (leaf <= LF_DIMVARLU)
        return leaf - LF_SKIP +
                LF_OEM2 - LF_MODIFIER + 1 +
                LF_MEMBERMODIFY_16t - LF_BCLASS_16t + 1 +
                LF_REFSYM - LF_SKIP_16t + 1 + 
                LF_TYPESERVER_ST + 1;
                
    if (leaf < LF_BCLASS)
        return 0;
    
    if (leaf <= LF_MANAGED_ST)
        return leaf - LF_BCLASS +
                LF_DIMVARLU - LF_SKIP + 1 +
                LF_OEM2 - LF_MODIFIER + 1 +
                LF_MEMBERMODIFY_16t - LF_BCLASS_16t + 1 +
                LF_REFSYM - LF_SKIP_16t + 1 + 
                LF_TYPESERVER_ST + 1;
    
    if (leaf < LF_TYPESERVER)
        return 0;
    
    if (leaf <= LF_ENDOFLEAFRECORD)
        return leaf - LF_TYPESERVER +
                LF_MANAGED_ST - LF_BCLASS + 1 +
                LF_DIMVARLU - LF_SKIP + 1 +
                LF_OEM2 - LF_MODIFIER + 1 +
                LF_MEMBERMODIFY_16t - LF_BCLASS_16t + 1 +
                LF_REFSYM - LF_SKIP_16t + 1 + 
                LF_TYPESERVER_ST + 1;
    return 0;
}

#define hashSymRecTypMax (  S_RECTYPE_LAST  - S_ST_MAX +     \
                            S_UNAMESPACE_ST - S_TI16_MAX     + \
                            S_OEM           - S_PROCREF_ST   + 1 +  \
                            S_GPROCMIPS_16t - S_LPROCMIPS_16t + 1 + \
                            S_SLINK32       - S_BPREL32_16t   + 1 + \
                            S_REGREL16      - S_BPREL16       + 1 + \
                            S_ENTRYTHIS     + 1)

// Return the perfect hash of the symbol record leaf.
//
// Note: depends upon cvinfo.h S_* assignments being grouped
//   (0..S_ENTRYTHIS, S_BPREL16..S_REGREL16, S_BPREL32_16t..S_SLINK32, S_LPROCMIPS_16t..S_GPROCMIPS_16t,
//    S_PROCREF_ST..S_LPROCREF_ST)
//
HASH __fastcall hashSymRecTyp(USHORT rectyp) {
    if (rectyp <= S_ENTRYTHIS)
        return rectyp;
    
    if (rectyp < S_BPREL16)
        return 0;
    
    if (rectyp <= S_REGREL16)
        return rectyp - S_BPREL16 + S_ENTRYTHIS + 1;

    if (rectyp < S_BPREL32_16t)
        return 0;
    
    if (rectyp <= S_SLINK32)
        return rectyp - S_BPREL32_16t + S_REGREL16 - S_BPREL16 + 1 + S_ENTRYTHIS + 1;

    if (rectyp < S_LPROCMIPS_16t)
        return 0;
    
    if (rectyp <= S_GPROCMIPS_16t)
        return rectyp - S_LPROCMIPS_16t +
               S_SLINK32 - S_BPREL32_16t + 1 +
               S_REGREL16  - S_BPREL16 + 1 +
               S_ENTRYTHIS             + 1;
    
    if (rectyp < S_PROCREF_ST)
        return 0;
    
    if (rectyp <= S_OEM)
        return rectyp - S_PROCREF_ST +
               S_GPROCMIPS_16t - S_LPROCMIPS_16t + 1 +
               S_SLINK32 - S_BPREL32_16t   + 1 +
               S_REGREL16  - S_BPREL16   + 1 +
               S_ENTRYTHIS               + 1;
    if (rectyp <= S_TI16_MAX)
        return 0;
    
    if (rectyp <= S_UNAMESPACE_ST)
        return rectyp - S_TI16_MAX + 
                S_LPROCREF_ST - S_PROCREF_ST +1 +
                S_GPROCMIPS_16t - S_LPROCMIPS_16t + 1 +
                S_SLINK32 - S_BPREL32_16t   + 1 +
                S_REGREL16  - S_BPREL16   + 1 +
                S_ENTRYTHIS               + 1;
    if (rectyp <= S_ST_MAX)
        return 0;
    
    if (rectyp <= S_RECTYPE_LAST)
        return rectyp - S_ST_MAX + 
                S_UNAMESPACE_ST - S_TI16_MAX + 1 +
                S_LPROCREF_ST - S_PROCREF_ST +1 +
                S_GPROCMIPS_16t - S_LPROCMIPS_16t + 1 +
                S_SLINK32 - S_BPREL32_16t   + 1 +
                S_REGREL16  - S_BPREL16   + 1 +
                S_ENTRYTHIS               ;

    return 0;
}


/////////////////////////////////////////////////////////////////////////////
// Mappings from type leaf to ptyti and from symbol rectyp to psyti

TYTI* mphashptyti[hashTypeLeafMax];
SYTI* mphashpsyti[hashSymRecTypMax];

struct InitHash {
    InitHash();
} initHash;

// Initialize the mphashptyti and mphashpsyti tables.

InitHash::InitHash()
{
    for (TYTI* ptyti = rgtyti; ptyti < rgtyti + itytiMax; ptyti++) {
        HASH hash = hashTypeLeaf(ptyti->leaf);
		trace((trMap,
				"hash %d/%d leaf %04X \n",
				(CB)hash,hashTypeLeafMax,ptyti->leaf,ptyti->sz));
        assert(!mphashptyti[hash] && hash < hashTypeLeafMax);

        mphashptyti[hash] = ptyti;
    }
    for (SYTI* psyti = rgsyti; psyti < rgsyti + isytiMax; psyti++) {
        HASH hash = hashSymRecTyp(psyti->rectyp);
		trace((trMap,
				"hash %d/%d rectyp %04X \n",
				(CB)hash,hashSymRecTypMax,psyti->rectyp,psyti->sz));
        assert(!mphashpsyti[hash] && hash < hashSymRecTypMax);
        mphashpsyti[hash] = psyti;
    }
}

//////////////////////////////////////////////////////////////////////////////
// Symbol and Type TI Iterators

inline SYTI* psytiFromPsym(PSYM psym) 
{
    SYTI* psyti;
    psyti = mphashpsyti[hashSymRecTyp(psym->rectyp)];
    dassert(psyti && psyti->rectyp == psym->rectyp);
    return psyti;
}

SymTiIter::SymTiIter(PSYM psym_)
    : psym(psym_), iib(-1)
{
    psyti = psytiFromPsym(psym);
}

inline TYTI* ptytiFromLeaf(USHORT leaf)
{
    TYTI* ptyti = mphashptyti[hashTypeLeaf(leaf)];
    dassert(ptyti && ptyti->leaf == leaf);
    return ptyti;
}

void TypeTiIter::init()
{
    ptyti = ptytiFromLeaf(*pleaf);
    iib = -1;
}

TypeTiIter::TypeTiIter(TYPTYPE* ptype_): 
    ptype(ptype_), 
    pleaf(&ptype->leaf), 
    pbEnd(pbEndType(ptype)),
    iib(-1), 
    pti(0), 
    ptyti(0), 
    isFieldList(*pleaf == LF_FIELDLIST_16t || *pleaf == LF_FIELDLIST)
{
    if (isFieldList) {
        lfFieldList* pList = (lfFieldList*)&ptype->leaf;
        pleaf = (USHORT*)&pList->data;
        if ((PB)pleaf < pbEnd)
            init();
    }
    else
        init();
}
 
BOOL TypeTiIter::next()
{
retry:
    if (!ptyti)
        return FALSE;
    else if (ptyti->cib < cibMac)
        pti = (++iib < ptyti->cib) ? (TI*)((PB)pleaf + ptyti->rgibTI[iib]) : 0;
    else if (ptyti->cib == cibFunction) {
        pti = ptyti->pfn(ptype, ++iib, &pbFnState, pbEnd);
    }
    else {
        dassert(ptyti->cib == cibNTypes);
        if (++iib < (int)*(USHORT*)((PB)pleaf + ptyti->rgibTI[iibNTypes]))
            pti = (TI*)((PB)pleaf + ptyti->rgibTI[iibRgti]) + iib;
        else
            pti = 0;
    }
    if (!pti && isFieldList && nextField()) {
        // this field in a field list was followed by another; retry
        goto retry;
    }
    return !!pti;
}

// Find where the current field ends, and if we haven't exhaused the list,
// advance to the next field.  Return TRUE if there is another field.
BOOL TypeTiIter::nextField()
{
    dassert(isFieldList);

    // find end of field sub-record
    if (!(ptyti && ptyti->pfnPbAfter))
        return FALSE;
    PB pbAfter = ptyti->pfnPbAfter(pleaf);

    // skip over alignment padding as necessary
    if ((pbAfter < pbEnd) && (*pbAfter > LF_PAD0)) 
        pbAfter += *pbAfter & 0xf;

    // there's another field if we haven't moved past the end of the record
    if (pbAfter < pbEnd) {
        pleaf = (USHORT*)pbAfter;
        init();
        return TRUE;
    } else
        return FALSE;
}

// Given a fieldlist type record, find the next field sub-record with the
// given leaf value.  Return a pointer to the leaf or 0 if not found.
//
PB TypeTiIter::pbFindField(unsigned leaf)
{
    dassert(ptype->leaf == LF_FIELDLIST_16t);

    while (*pleaf != leaf)
        if (!nextField())
            return 0;

    return (PB)pleaf;
}

PB TypeTiIter::pbEndCurFieldSansPad()
{
    PB pb=0;
    if (!isFieldList)
        goto done;
    if (!ptyti)
        goto done;

    pb = ptyti->pfnPbAfter(ptype);
done:
    return pb;
}

// Return the address of the iti'th TI in this LF_POINTER_16t record, or 0 if no more.
TI* PtiPointer(PTYPE ptype, int iti, PB*, PB)
{
    lfPointer* pPtr = (lfPointer*)&ptype->leaf;

    switch (iti) {
    case 0:
        return &pPtr->utype;
    case 1:
        switch (pPtr->attr.ptrmode) {
        case CV_PTR_MODE_PTR:
        case CV_PTR_MODE_REF:
            if (pPtr->attr.ptrtype == CV_PTR_BASE_SEG) {
                NYI();
                return 0;
            }
            else if (pPtr->attr.ptrtype == CV_PTR_BASE_TYPE)
                return &pPtr->pbase.btype.index;
            else
                return 0;
        case CV_PTR_MODE_PMEM:
        case CV_PTR_MODE_PMFUNC:
            return &pPtr->pbase.pm.pmclass;
        default:
            assert(0);
            return 0;
        }
        break;
    case 2:
        switch (pPtr->attr.ptrmode) {
        case CV_PTR_MODE_PTR:
        case CV_PTR_MODE_REF:
            if (pPtr->attr.ptrtype == CV_PTR_BASE_SEG) {
                NYI();
                return 0;
            }
            else
                return 0;
        case CV_PTR_MODE_PMEM:
        case CV_PTR_MODE_PMFUNC:
            return 0;
        default:
            assert(0);
            return 0;
        }
        break;
    default:
        assert(0);
        return 0;
    }
}
TI* PtiPointer_16t(PTYPE ptype, int iti, PB*, PB)
{
    lfPointer_16t* pPtr = (lfPointer_16t*)&ptype->leaf;

    switch (iti) {
    case 0:
        return (TI*)&pPtr->utype;
    case 1:
        switch (pPtr->attr.ptrmode) {
        case CV_PTR_MODE_PTR:
        case CV_PTR_MODE_REF:
            if (pPtr->attr.ptrtype == CV_PTR_BASE_SEG) {
                NYI();
                return 0;
            }
            else if (pPtr->attr.ptrtype == CV_PTR_BASE_TYPE)
                return (TI*)&pPtr->pbase.btype.index;
            else
                return 0;
        case CV_PTR_MODE_PMEM:
        case CV_PTR_MODE_PMFUNC:
            return (TI*)&pPtr->pbase.pm.pmclass;
        default:
            assert(0);
            return 0;
        }
        break;
    case 2:
        switch (pPtr->attr.ptrmode) {
        case CV_PTR_MODE_PTR:
        case CV_PTR_MODE_REF:
            if (pPtr->attr.ptrtype == CV_PTR_BASE_SEG) {
                NYI();
                return 0;
            }
            else
                return 0;
        case CV_PTR_MODE_PMEM:
        case CV_PTR_MODE_PMFUNC:
            return 0;
        default:
            assert(0);
            return 0;
        }
        break;
    default:
        assert(0);
        return 0;
    }
}

// Return the address of the iti'th TI in this LF_LIST record, or 0 if no more.
TI* PtiList(PTYPE ptype, int iti, PB*, PB)
{
    dassert(ptype->leaf == LF_LIST);
    NYI();
    return 0;
}

// Return the address of the iti'th TI in this LF_METHODLIST_16t record, or 0 if no more.
TI* PtiMethodList_16t(PTYPE ptype, int iti, PB* ppb, PB pbEnd)
{
    dassert(ptype->leaf == LF_METHODLIST_16t);
    if (iti == 0) {
        // first call for this type record
        lfMethodList_16t* pList = (lfMethodList_16t*)&ptype->leaf;
        *ppb = (PB)&pList->mList;
    }
    if (*ppb < pbEnd) {
        // review: alignment padding?
        mlMethod* pMethod = (mlMethod*)*ppb;
        TI *pti = &pMethod->index;
        *ppb += offsetof(mlMethod, vbaseoff);
        if (pMethod->attr.mprop == CV_MTintro)
            *ppb += sizeof(ULONG);
        return pti;
    }
    return 0;
}
TI* PtiMethodList(PTYPE ptype, int iti, PB* ppb, PB pbEnd)
{
    dassert(ptype->leaf == LF_METHODLIST);
    if (iti == 0) {
        // first call for this type record
        lfMethodList* pList = (lfMethodList*)&ptype->leaf;
        *ppb = (PB)&pList->mList;
    }
    if (*ppb < pbEnd) {
        // review: alignment padding?
        mlMethod* pMethod = (mlMethod*)*ppb;
        TI *pti = &pMethod->index;
        *ppb += offsetof(mlMethod, vbaseoff);
        if (pMethod->attr.mprop == CV_MTintro)
            *ppb += sizeof(ULONG);
        return pti;
    }
    return 0;
}
// the address of ith dimvar index
inline TI* ptiDimVar(lfDimVar* pDimVar, int iti, int iMac)
{
    TI* pti = (TI*)&pDimVar->typ;
    if (iti < iMac) {
        return pti + iti;
    }
    return 0;
}
inline TI* ptiDimVar(lfDimVar_16t* pDimVar, int iti, int iMac)
{
    TI* pti = (TI*)&pDimVar->typ;
    if (iti < iMac) {
        return pti + iti;
    }
    return 0;
}
TI* PtiDimVarU_16t(PTYPE ptype, int iti, PB* ppb, PB pbEnd)
{
    dassert(ptype->leaf == LF_DIMVARU_16t);
    lfDimVar_16t* pDimVar = (lfDimVar_16t*)&ptype->leaf;
    TI* pti = ptiDimVar(pDimVar, iti,pDimVar->rank + 1);
    dassert ((PB)pti  < pbEnd); 
    return pti;
}

TI* PtiDimVarLU_16t(PTYPE ptype, int iti, PB* ppb, PB pbEnd)
{
    dassert(ptype->leaf == LF_DIMVARU_16t);
    lfDimVar_16t* pDimVar = (lfDimVar_16t*)&ptype->leaf;
    TI* pti = ptiDimVar(pDimVar, iti, (pDimVar->rank * 2) + 1);
    dassert ((PB)pti  < pbEnd); 
    return pti;
}
TI* PtiDimVarU(PTYPE ptype, int iti, PB* ppb, PB pbEnd)
{
    dassert(ptype->leaf == LF_DIMVARU);
    lfDimVar* pDimVar = (lfDimVar*)&ptype->leaf;
    TI* pti = ptiDimVar(pDimVar, iti,pDimVar->rank + 1);
    dassert ((PB)pti  < pbEnd); 
    return pti;
}

TI* PtiDimVarLU(PTYPE ptype, int iti, PB* ppb, PB pbEnd)
{
    dassert(ptype->leaf == LF_DIMVARU);
    lfDimVar* pDimVar = (lfDimVar*)&ptype->leaf;
    TI* pti = ptiDimVar(pDimVar, iti, (pDimVar->rank * 2) + 1);
    dassert ((PB)pti  < pbEnd); 
    return pti;
}
TI* PtiVFTPath_16t(PTYPE ptype, int iti, PB*, PB)
{
    NYI();
    return 0;
}
TI* PtiVFTPath(PTYPE ptype, int iti, PB*, PB)
{
    NYI();
    return 0;
}
CVR_EXPORT BOOL CVRAPI fGetSymName(PSYM psym, OUT ST* pst)
{
    dassert(psym);
    SYTI* psyti = psytiFromPsym(psym);

    dassert(psyti);
    if (psyti == NULL) {
        return FALSE;
    }

    if (psyti->ibName){
        *pst = (ST) ((IB)psym + psyti->ibName);
        return TRUE;
    }
    else if (psyti->pfnstName) {
        *pst = (*(psyti->pfnstName))(psym);
        return TRUE;
    }

    return FALSE;

}

BOOL fGetTypeLeafName(PTYPE ptype, OUT SZ* psz)
{
    TYTI* ptyti = ptytiFromLeaf(ptype->leaf);
    if (ptype) {
        *psz = ptyti->sz;
        return !!*psz;
    }
    else
        return FALSE;
}

CVR_EXPORT BOOL CVRAPI fGetSymRecTypName(PSYM psym, OUT SZ* psz)
{
    SYTI* psyti = psytiFromPsym(psym);
    if (psyti) {
        *psz = psyti->sz;
        return !!*psz;
    }
    else
        return FALSE;
}

static ST stManyRegName(PSYM psym)
{

    dassert(psym);
    dassert(psym->rectyp == S_MANYREG_16t);

    return (ST)pbName(&(((MANYREGSYM*)psym)->count));   // count is like a length preceeded name 

} 

static ST stProcRefName(PSYM psym)
{
    dassert(psym);
    dassert((psym->rectyp == S_PROCREF_ST) || (psym->rectyp == S_LPROCREF_ST));
    
    //there is a hidden name at the end of the record
    return (ST)((PB)psym + psym->reclen + sizeof(psym->reclen));
} 
      
static ST stConstantName(PSYM psym)
{

    dassert(psym);
    dassert(psym->rectyp == S_CONSTANT_16t);

    return (ST)pbNum(&(((CONSTSYM*)psym)->value));  

} 

BOOL fSymIsGlobal(PSYM psym)
{
    dassert(psym);
    SYTI* psyti = psytiFromPsym(psym);
    return psyti->isGlobal;
}

void NYI()
{
}
