#include "pdbimpl.h"
#include "dbiimpl.h"
#include "srcimpl.h"


bool SrcCommon::Add(struct SrcHeader const *,void const *)
{
	__debugbreak();
	return false;
}

bool SrcCommon::QueryByName(char const *,struct SrcHeaderOut *) const 
{
	__debugbreak();
	return false;
}






#ifdef PDB_MT
SrcImpl::SrcImpl(PDB * ppdb,bool (*pfnClose)(PDB *))
#else
SrcImpl::SrcImpl(PDB * ppdb)
#endif
{
	
}

SrcImpl::~SrcImpl()
{
	
}


bool SrcImpl::Close()
{
	__debugbreak();
	return false;
}

bool SrcImpl::Remove(IN SZ_CONST szFile)
{
	__debugbreak();
	return false;
}

bool SrcImpl::GetData(IN PCSrcHeaderOut pcsrcheader, OUT void * pvData) const
{
	__debugbreak();
	return false;
}

bool SrcImpl::GetEnum(OUT EnumSrc ** ppenum) const
{
	__debugbreak();
	return false;
}

bool SrcImpl::GetHeaderBlock(SrcHeaderBlock &shb) const
{
	__debugbreak();
	return false;
}

bool SrcImpl::RemoveW(__in_z wchar_t *wcsFile)
{
	__debugbreak();
	return false;
}
bool SrcImpl::QueryByNameW(__in_z wchar_t *wcsFile, OUT PSrcHeaderOut psrcheaderOut) const
{
	__debugbreak();
	return false;
}
bool SrcImpl::AddW(PCSrcHeaderW psrcheader, const void * pvData)
{
	__debugbreak();
	return false;
}

bool SrcImpl::internalInit(bool)
{
	__debugbreak();
	return false;
}