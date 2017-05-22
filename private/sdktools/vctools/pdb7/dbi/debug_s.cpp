#include "prefast.h"
#include "pdbimpl.h"
#include "dbiimpl.h"
#include <stdio.h>
#include "debug_s.h"


IID IID_IDebugSStringTable;
IID IID_IDebugSFileInfo;
IID IID_IDebugSFrameData;
IID IID_IDebugSLines;

#define DbgBuffSize (0x200UL)

BOOL trace_(TR tr, const char* szFmt, ...)
{
	char buff[DbgBuffSize];
	va_list args;
	va_start(args, szFmt);
	_vsnprintf(buff, DbgBuffSize - 1, szFmt, args);
	buff[DbgBuffSize - 1] = 0;
	OutputDebugStringA(buff);
	va_end(args);
	return 1;
}
BOOL traceW_(TR tr, const wchar_t* szFmt, ...)
{
	wchar_t buff[DbgBuffSize];
	va_list args;
	va_start(args, szFmt);
	_vsnwprintf(buff, DbgBuffSize - 1, szFmt, args);
	buff[DbgBuffSize - 1] = 0;
	OutputDebugStringW(buff);
	va_end(args);
	return 1;
}

IDebugSSubSection::IDebugSSubSection()
{

}
IDebugSSubSection::~IDebugSSubSection()
{

}

int IDebugSSubSection::remap(MapStrs*)
{
	__debugbreak();
	return 0;
}
int IDebugSSubSection::Type()
{
	__debugbreak();
	return 0;
}
int IDebugSSubSection::QueryInterface(IID riid, void **ppInterface)
{
	__debugbreak();
	return 0;
}
int IDebugSSubSection::GetRawBytes(PB* pb)
{
	__debugbreak();
	return 0;
}
int IDebugSSubSection::GetData(PB * pb)
{
	__debugbreak();
	return 0;
}



IDebugSStringEnum::IDebugSStringEnum()
{

}
int IDebugSStringEnum::QueryInterface(IID riid, void **ppInterface)
{
	__debugbreak();
	return 0;
}
int IDebugSStringEnum::Get(wchar_t *,DWORD *,DWORD *)
{
	__debugbreak();
	return 0;
}
int IDebugSStringEnum::Next()
{
	__debugbreak();
	return 0;
}
int IDebugSStringEnum::Reset()
{
	__debugbreak();
	return 0;
}
int IDebugSStringEnum::clone(IDebugSStringEnum**)
{
	__debugbreak();
	return 0;
}




IDebugSSubSectionEnum::IDebugSSubSectionEnum()
{

}
int IDebugSSubSectionEnum::QueryInterface(IID riid, void **ppInterface)
{
	__debugbreak();
	return 0;
}

int IDebugSSubSectionEnum::Get(IDebugSSubSection** idsss)
{
	__debugbreak();
	return 0;
}

int IDebugSSubSectionEnum::Next()
{
	__debugbreak();
	return 0;
}

int IDebugSSubSectionEnum::Reset()
{
	__debugbreak();
	return 0;
}

int IDebugSSubSectionEnum::clone(IDebugSSubSectionEnum **)
{
	__debugbreak();
	return 0;
}






IDebugSFileEnum::IDebugSFileEnum(unsigned char *,unsigned int,IDebugSFileInfo *)
{
	
}
int IDebugSFileEnum::QueryInterface(IID riid, void **ppInterface)
{
	__debugbreak();
	return 0;
}

int IDebugSFileEnum::Get(DWORD *,DWORD *,int,int,int)
{
	__debugbreak();
	return 0;
}

int IDebugSFileEnum::Next()
{
	__debugbreak();
	return 0;
}

int IDebugSFileEnum::Reset()
{
	__debugbreak();
	return 0;
}


int IDebugSFileEnum::clone(IDebugSFileEnum **)
{
	__debugbreak();
	return 0;
}

int IDebugSFileEnum::AddRef()
{
	__debugbreak();
	return 0;
}





IDebugSFrameDataEnum::IDebugSFrameDataEnum(tagFRAMEDATA *,DWORD,IDebugSFrameData *)
{
	
}
IDebugSFrameDataEnum::~IDebugSFrameDataEnum()
{
	
}
int IDebugSFrameDataEnum::QueryInterface(IID riid, void **ppInterface)
{
	__debugbreak();
	return 0;
}

int IDebugSFrameDataEnum::Get(IDebugSFrameData**)
{
	__debugbreak();
	return 0;
}

int IDebugSFrameDataEnum::Next()
{
	__debugbreak();
	return 0;
}

int IDebugSFrameDataEnum::reset()
{
	__debugbreak();
	return 0;
}

int IDebugSFrameDataEnum::clone(IDebugSFrameDataEnum **)
{
	__debugbreak();
	return 0;
}





IDebugSLineEnum::IDebugSLineEnum(ulong,CV_Line_t *,CV_Column_t *,IDebugSLines *)
{
	
}
IDebugSLineEnum::~IDebugSLineEnum()
{
	
}
int IDebugSLineEnum::QueryInterface(IID riid, void **ppInterface)
{
	__debugbreak();
	return 0;
}
int IDebugSLineEnum::Next()
{
	__debugbreak();
	return 0;
}
int IDebugSLineEnum::Get(CV_Line_t *,CV_Column_t *)
{
	__debugbreak();
	return 0;
}



IDebugSLineBlockEnum::IDebugSLineBlockEnum(unsigned char *,unsigned int,DWORD,IDebugSLines *,unsigned char *)
{
	
}
int IDebugSLineBlockEnum::fVerify(unsigned char *,unsigned int,DWORD)
{
	__debugbreak();
	return 0;
}
int IDebugSLineBlockEnum::columns()
{
	__debugbreak();
	return 0;
}
int IDebugSLineBlockEnum::clone(IDebugSLineBlockEnum * *)
{
	__debugbreak();
	return 0;
}
int IDebugSLineBlockEnum::Reset()
{
	__debugbreak();
	return 0;
}
int IDebugSLineBlockEnum::Release()
{
	__debugbreak();
	return 0;
}
int IDebugSLineBlockEnum::QueryInterface(IID riid, void **ppInterface)
{
	__debugbreak();
	return 0;
}
int IDebugSLineBlockEnum::Next()
{
	__debugbreak();
	return 0;
}
int IDebugSLineBlockEnum::GetSegOffset(ushort *,DWORD *,DWORD *)
{
	__debugbreak();
	return 0;
}
int IDebugSLineBlockEnum::GetLineEnum(IDebugSLineEnum **)
{
	__debugbreak();
	return 0;
}
int IDebugSLineBlockEnum::GetFileId(DWORD *)
{
	__debugbreak();
	return 0;
}
int IDebugSLineBlockEnum::Get(DWORD *,CV_Line_t * *,CV_Column_t **)
{
	__debugbreak();
	return 0;
}



IDebugSStringTable::IDebugSStringTable(unsigned char *,unsigned int,IDebugSSectionReader *)
{
	
}
int IDebugSStringTable::QueryInterface(IID riid, void **ppInterface)
{
	__debugbreak();
	return 0;
}

int IDebugSStringTable::GetStringEnum(IDebugSStringEnum * *)
{
	__debugbreak();
	return 0;
}

int IDebugSStringTable::GetStringByOff(DWORD,char * *)
{
	__debugbreak();
	return 0;
}




IDebugSFileInfo::IDebugSFileInfo(unsigned char *,unsigned int,IDebugSSectionReader *)
{
	
}
int IDebugSFileInfo::remap(MapStrs *)
{
	__debugbreak();
	return 0;
}

int IDebugSFileInfo::QueryInterface(IID riid, void **ppInterface)
{
	__debugbreak();
	return 0;
}

int IDebugSFileInfo::GetFileEnum(IDebugSFileEnum * *)
{
	__debugbreak();
	return 0;
}

int IDebugSFileInfo::GetFileById(DWORD,DWORD *,DWORD *,unsigned char * *,DWORD *)
{
	__debugbreak();
	return 0;
}



IDebugSFrameData::IDebugSFrameData(unsigned char *,unsigned int,IDebugSSectionReader *)
{
	
}
int IDebugSFrameData::remap(MapStrs *)
{
	__debugbreak();
	return 0;
}

int IDebugSFrameData::QueryInterface(IID riid, void **ppInterface)
{
	__debugbreak();
	return 0;
}

int IDebugSFrameData::GetSectionRva(DWORD *)
{
	__debugbreak();
	return 0;
}

int IDebugSFrameData::GetFrameDataEnum(IDebugSFrameDataEnum * *)
{
	__debugbreak();
	return 0;
}

int IDebugSFrameData::GetFrameDataByRva(DWORD,tagFRAMEDATA *)
{
	__debugbreak();
	return 0;
}

int IDebugSFrameData::ApplyReloc()
{
	__debugbreak();
	return 0;
}





IDebugSLines::IDebugSLines(unsigned char *,unsigned int,IDebugSSectionReader *)
{
	
}
int IDebugSLines::QueryInterface(IID riid, void **ppInterface)
{
	__debugbreak();
	return 0;
}
int IDebugSLines::GetSegOffset(ushort *,DWORD *,DWORD *)
{
	__debugbreak();
	return 0;
}
int IDebugSLines::GetFlags()
{
	__debugbreak();
	return 0;
}
int IDebugSLines::GetBlockEnum(IDebugSLineBlockEnum * *)
{
	__debugbreak();
	return 0;
}



IDebugSSectionReader::IDebugSSectionReader(unsigned char *,unsigned int)
{
	
}
IDebugSSectionReader::~IDebugSSectionReader()
{
	
}
int IDebugSSectionReader::QueryInterface(IID riid, void **ppInterface)
{
	__debugbreak();
	return 0;
}
int IDebugSSectionReader::GetStringTable(IDebugSStringTable **)
{
	__debugbreak();
	return 0;
}
int IDebugSSectionReader::GetSectionEnum(IDebugSSubSectionEnum **)
{
	__debugbreak();
	return 0;
}
int IDebugSSectionReader::GetFileInfo(IDebugSFileInfo * *)
{
	__debugbreak();
	return 0;
}
DSR_EC IDebugSSectionReader::GetLastError()
{
	__debugbreak();
	return DSR_EC_CORRUPT;
}


IDebugSSectionWriter::IDebugSSectionWriter(unsigned char *,unsigned int)
{
	
}
IDebugSSectionWriter::~IDebugSSectionWriter()
{
	
}
int IDebugSSectionWriter::InitBuffers()
{
	__debugbreak();
	return 0;
}
int IDebugSSectionWriter::GetSectionRelocs(char**)
{
	__debugbreak();
	return 0;
}
int IDebugSSectionWriter::GetSectionBytes(PB* pb)
{
	__debugbreak();
	return 0;
}
int IDebugSSectionWriter::EndSection()
{
	__debugbreak();
	return 0;
}
int IDebugSSectionWriter::EndSection(int)
{
	__debugbreak();
	return 0;
}
int IDebugSSectionWriter::StartSection(int,int,int)
{
	__debugbreak();
	return 0;
}
int IDebugSSectionWriter::StartSectionSymId(int)
{
	__debugbreak();
	return 0;
}
int IDebugSSectionWriter::AddLine(int,int,int,int)
{
	__debugbreak();
	return 0;
}
int IDebugSSectionWriter::AddLine(int,int,int,int,int)
{
	__debugbreak();
	return 0;
}
int IDebugSSectionWriter::AddLineWithColumn(int,int,int,int,int,int,int)
{
	__debugbreak();
	return 0;
}
int IDebugSSectionWriter::AddSourceFile(const wchar_t *,char*,int,int)
{
	__debugbreak();
	return 0;
}
int IDebugSSectionWriter::AppendToSymbols(char*,int,DWORD*)
{
	__debugbreak();
	return 0;
}
int IDebugSSectionWriter::AppendRelocation(int,int,int)
{
	__debugbreak();
	return 0;
}
int IDebugSSectionWriter::AddUtf8String(char*)
{
	__debugbreak();
	return 0;
}
int IDebugSSectionWriter::AddString(wchar_t*)
{
	__debugbreak();
	return 0;
}
int IDebugSSectionWriter::AddFrameData(struct tagFRAMEDATA*)
{
	__debugbreak();
	return 0;
}






