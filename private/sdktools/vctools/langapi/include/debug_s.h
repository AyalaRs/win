#ifndef _DEBUG_S_H_
#define _DEBUG_S_H_

enum DSR_EC{
	DSR_EC_OK,
	DSR_EC_USAGE,
	DSR_EC_OUT_OF_MEMORY,
	DSR_EC_CORRUPT,
	DSR_EC_CORRUPT2,

	DSR_EC_MAX
};

#ifndef IID
#define IID GUID
#endif

extern IID IID_IDebugSStringTable;
extern IID IID_IDebugSFileInfo;
extern IID IID_IDebugSFrameData;
extern IID IID_IDebugSLines;


class IDebugSSubSection
{
public:
	IDebugSSubSection();
	~IDebugSSubSection();
	int remap(MapStrs*);
	int Type();
	int QueryInterface(IID riid, void **ppInterface);
	int GetRawBytes(PB* pb);
	int GetData(PB * pb);
};


class IDebugSStringEnum
{
public:
	IDebugSStringEnum();
	int QueryInterface(IID riid, void **ppInterface);
	int Get(wchar_t *,DWORD *,DWORD *);
	int Next();
	int Reset();
	int clone(IDebugSStringEnum**);
};

class IDebugSSubSectionEnum
{
public:
	IDebugSSubSectionEnum();
	int QueryInterface(IID riid, void **ppInterface);
	int Get(IDebugSSubSection** idsss);
	int Next();
	int Reset();
	int clone(IDebugSSubSectionEnum **);
};

class IDebugSFileInfo;
class IDebugSFileEnum
{
public:
	IDebugSFileEnum(unsigned char *,unsigned int,IDebugSFileInfo *);
	int QueryInterface(IID riid, void **ppInterface);
	int Get(DWORD *,DWORD *,int,int,int);
	int Next();
	int Reset();
	int clone(IDebugSFileEnum **);
	int AddRef();
};



class IDebugSFrameData;
class IDebugSFrameDataEnum
{
public:
	IDebugSFrameDataEnum(tagFRAMEDATA *,DWORD,IDebugSFrameData *);
	~IDebugSFrameDataEnum();
	int QueryInterface(IID riid, void **ppInterface);
	int Get(IDebugSFrameData**);
	int Next();
	int reset();
	int clone(IDebugSFrameDataEnum **);
};

class IDebugSLines;

class IDebugSLineEnum
{
public:
	IDebugSLineEnum(ulong,CV_Line_t *,CV_Column_t *,IDebugSLines *);
	~IDebugSLineEnum();
	int QueryInterface(IID riid, void **ppInterface);
	int Next();
	int Get(CV_Line_t *,CV_Column_t *);
};

class IDebugSLineBlockEnum
{
public:
	IDebugSLineBlockEnum(unsigned char *,unsigned int,DWORD,IDebugSLines *,unsigned char *);
	int fVerify(unsigned char *,unsigned int,DWORD);
	int columns();
	int clone(IDebugSLineBlockEnum * *);
	int Reset();
	int Release();
	int QueryInterface(IID riid, void **ppInterface);
	int Next();
	int GetSegOffset(ushort *,DWORD *,DWORD *);
	int GetLineEnum(IDebugSLineEnum **);
	int GetFileId(DWORD *);
	int Get(DWORD *,CV_Line_t * *,CV_Column_t **);
};

class IDebugSStringTable
{
public:
	IDebugSStringTable(unsigned char *,unsigned int,IDebugSSectionReader *);
	int QueryInterface(IID riid, void **ppInterface);
	int GetStringEnum(IDebugSStringEnum * *);
	int GetStringByOff(DWORD,char * *);
};

class IDebugSFileInfo
{
public:
	IDebugSFileInfo(unsigned char *,unsigned int,IDebugSSectionReader *);
	int remap(MapStrs *);
	int QueryInterface(IID riid, void **ppInterface);
	int GetFileEnum(IDebugSFileEnum * *);
	int GetFileById(DWORD,DWORD *,DWORD *,unsigned char * *,DWORD *);
};

class IDebugSFrameData
{
public:
	IDebugSFrameData(unsigned char *,unsigned int,IDebugSSectionReader *);
	int remap(MapStrs *);
	int QueryInterface(IID riid, void **ppInterface);
	int GetSectionRva(DWORD *);
	int GetFrameDataEnum(IDebugSFrameDataEnum * *);
	int GetFrameDataByRva(DWORD,tagFRAMEDATA *);
	int ApplyReloc();

};

class IDebugSLines
{
public:
	IDebugSLines(unsigned char *,unsigned int,IDebugSSectionReader *);
	int QueryInterface(IID riid, void **ppInterface);
	int GetSegOffset(ushort *,DWORD *,DWORD *);
	int GetFlags();
	int GetBlockEnum(IDebugSLineBlockEnum * *);
};

class IDebugSSectionReader
{
public:
	~IDebugSSectionReader();
	IDebugSSectionReader(unsigned char *,unsigned int);
	static int FCreateReader(PB pb,size_t cb,IDebugSSectionReader ** self,DWORD nb,enum DSR_EC *ec){return 0;};
	int QueryInterface(IID riid, void **ppInterface);
	int GetStringTable(IDebugSStringTable **);
	int GetSectionEnum(IDebugSSubSectionEnum **);
	int GetFileInfo(IDebugSFileInfo * *);
	DSR_EC GetLastError();
};



class IDebugSSectionWriter
{
public:
	static int FCreateWriter(char s,IDebugSSectionWriter ** self,DWORD nb,int xx){return 0;};
	static int FinishFileBlock(){return 0;};
public:
	enum INDEX {BAD_INDEX=-1};
	IDebugSSectionWriter(unsigned char *,unsigned int);
	~IDebugSSectionWriter();
	int InitBuffers();
	int GetSectionRelocs(char**);
	int GetSectionBytes(PB* pb);
	int EndSection();
	int EndSection(int);
	int StartSection(int,int,int);
	int StartSectionSymId(int);
	int AddLine(int,int,int,int);
	int AddLine(int,int,int,int,int);
	int AddLineWithColumn(int,int,int,int,int,int,int);
	int AddSourceFile(const wchar_t *,char*,int,int);
	int AppendToSymbols(char*,int,DWORD*);
	int AppendRelocation(int,int,int);
	int AddUtf8String(char*);
	int AddString(wchar_t*);
	int AddFrameData(struct tagFRAMEDATA*);
};


#endif

