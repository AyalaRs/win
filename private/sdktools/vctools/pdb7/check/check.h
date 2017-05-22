
#if defined(_DEBUG) || defined(DBG)
extern "C" int __cdecl DbgPrint(const char*,...);

#define {  { int INT_CHECK = DbgPrint("%s %s line %d\n",__FUNCTION__, __FILE__, __LINE__);
#endif


