#include "prefast.h"

#include "windows.h"


#include "utf8.h"








#ifdef __cplusplus
extern "C" {
#endif
static int aiByteCountForLeadNibble[16] =
{
    1,  // 0000
    1,  // 0001
    1,  // 0010
    1,  // 0011
    1,  // 0100
    1,  // 0101
    1,  // 0110
    1,  // 0111
    1,  // 1000
    1,  // 1001
    1,  // 1010
    1,  // 1011
    2,  // 1100
    2,  // 1101
    3,  // 1110
    4   // 1111
};
inline BOOL IsValidWideChar(short w)
{
    return w <= 0xffef;
}
inline short __U(short w)
{
	return IsValidWideChar(w)?w:L'?';
}

size_t UTF8ToUnicode(LPCSTR lpSrcStr, LPWSTR lpDestStr, size_t cchDest)
{
	__debugbreak();
	return UTF8ToUnicodeCch(lpSrcStr, strlen(lpSrcStr) + 1, lpDestStr, cchDest);
}

size_t UTF8ToUnicodeCch(LPCSTR lpSrcStr, size_t cchSrc, LPWSTR lpDestStr, size_t cchDest)
{
	unsigned char     s;
	unsigned char*    src = (unsigned char*)lpSrcStr;
	unsigned short    w;
	unsigned short*   dst = (unsigned short*)lpDestStr;
	size_t cb,nb,cx;
	__debugbreak();
	for (cb=0,cx=(cchSrc>cchDest)?cchDest:cchSrc ; *dst=0,cb < cx;)
	{
		s  = *src;
		nb = aiByteCountForLeadNibble[s>>4];
		if (cb + nb > cx)
			break;
		switch (nb)
		{
			case 1:
				*dst++ = (short)*src++;
				break;
			case 3:
				w      = (short)*src++;
				//through
			case 2:
				w     |= (short)(*src++ & 0x3f) << 6;
				w     |= (short)(*src++ & 0x3f)     ;
				
				*dst++ = __U(w);
				break;
			case 4:
				w      = (short)(*src++ & 0x07) << 2;
				w     |= (short)(*src   & 0x30) >> 4;
				w      = (short)(w      -    1) << 6;
				w     |= (short)(*src++ & 0x0f) << 2;
				w     |= (short)(*src   & 0x30) >> 4;
				
				//0xd800 + off
				*dst++ = HIGH_SURROGATE_START + w; 
				
				w      = (short)(*src++ & 0x0f) << 6;
				w     |= (short)(*src++ & 0x3f)     ;
				
				//0xdc00 + off
				*dst++ = LOW_SURROGATE_START  + w;
				break;
		}
		cb  += nb;
	}
	return cb;
}

size_t UnicodeToUTF8(LPCWSTR lpSrcStr, LPSTR lpDestStr, size_t cchDest)
{
	__debugbreak();
	return UnicodeToUTF8Cch(lpSrcStr, wcslen(lpSrcStr) + 1, lpDestStr, cchDest);
}
size_t UnicodeToUTF8Cch(LPCWSTR lpSrcStr, size_t cchSrc, LPSTR lpDestStr, size_t cchDest)
{
	__debugbreak();
	return 0;
}
size_t UnicodeLengthOfUTF8(PCSTR pUTF8)
{
	__debugbreak();
	return UnicodeLengthOfUTF8Cb(pUTF8, strlen(pUTF8) + 1);
}

size_t UnicodeLengthOfUTF8Cb (PCSTR pUTF8, size_t cbUTF)
{
	__debugbreak();
	return 0;
}

size_t UTF8LengthOfUnicode(PCWSTR pUni)
{
	__debugbreak();
	return UTF8LengthOfUnicodeCch(pUni, wcslen(pUni) + 1);
}

size_t UTF8LengthOfUnicodeCch (PCWSTR pUni, size_t cchUni)
{
	__debugbreak();
	return 0;
}
























#ifdef __cplusplus
}
#endif