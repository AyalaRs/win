#ifndef _COMENVI_H_
#define _COMENVI_H_
class StrEnviron
{
private:
	char * s1;
	char * s2;
public:
	char * szValueForTag(char* s)
	{
		__debugbreak();
		return NULL;
	}
};

class CompEnviron : public StrEnviron
{
public:
	CompEnviron(COMPILESYM *)
	{
		__debugbreak();
	}
};

class EnvBlockEnviron:public StrEnviron
{
public:
	EnvBlockEnviron(ENVBLOCKSYM *)
	{
		__debugbreak();
	}
};



#define ENC_SRC      "src"
#define ENC_PDB      "pdb"
#define ENVBLOCK_SRC "src"
#define ENVBLOCK_PDB "pdb"










#endif