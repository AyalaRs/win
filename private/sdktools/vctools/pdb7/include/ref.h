#pragma once

#if !defined(_ref_h)
#define _ref_h 1

#define refNil	0


template<typename T>
class COMRefPtr {
private:
    T * tag;
	void Release() {
		if (tag != NULL ) 
			delete tag;
		tag = NULL;
	}
	
public:
	COMRefPtr<T>(){
		tag = NULL;
	}
	
	COMRefPtr<T>(T * NEW) {
		tag = NEW;
	}

	COMRefPtr<T>(const COMRefPtr<T> & NEW) {
		tag = NEW.tag;
	}

   ~COMRefPtr<T>() {
		Release();
	}

	COMRefPtr<T>& operator=(T *NEW) {
		Release();
		tag = NEW;
		return *this;
	}

	COMRefPtr<T>& operator=(const COMRefPtr<T> &NEW) {
		Release();
		tag = NEW.tag;

		return *this;
	}

	bool      operator== (T *NEW)  const { return  tag == NEW; }
	bool      operator!= (T *NEW)  const { return  tag != NEW; }
	T&        operator*  ()		   const { return *tag;}
	          operator T*()	       const { return  tag;}
	T*        operator-> ()	       const { return  tag;}
	const T** operator & ()	       const { return &tag;}
	T**       operator & ()	             { return &tag;}
	
};


template<typename T>
class RefPtr :public T {
private:
    T * tag;
	void Release() {
		if (tag != NULL ) 
			delete tag;
		tag = NULL;
	}
	
public:
	RefPtr<T>(){
		tag = NULL;
	}
	
	RefPtr<T>(T * NEW) {
		tag = NEW;
	}

	RefPtr<T>(const RefPtr<T> & NEW) {
		tag = NEW.tag;
	}

   ~RefPtr<T>() {
		Release();
	}

	RefPtr<T>& operator=(T *NEW) {
		Release();
		tag = NEW;
		return *this;
	}

	RefPtr<T>& operator=(const RefPtr<T> &NEW) {
		Release();
		tag = NEW.tag;

		return *this;
	}
	
	bool  operator== (T *NEW) const { return  tag == NEW; }
	bool  operator!= (T *NEW) const { return  tag != NEW; }
	T*    operator-> ()	       const { return  tag;}
	T&    operator*  ()		   const { return *tag;}
};



template <typename T>  
class RefCount :public T
{  
private:    
	int  Count; 
public:  
	RefCount<T>(){
		Count =0;
	}
};

#endif
