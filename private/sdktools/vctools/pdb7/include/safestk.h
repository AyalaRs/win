#ifndef _SAFE_STK_H_
#define _SAFE_STK_H_

#ifndef ALIGN_PVOID
#define ALIGN_PVOID(x) ((x + sizeof(PVOID) - 1) & (0 - sizeof(PVOID)))
#endif

template <int inst>
struct _list{
public:
	union{
		void*  ptr;
		_list<0x180>*     minipage;
		_list<0x1000>*    normpage;
		_list<0x20000>*   LargePage;
	}next;
	char  data[inst];
};

typedef struct _list<0> list;

class Allocator
{
public:
	__inline
	virtual void* AllocBytes(size_t size);
	
	template <typename T>
	inline
	 T* Alloc(size_t size)
	{
		return (T*)AllocBytes(size*sizeof(T));
	};

	inline Allocator(){}
	inline ~Allocator(){}

};

template  <const int inst>
class SafeStackAllocator : public Allocator
{
private:
	size_t         cbused;
	_list<inst>    heap;
public:
	inline
	SafeStackAllocator<inst>(){
		cbused     = 0;
		heap.next.ptr = NULL;
	}
	inline
	~SafeStackAllocator<inst>(){
		Free();
	}
	void* AllocBytes(size_t size);
protected:
	void* AllocInHeap(size_t size);
	void  Free();
};

template  <const int inst>
void* SafeStackAllocator<inst>::AllocInHeap(size_t size)
{
	void*  list_p = operator new[] (size+sizeof(list*));
	list*  listp = static_cast<list*>(list_p);
	
	void*  p = NULL;
	if (listp)
	{
		listp->next.ptr = heap.next.ptr;
		
		heap.next.ptr  = listp;
		p = &listp->data[0];
	}
	return p;
};

template  <const int inst>
void SafeStackAllocator<inst>::Free()
{
	list* listp;
	list* nextp = static_cast<list*>(heap.next.ptr);
	while (nextp)
	{
		listp = nextp;
		nextp = static_cast<list*>(listp->next.ptr);
		operator delete(listp);
	}
	heap.next.ptr = NULL;
	cbused = 0;
};

template  <const int inst>
void* SafeStackAllocator<inst>::AllocBytes(size_t size)
{
	void* p;
	size_t cb = ALIGN_PVOID(size);
	
	if (inst - cbused < cb)
		p = AllocInHeap(cb);
	else
	{
		p = &heap.data[cb];
		cbused += cb;
	}
	return p;
};
void* Allocator::AllocBytes(size_t size)
{
	return this->AllocBytes(size);
}
#endif
