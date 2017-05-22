class Allocator
{
public:
	 void* AllocBytes(size_t size);
	template <typename T>
	 T* Alloc(size_t size)
	{
		return (T*)AllocBytes(size*sizeof(T));
	};
};


template  <int inst>
class SafeStackAllocator : public Allocator
{
public:

};

