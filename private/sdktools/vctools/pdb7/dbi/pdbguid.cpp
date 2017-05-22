#include <rpc.h>            // definition for UUID
BOOL FUuidCreate(UUID * guid)
{
	return UuidCreate(guid)>=0;
}
