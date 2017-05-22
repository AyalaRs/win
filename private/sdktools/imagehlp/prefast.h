#ifndef _PRE_FAST_H
#define _PRE_FAST_H

#ifndef rsize_t
#define rsize_t size_t
#endif

#ifndef PREFAST_SUPPRESS
#define PREFAST_SUPPRESS(n, stmt) __pragma(warning(suppress:n)) stmt
#endif

#ifndef _In_
#define _In_
#endif

#ifndef _In_z_
#define _In_z_
#endif

#ifndef _In_count_
#define _In_count_(x)
#endif

#ifndef _Out_
#define _Out_
#endif

#ifndef _Out_opt_
#define _Out_opt_
#endif

#ifndef _Inout_
#define _Inout_
#endif

#ifndef _Inout_opt_
#define _Inout_opt_
#endif

#ifndef _Inout_z_
#define _Inout_z_
#endif

#ifndef _Inout_opt_cap_
#define _Inout_opt_cap_(x)
#endif

#ifndef _Out_z_cap_
#define _Out_z_cap_(x)
#endif

#ifndef _Out_opt_cap_
#define _Out_opt_cap_(x)
#endif

#ifndef _Out_opt_capcount_
#define _Out_opt_capcount_(x)
#endif


#ifndef _Out_opt_z_cap_
#define _Out_opt_z_cap_(x)
#endif

#ifndef _Post_z_
#define _Post_z_
#endif

#ifndef _Pre_notnull_
#define _Pre_notnull_
#endif

#ifndef _Pre_z_
#define _Pre_z_
#endif

#ifndef _Deref_out_z_
#define _Deref_out_z_
#endif

#ifndef _Deref_out_opt_
#define _Deref_out_opt_
#endif

#ifndef _Deref_out_opt_z_
#define _Deref_out_opt_z_
#endif

#endif