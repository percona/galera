#ifndef __GU_ENC_DEBUG__
#define __GU_ENC_DEBUG__

#include <stddef.h>

namespace gu {

#if 0
#define S_DEBUG0(format)
#define S_DEBUG1(format, args...)
#define S_DEBUG2(format, args...)
#else
#define S_DEBUG0(format) swrite(format)
#define S_DEBUG1(format, args...) swrite(format, args)
#define S_DEBUG2(format, args...) swrite(format, args)
#endif
// always
#define S_DEBUG_A0(format) swrite(format)
#define S_DEBUG_A(format, args...) swrite(format, args)


void swrite(const char* format, ...);
void dumpMemory(void *ptr, size_t size);

}  // namespace

#endif  // __GU_ENC_DEBUG__
