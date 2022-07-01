#ifndef __GU_ENC_DEBUG__
#define __GU_ENC_DEBUG__

#include <stddef.h>

namespace gu {

#if 0
#define S_DEBUG(format, ...) swrite(format, ##__VA_ARGS__)
#else
#define S_DEBUG(...)
#endif
// always
#define S_DEBUG_A(format, ...) swrite(format, ##__VA_ARGS__)


void swrite(const char* format, ...);
void dumpMemory(void *ptr, size_t size);

}  // namespace

#endif  // __GU_ENC_DEBUG__
