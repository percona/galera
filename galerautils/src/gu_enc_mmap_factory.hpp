#ifndef __GU_MMAP_FACTORY__
#define __GU_MMAP_FACTORY__

#include <memory>
#include "gu_mmap.hpp"

namespace gu {
class FileDescriptor;


class MMapFactory {
public:
    static std::shared_ptr<IMMap> create(FileDescriptor& fd, bool encrypt,
        size_t cachePageSize, size_t cacheSize, bool syncOnDestroy, size_t unencryptedHeaderSize);
};
}

#endif  /* __GU_MMAP_FACTORY__ */