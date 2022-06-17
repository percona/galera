#include "gu_enc_mmap_factory.hpp"
#include "gu_fdesc.hpp"
#include "gu_enc_mmap.hpp"
#include "gu_enc_utils.hpp"

namespace gu {
std::shared_ptr<IMMap> MMapFactory::create(FileDescriptor& fd, bool encrypt, size_t cachePageSize,
  size_t cacheSize, size_t unencryptedHeaderSize) {
    auto rawMmap = std::make_shared<gu::MMap>(fd);
    if (encrypt) {
        return std::make_shared<gu::EncMMap>(generateRandomKey(), rawMmap, cachePageSize, cacheSize,
                                             unencryptedHeaderSize);
    }
    return rawMmap;
}

}  // namespace gu