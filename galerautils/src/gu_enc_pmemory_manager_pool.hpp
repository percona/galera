#ifndef __ENC_PMEMORY_MANAGER_POOL__
#define __ENC_PMEMORY_MANAGER_POOL__

#include <memory>
#include <mutex>
#include <set>

namespace gu {
class PMemoryManager;

/* PMemoryManagerPool is the pool of physical memory managers used by
   MMapEnc objects. Its purpose is to avoid physical memory
   allocation/deallocation when MMapEnc object is created, which is time consuming
   generic task. Instead of this, we can reuse already configured PMemoryManager
   object
*/
class PMemoryManagerPool {
public:
    PMemoryManagerPool(size_t managersPoolSize);
    std::shared_ptr<PMemoryManager> allocate(size_t allocPageSize, size_t size);
    void free(std::shared_ptr<PMemoryManager>mgr);

private:
    // we can use mutex for managers_ protection, because it is never
    // accessed from the signal handler context. We access it only
    // when the client request creation of new EncMMap object.
    std::mutex mtx_;
    std::set<std::shared_ptr<PMemoryManager>> managers_;
    size_t poolSizeMax_;
    size_t poolSize_;
};

}  // namespace
#endif /* __ENC_PMEMORY_MANAGER_POOL__ */