#include "gu_enc_pmemory_manager.hpp"
#include "gu_enc_pmemory_manager_pool.hpp"
#include "gu_enc_debug.hpp"

namespace gu {

PMemoryManagerPool::PMemoryManagerPool(size_t managersPoolSize)
: mtx_()
, managers_()
, poolSizeMax_(managersPoolSize)
, poolSize_(0) {

}

std::shared_ptr<PMemoryManager> PMemoryManagerPool::allocate(size_t allocPageSize, size_t size) {
    std::lock_guard<std::mutex> l(mtx_);
    S_DEBUG1("PMemoryManagerPool::allocate(). size: %ld, pageSize: %ld, Pool size: %ld/%ld\n",
      size, allocPageSize, poolSize_, poolSizeMax_);
    for (auto mgr : managers_) {
        size_t mgrSize, mgrAllocPageSize;
        mgr->GetCreateParams(&mgrSize, &mgrAllocPageSize);
        if (mgrSize >= size && mgrAllocPageSize >= allocPageSize) {
            managers_.erase(mgr);
            poolSize_--;
            S_DEBUG0("Reusing PMemoryManager\n");
            return mgr;
        }
    }
    S_DEBUG0("Creating new PMemoryManager\n");
    auto mgr = std::make_shared<PMemoryManager>(size, allocPageSize);
    return mgr;
}

void PMemoryManagerPool::free(std::shared_ptr<PMemoryManager>mgr) {
    std::lock_guard<std::mutex> l(mtx_);
    if (poolSize_ < poolSizeMax_) {
        mgr->reset();  // todo: move this responsibility to the client
        managers_.insert(mgr);
        poolSize_++;
        S_DEBUG1("PMemoryManager returned to pool. Pool size: %ld/%ld\n", poolSize_, poolSizeMax_);
    } else {
        S_DEBUG1("PMemoryManager freed, but not to the pool. Pool size: %ld/%ld\n", poolSize_, poolSizeMax_);
    }
}
    
    
}