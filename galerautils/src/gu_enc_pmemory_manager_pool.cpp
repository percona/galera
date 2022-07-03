#include "gu_enc_pmemory_manager.hpp"
#include "gu_enc_pmemory_manager_pool.hpp"
#include "gu_enc_debug.hpp"

namespace gu {
static uint64_t timestampServer = 0;
static const uint64_t AGE_THREASHOLD = 10;
static const uint64_t ERASE_TRIGGER = 10;

PMemoryManagerHolder::PMemoryManagerHolder(uint64_t timestamp, std::shared_ptr<PMemoryManager> manager)
: timestamp_(timestamp)
, manager_(manager)
, mgrSize_(0)
, mgrAllocPageSize_(0)
{
    manager_->GetCreateParams(&mgrSize_, &mgrAllocPageSize_);
}

bool PMemoryManagerHolder::operator <(const PMemoryManagerHolder& rhs) const {
    return mgrSize_ < rhs.mgrSize_ && mgrAllocPageSize_ < rhs.mgrAllocPageSize_;
}


PMemoryManagerPool::PMemoryManagerPool(size_t managersPoolSize)
: mtx_()
, managers_()
, poolSizeMax_(managersPoolSize)
, poolSize_(0) {
}

std::shared_ptr<PMemoryManager> PMemoryManagerPool::allocate(size_t allocPageSize, size_t size) {
    std::lock_guard<std::mutex> l(mtx_);
    std::shared_ptr<PMemoryManager> result;

    S_DEBUG("PMemoryManagerPool::allocate(). size: %ld, pageSize: %ld, Pool size: %ld/%ld\n",
      size, allocPageSize, poolSize_, poolSizeMax_);
    timestampServer++;
    bool doErase = (timestampServer % ERASE_TRIGGER == 0);

    for (auto iter = managers_.begin(); iter != managers_.end();) {
        if (!result && iter->mgrSize_ >= size && iter->mgrAllocPageSize_ >= allocPageSize) {
            result = iter->manager_;
            auto eraseIter = iter;
            ++iter;
            managers_.erase(eraseIter);
            poolSize_--;
            S_DEBUG("Reusing PMemoryManager\n");
        }
        if(result && !doErase) {
            break;
        }

        // once every ERASE_THREASHOLD allocations try to erase obsolete managers
        if (iter == managers_.end()) {
            break;
        }

        if (iter->timestamp_ + AGE_THREASHOLD < timestampServer ||
            iter->timestamp_ > timestampServer) {
            S_DEBUG("PMemoryManagerPool::allocate(). Removing obsolete manager."
                     " Manager timestamp: %llu, current timestamp: %llu"
                     " Manager size: %ld\n", iter->timestamp_, timestampServer, iter->mgrSize_);
            auto eraseIter = iter;
            ++iter;
            managers_.erase(eraseIter);
        } else {
            ++iter;
        }
    }
    if (!result) {
        S_DEBUG("Creating new PMemoryManager\n");
        result = std::make_shared<PMemoryManager>(size, allocPageSize);
    }
    return result;
}

void PMemoryManagerPool::free(std::shared_ptr<PMemoryManager>mgr) {
    std::lock_guard<std::mutex> l(mtx_);
    if (poolSize_ < poolSizeMax_) {
        managers_.emplace(timestampServer, mgr);
        poolSize_++;
        S_DEBUG("PMemoryManager returned to pool. Pool size: %ld/%ld\n", poolSize_, poolSizeMax_);
    } else {
        S_DEBUG("PMemoryManager freed, but not to the pool. Pool size: %ld/%ld\n", poolSize_, poolSizeMax_);
    }
}
}