#include "gu_enc_pmemory_manager.hpp"
#include "gu_enc_debug.hpp"
#include "gu_enc_utils.hpp"
#include "gu_throw.hpp"

#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>


namespace gu {
// We allow to allocate max 512 pages (allocation pages, not CPU pages).
// If cache size needs to be bigger, gcache.encryption_cache_page_size should be bigger
static const size_t CACHE_ALLOC_PAGES_MAX = 512;

#define CLEAR_BUFFERS 0
static const unsigned char FREE_PAGE_PATTERN = 0xAB;
static const unsigned char ALLOCATED_PAGE_PATTERN = 0xED;

static inline std::size_t getCpuPageSize() {
    static const std::size_t nbytes = sysconf(_SC_PAGESIZE);
    return nbytes;
};

PMemoryManager::PMemoryManager(size_t size, size_t allocPageSize)
: createSize_(size)  // actual size may differ because of limits
, base_(0)
, size_(0)
, freePages_()
, myPages_()
, fd_(-1)
, mapped_(false)
, allocPagesCnt_(0)
, allocPageSize_(allocPageSize) {
    S_DEBUG_A0("+++PMemoryManager::PMemoryManager()\n");

    // allocPageSize has to be CPU page aligned
    if (allocPageSize_ % getCpuPageSize() || allocPageSize_ < getCpuPageSize()) {
        S_DEBUG_A("PMemoryManager::PMemoryManager() allocPageSize not aligned. Requested: %ld. "
                  "Should be multiply of CPU page size %ld\n", allocPageSize, getCpuPageSize());
        gu_throw_error(errno) << "PMemoryManager::PMemoryManager() allocPageSize not aligned";
    }

    // how many pages do we need to satisfy size?
    allocPagesCnt_ = size / allocPageSize_;
    if (size % allocPageSize_) {
        S_DEBUG_A("PMemoryManager::PMemoryManager() adding page, size not aligned to allocation unit: %ld\n", size);
        allocPagesCnt_++;
    }
    allocPagesCnt_ = allocPagesCnt_ < CACHE_ALLOC_PAGES_MAX ? allocPagesCnt_ : CACHE_ALLOC_PAGES_MAX;

    size_ = allocPagesCnt_ * allocPageSize_;
    if (createTmpFile()) {
        gu_throw_error(errno) << "PMemoryManager::PMemoryManager() creation of tempfile failed";
    }
    base_ = static_cast<unsigned char*>(mmap(nullptr, size_, PROT_READ|PROT_WRITE, MAP_SHARED, fd_, 0));
    mapped_ = (base_ != MAP_FAILED);
    if (!mapped_)
    {
        gu_throw_error(errno) << "PMemoryManager::PMemoryManager() mmap() failed";
    }
    if (mlock(base_, size_)) {
        S_DEBUG_A0("PMemoryManager::PMemoryManager() mlock failed. It will still work, "
                   "but swap pages into the disk, so performance will be affected\n");
    }
#if CLEAR_BUFFERS
    memset(base_, FREE_PAGE_PATTERN, size_);
#endif
    S_DEBUG_A("PMemoryManager::PMemoryManager() (x%llX - x%llX). "
              "CpuPageSize: %ld, allocPageSize: %ld, allocPagesCnt: %ld, "
              "size requested: %ld, size allocated: %ld\n",
      ptr2ull(base_), ptr2ull(base_) + size_,
      getCpuPageSize(), allocPageSize_, allocPagesCnt_, createSize_, size_);

    for (size_t i = 0; i < allocPagesCnt_; ++i) {
        auto page = std::make_shared<PPage>();
        page->fd_ = fd_;
        page->offset_ = i*allocPageSize_;
        page->ptr_ = base_ + page->offset_;
        myPages_.push_back(page);
    }
    freePages_ = myPages_;
    S_DEBUG_A0("---PMemoryManager::PMemoryManager()\n");
}

PMemoryManager::~PMemoryManager() {
    S_DEBUG_A("+++PMemoryManager::~PMemoryManager() (x%llX - x%llX)\n",
      ptr2ull(base_), ptr2ull(base_) + size_);

    if (freePages_.size() != allocPagesCnt_) {
        S_DEBUG_A("Some pages still allocated. Free pages cnt: %d\n", freePages_.size());
    }

    if (mapped_) {
        if (munmap (base_, size_) < 0) {
            S_DEBUG_A0("unmap failed");
        }
    }
    mapped_ = false;
    S_DEBUG_A("---PMemoryManager::~PMemoryManager() (x%llX - x%llX)\n",
      ptr2ull(base_), ptr2ull(base_) + size_);
}

void PMemoryManager::GetCreateParams(size_t* size, size_t* allocPageSize) {
    *size = createSize_;
    *allocPageSize = allocPageSize_;
}


std::shared_ptr<PPage> PMemoryManager::alloc() {
    // no free pages. Need to free some pages before allocating.
    S_DEBUG1("PMemoryManager::alloc() freePages: %d\n", freePages_.size());
    if (freePages_.empty()) {
        S_DEBUG0("PMemoryManager::alloc() no free pages\n");
        return std::shared_ptr<PPage>();
    }
    auto p = freePages_.back();
    freePages_.pop_back();

#if CLEAR_BUFFERS
    for(size_t i = 0; i < allocPageSize_; ++i){
        if ((unsigned char)(p->ptr_[i]) != FREE_PAGE_PATTERN) {
            S_DEBUG_A0("Free page pattern does not mach\n");
            assert(0);
        }
    }
    memset(p->ptr_, ALLOCATED_PAGE_PATTERN, allocPageSize_);
#endif
    return p;
}

void PMemoryManager::free(std::shared_ptr<PPage> page) {
#if CLEAR_BUFFERS
    memset(page->ptr_, FREE_PAGE_PATTERN, allocPageSize_);
#endif
    freePages_.push_back(page);
}

void PMemoryManager::freeAll() {
    if(myPages_.size() != freePages_.size()) {
        // some pages were not released, restore clean state
        freePages_ = myPages_;
    }
}

bool PMemoryManager::createTmpFile()
{
    char path_template[] = "/tmp/XXXXXX";
    int fd (mkstemp(path_template));
    if (fd == -1) {
        return true;
    }
    // setup automatic deletion of the file
    unlink(path_template);

    // and file description in case of forking
    int flags = fcntl(fd, F_GETFD);
    if (fd == -1) {
        return true;
    }
    if (fcntl(fd, F_SETFD, flags|FD_CLOEXEC) == -1) {
        return -1;
    }

    if (posix_fallocate(fd, 0, size_)) {
        S_DEBUG_A0("posix_fallocate failed\n");
        return true;
    }
    fd_ = fd;
    return false;
}

}