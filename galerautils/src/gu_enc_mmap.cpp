#include "gu_enc_mmap.hpp"
#include "gu_throw.hpp"
#include "gu_logger.hpp"
#include "gu_enc_debug.hpp"
#include "gu_enc_utils.hpp"
#include "gu_enc_pmemory_manager.hpp"
#include "gu_enc_pmemory_manager_pool.hpp"

#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/mman.h>

#include <cassert>
#include <thread>
#include <set>


namespace gu {

#define IS_LAST_PAGE(_page) (_page == pagesCnt_-1)

#define REAL_ENCRYPTION 1

// maximum number of PMemoryManagers waiting in the pool
static const size_t MANAGERS_POOL_SIZE = 10;
PMemoryManagerPool memoryManagerPool(MANAGERS_POOL_SIZE);

// EncMMap objects repository
static std::atomic_flag encMmapsLock = ATOMIC_FLAG_INIT;

struct EncMMapDescriptor {
    unsigned char*   start_;
    unsigned char*   end_;
};
std::map<EncMMap*, EncMMapDescriptor> encMMaps;

static void addEncMMap(EncMMap *mmap, unsigned char* ptr, size_t size) {
    while (encMmapsLock.test_and_set(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    encMMaps[mmap] = {ptr, ptr+size};
    encMmapsLock.clear(std::memory_order_release);
}

static void delEncMMap(EncMMap *mmap) {
    while (encMmapsLock.test_and_set(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    encMMaps.erase(mmap);
    encMmapsLock.clear(std::memory_order_release);
}

static EncMMap* getEncMMap(unsigned char* ptr) {
    for (auto m : encMMaps) {
        if (ptr >= m.second.start_  &&  ptr < m.second.end_) {
            return m.first;
        }
    }
    return nullptr;
}


// Debug purpose only
void EncMMap::dumpMappings() {
    while (encMmapsLock.test_and_set(std::memory_order_acquire)) {
        std::this_thread::yield();
    }

        for (auto mm : encMMaps) {
            S_DEBUG_A("Mappings for EncMMap x%llX (x%llX - x%llX) START\n",
              ptr2ull(mm.first), ptr2ull(mm.second.start_), ptr2ull(mm.second.end_));
            mm.first->dumpMappingsInt();
        }
    encMmapsLock.clear(std::memory_order_release);
}
void dumpMappings() {
    EncMMap::dumpMappings();
}

void EncMMap::dumpMappingsInt()
{
    S_DEBUG_A0("vpage -> ppage mappings start\n");
    for (auto kv : vpage2ppage_) {
        S_DEBUG_A("vpage: x%llX, ppage: x%llX\n", ptr2ull(kv.first), ptr2ull(kv.second->ptr_));
    }
    S_DEBUG_A0("vpage -> ppage mappings end\n");
}


// Helper methods
unsigned char* EncMMap::page_start(unsigned long long pageNo) const {
    return base_ + pageSize_ * pageNo;
}

unsigned char* EncMMap::page_start(unsigned char* addr) const {
    unsigned long long addr_u = ptr2ull(addr);
    unsigned long long page_start = (addr_u / pageSize_) * pageSize_;
    return reinterpret_cast<unsigned char*>(page_start);
}

size_t EncMMap::page_number(unsigned char* addr) const {
    unsigned long long offset = ptr2ull(addr) - ptr2ull(base_);
    size_t pageNo = offset / pageSize_;
    return pageNo;
}


// encrption / decryption
void EncMMap::encrypt(unsigned char* dst, unsigned char* src, size_t size, size_t pageNumber) const {
    // the last page may be not full
    size = IS_LAST_PAGE(pageNumber) ? lastPageSize_ : size;
#if REAL_ENCRYPTION
    size_t pageStartOffset = pageNumber * pageSize_;
    size_t unencryptedSize = 0;

    if (gu_unlikely(pageStartOffset < encryptionStartOffset_)) {
        unencryptedSize = std::min(size, encryptionStartOffset_);
        memcpy(dst, src, unencryptedSize);
        dst += unencryptedSize;
        src += unencryptedSize;
    }

    int encryptedSize = size - unencryptedSize;
    if(encryptedSize > 0) {
      encryptor_.set_stream_offset(pageStartOffset + unencryptedSize);
      encryptor_.encrypt(dst, src, size - unencryptedSize);
    }
#else
    memcpy(dst, src, size);
#endif
}

void EncMMap::decrypt(unsigned char* dst, unsigned char* src, size_t size, size_t pageNumber) const {
    // the last page may be not full
    size = IS_LAST_PAGE(pageNumber) ? lastPageSize_ : size;
#if REAL_ENCRYPTION
    size_t pageStartOffset = pageNumber * pageSize_;
    size_t unencryptedSize = 0;

    if (gu_unlikely(pageStartOffset < encryptionStartOffset_)) {
        unencryptedSize = std::min(size, encryptionStartOffset_);
        memcpy(dst, src, unencryptedSize);
        dst += unencryptedSize;
        src += unencryptedSize;
    }

    int encryptedSize = size - unencryptedSize;
    if(encryptedSize > 0) {
        decryptor_.set_stream_offset(pageStartOffset + unencryptedSize);
        decryptor_.decrypt(dst, src, size - unencryptedSize);
    }
#else
    memcpy(dst, src, size);
#endif
}


// signal handler install and dispatch
static std::once_flag signal_handler_once;
static struct sigaction oldsigact;

void signal_handler(int sig, siginfo_t* info, void* ctx) {
    // If someone is accessing encMMaps, just bail out without even trying
    // to find our object.
    // It can happen in the following situations:
    // 1. (rare) The client in registering/deregistering new EncMMap object
    // 2. (more probable but still not so often) Two signal handlers are called
    //    simultaneously (2 threads). In such a case the 2nd one will retry
    //    in a while.
    if (encMmapsLock.test_and_set(std::memory_order_acquire)) {
        S_DEBUG_A0("signal_handler collision\n");
        return;
    }
    unsigned char *addr = static_cast<unsigned char*>(info->si_addr);
    S_DEBUG1("addr: x%llX\n", ptr2ull(addr));
    EncMMap*  encmmap = getEncMMap(addr);
    encMmapsLock.clear(std::memory_order_release);

    if (encmmap == nullptr) {
        S_DEBUG0("calling old signal handler\n");
        if (oldsigact.sa_flags == SA_SIGINFO) {
            oldsigact.sa_sigaction(sig, info, ctx);
        } else {
            oldsigact.sa_handler(sig);
        }
        return;
    }

    // This is our region. Dispatch to the proper EncMMap object.
    if (!encmmap->lock()) {
        S_DEBUG_A0("encmmap collision\n");
        return;
    }
    encmmap->handle_signal(info);
    encmmap->unlock();
}

static void install_signal_handler() {
	if (sigaction(SIGSEGV, nullptr, &oldsigact) == -1) {
        gu_throw_error(errno) << "install_signal_handler() getting old signal handler failed";
    }

	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = &signal_handler;
	if (sigaction(SIGSEGV, &sa, nullptr) == -1) {
        gu_throw_error(errno) << "install_signal_handler() signal handler installation failed";
    }
}


EncMMap::EncMMap(const std::string& key, std::shared_ptr<MMap> rawmmap,
                 size_t cachePageSize, size_t cacheSize, bool syncOnDestroy,
                 size_t encryptionStartOffset)
: mmapraw_(rawmmap)
, pageSize_(cachePageSize)
, mmaprawPtr_(static_cast<unsigned char*>(mmapraw_->get_ptr()))
, vMemSize_(mmapraw_->get_size())
// mmap 2 pages more: 1st for aligning start, 2nd if the last underlying page is not aligned
, mmap_ptr_(static_cast<unsigned char*>(mmap(nullptr, vMemSize_ + 2*pageSize_, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)))
, base_(nullptr)
, memoryManagerP_(memoryManagerPool.allocate(cachePageSize, cacheSize))
, memoryManager_(*memoryManagerP_)
, page2protectionGuard_()
, page2protection_(nullptr)
, vpage2ppage_()
, pagesCnt_(0)
, mapped_(mmap_ptr_ != MAP_FAILED)
, lastPageSize_(pageSize_)
, encryptionStartOffset_(encryptionStartOffset)
, defaultPageProtection_(PROT_READ | PROT_WRITE )
, lock_(ATOMIC_FLAG_INIT)
, encryptor_()
, decryptor_()
, syncOnDestroy_(syncOnDestroy) {

    if (!mapped_)
    {
        gu_throw_error(errno) << "EncMMap::EncMMap() mmap() on anonymous failed";
    }

    // we need base_ to be aligned with pageSize_ for easier calculations later
    // here we will loose at most pageSize_ at the beginning
    base_ = reinterpret_cast<unsigned char*>(((ptr2ull(mmap_ptr_) + pageSize_) / pageSize_) * pageSize_);

    S_DEBUG_A("EncMMap::EncMMap() this: x%llX, mmap_ptr: x%llX aligned mapping: (x%llX - x%llX) (%ld bytes)\n",
        ptr2ull(this), ptr2ull(mmap_ptr_), ptr2ull(base_), ptr2ull(base_) + vMemSize_, vMemSize_);
    // install signal handler common for all objects
    std::call_once(signal_handler_once, install_signal_handler);
    pagesCnt_ = vMemSize_ / pageSize_;
    if (vMemSize_ % pageSize_) {
        // if the size is not aligned, the last page is smaller than pageSize_
        lastPageSize_ = vMemSize_ % pageSize_;
        S_DEBUG_A("EncMMap::EncMMap() adding page, size not aligned: %ld, lastPageSize: %ld\n",
          vMemSize_, lastPageSize_);
        pagesCnt_++;
    }

    S_DEBUG_A("EncMMap::EncMMap() allocated pages cnt: %ld\n", pagesCnt_);
    page2protectionGuard_ = std::shared_ptr<int>(new int[pagesCnt_], [](int *p) { delete[] p; });
    page2protection_ = page2protectionGuard_.get();
    addEncMMap(this, base_, vMemSize_);

    // we set up page2protection_ map inside
    set_key(key);
}

EncMMap::~EncMMap() {
    S_DEBUG_A("EncMMap::~EncMMap() this: x%llX, mmap_ptr: x%llX aligned mapping: (x%llX - x%llX) (%ld bytes)\n",
        ptr2ull(this), ptr2ull(mmap_ptr_), ptr2ull(base_), ptr2ull(base_) + vMemSize_, vMemSize_);
    if (mapped_)
    {
        try { unmap(); } catch (Exception& e) { log_error << e.what(); }
    }

    delEncMMap(this);

    encryptor_.close();
    decryptor_.close();

    memoryManager_.freeAll();
    memoryManagerPool.free(memoryManagerP_);
}

bool EncMMap::lock() {
    return !lock_.test_and_set(std::memory_order_acquire);
}

void EncMMap::unlock() {
    assert(lock_.test_and_set(std::memory_order_acquire));
    lock_.clear(std::memory_order_release);
}

size_t EncMMap::get_size() const {
    return vMemSize_;
}

void* EncMMap::get_ptr() const {
    return base_;
}

void EncMMap::dont_need() const {
    mmapraw_->dont_need();
}

void EncMMap::mprotectd(unsigned char *ptr, size_t size, int prot) const {
    S_DEBUG1("mprotect ptr: x%llX, size: %ld, prot: %d\n",
      ptr2ull(ptr), size, prot);
    if (0 != mprotect(ptr, size, prot)) {
        S_DEBUG1("mprotect failed. errno: %d, msg: %s\n", errno, strerror(errno));
    }

    size_t firstPageNo = page_number(ptr);
    if (gu_likely(size == pageSize_)) {
        page2protection_[firstPageNo] = prot;
    } else {
        size_t pagesCnt = size/pageSize_;
        pagesCnt = (size%pageSize_) ? pagesCnt+1 : pagesCnt;
        memset(&(page2protection_[firstPageNo]), prot, sizeof(int) * pagesCnt);
    }
}

// todo: maybe use PageGluer here as well?
void EncMMap::sync(void *addr, size_t length) const {
    unsigned char* addrU = reinterpret_cast<unsigned char*>(addr);

    S_DEBUG1("sync() addr: %llX, length: %ld\n", ptr2ull(addr), length);

    size_t firstPageToSync = page_number(addrU);
    unsigned char* vpageEnd = addrU + length;
    size_t lastPageToSync = page_number(vpageEnd);

    // calculate the real lenght to sync. It is pages bound
    unsigned char* syncAddrStart = page_start(firstPageToSync);
    size_t lastPageSize = IS_LAST_PAGE(lastPageToSync) ? lastPageSize_ : pageSize_;
    unsigned char* syncAddrEnd = page_start(lastPageToSync) + lastPageSize;
    size_t realSyncLen = syncAddrEnd - syncAddrStart;
    size_t syncStartOffset = base_ - addrU;

    for (auto kv = vpage2ppage_.begin(); kv != vpage2ppage_.end(); ++kv) {
        size_t pageNo = page_number(kv->first);
        if(pageNo < firstPageToSync || pageNo > lastPageToSync) {
            continue;
        }

        int protection = page2protection_[pageNo];
        unsigned char* vpageStart = kv->first;

        S_DEBUG1("sync pageNo: %d, prot: %d (x%llX - x%llX)\n",
            pageNo, page2protection_[pageNo], ptr2ull(vpageStart), ptr2ull(vpageStart)+pageSize_);

        if(protection == (PROT_READ | PROT_WRITE)) {
            // flush
            mprotectd(vpageStart, pageSize_, PROT_READ);
            unsigned char* dstPtr = mmaprawPtr_ + pageNo * pageSize_;
            encrypt(dstPtr, vpageStart, pageSize_, pageNo);
            S_DEBUG0("    -> flushed\n");
            mprotectd(vpageStart, pageSize_, defaultPageProtection_);
        }
    }
    // sync the underlaying file
    // we need to sync whole alloc pages
    mmapraw_->sync(mmaprawPtr_+syncStartOffset, realSyncLen);
 }

void EncMMap::sync() const {
    for (auto kv = vpage2ppage_.begin(); kv != vpage2ppage_.end(); ++kv) {
        int pageNo = page_number(kv->first);
        int protection = page2protection_[pageNo];
        unsigned char* vpageStart = kv->first;
        S_DEBUG1("sync() pageNo: %d, prot: %d (x%llX - x%llX)\n",
            pageNo, page2protection_[pageNo], ptr2ull(vpageStart), ptr2ull(vpageStart)+pageSize_);
        if(protection == (PROT_READ | PROT_WRITE)) {
            // flush
            mprotectd(vpageStart, pageSize_, PROT_READ);
            unsigned char* dstPtr = mmaprawPtr_ + pageNo*pageSize_;
            encrypt(dstPtr, vpageStart, pageSize_, pageNo);
            S_DEBUG0("    -> flushed\n");
            mprotectd(vpageStart, pageSize_, defaultPageProtection_);
        }
    }
    // sync the underlaying file
    mmapraw_->sync();
}

void EncMMap::unmap() {
    // todo: For RecordSet cache and GCache overflow pages this sync is not needed
    // if we unmap it means we will never map again, so we are not interested
    // with the content anymore.
    if (syncOnDestroy_) {
        sync();
    }

    if (munmap (mmap_ptr_, get_size() + pageSize_) < 0)
    {
        gu_throw_error(errno) << "munmap(" << ptr2ull(mmap_ptr_) << ", " << get_size()
                                << ") failed";
    }
    S_DEBUG_A("EncMMap::unmap() (x%llX - x%llX) (%ld bytes)\n",
        ptr2ull(base_), ptr2ull(base_) + vMemSize_, vMemSize_);
    base_ = nullptr;
    mapped_ = false;
}

void EncMMap::set_key(const std::string& key) {
    static unsigned char iv[Aes_ctr_encryptor::AES_BLOCK_SIZE] = {0};

    assert(key.length() >= Aes_ctr_encryptor::FILE_KEY_LENGTH);
    unsigned char *kkey = (unsigned char*)key.c_str();
    encryptor_.close();
    decryptor_.close();
    encryptor_.open(kkey, iv);
    decryptor_.open(kkey, iv);

    // We just set the key. Cache may contain some data, which was decrypted
    // with old key. If we flush now, we will spoil the data.
    // Discard everything cached so far.
    mprotectd(base_, vMemSize_, PROT_NONE);
    memoryManager_.freeAll();
    vpage2ppage_.clear();
}


/* When we need to flush pages it is the common situation that they are
   continous. In such a case glue them to avoid partial encryptions.
   The following class encapsulates gluing logic.  */
struct PageGluer {
    unsigned char* src_;
    unsigned char* dst_;
    size_t size_;
    int minPageNo_;
    int prevPageNo_;
    int gluedPages_;
    static const int glueLimit_ = 25;  // todo: do we need this limit?

    PageGluer(): src_(nullptr), dst_(nullptr), size_(0),
                 minPageNo_(-1), prevPageNo_(-1), gluedPages_(0) {}
    bool glue(int pageNo, unsigned char* src, unsigned char* dst, size_t size) {
        if (prevPageNo_ == -1) {
            prevPageNo_ = pageNo;
            minPageNo_ = pageNo;
            src_ = src;
            dst_ = dst;
            size_ = size;
            gluedPages_++;
            return true;
        }

        if (gluedPages_ < glueLimit_ && prevPageNo_ + 1 == pageNo) {
            prevPageNo_ = pageNo;
            size_ += size;
            gluedPages_++;
            return true;
        }
        return false;
    }

    void reset() {
        src_ = nullptr;
        dst_ = nullptr;
        size_ = 0;
        minPageNo_ = -1;
        prevPageNo_ = -1;
        gluedPages_ = 0;
    }
};

// signal handler. The whole magic happens here
void EncMMap::handle_signal(siginfo_t* info) {
    S_DEBUG0("handle_signal >>>>>>>>>>>\n");
    unsigned char* p = static_cast<unsigned char*>(info->si_addr);
    size_t reqPageNo = page_number(p);
    unsigned char* reqPageStart = page_start(p);

    S_DEBUG1("this: x%llX, p: x%llX, reqPageNo: %llu, (x%llX - x%llX)\n",
      ptr2ull(this), ptr2ull(p), reqPageNo, ptr2ull(reqPageStart), ptr2ull(reqPageStart)+pageSize_);

    assert(reqPageNo < pagesCnt_);

    S_DEBUG1("reqPageNo: %llu, prot: %d\n",
      reqPageNo, page2protection_[reqPageNo]);

    if (page2protection_[reqPageNo] == PROT_NONE) {
        // page is not mapped. Find free one
        auto p = memoryManager_.alloc();
        if (!p) {
            size_t freedCout = 0;
            size_t flushedCnt = 0;
            unsigned char *vpageStart = nullptr;

            // free FLUSH_LIMIT pages, no more
            const static int FLUSH_LIMIT = 100;
            int limit = FLUSH_LIMIT;
            S_DEBUG1("freeing ppages. allocated: %d\n", vpage2ppage_.size());

            PageGluer gluer;
            for (auto& kv : vpage2ppage_) {
                //S_DEBUG1("freeing ppages. allocated: %d\n", vpage2ppage_.size());
                size_t pageNo = page_number(kv.first);
                //S_DEBUG1("pageNo: %d\n", pageNo);
                int protection = page2protection_[pageNo];
                vpageStart = kv.first;
                S_DEBUG1("free pageNo: %d, prot: %d (x%llX - x%llX)\n",
                  pageNo, protection, ptr2ull(vpageStart), ptr2ull(vpageStart)+pageSize_);
                if(protection == (PROT_READ | PROT_WRITE)) {
                    // flush
                    unsigned char* dstPtr = mmaprawPtr_ + pageNo*pageSize_;
                    mprotectd(vpageStart, pageSize_, PROT_READ);

                    size_t pageSize = IS_LAST_PAGE(pageNo) ? lastPageSize_ : pageSize_;
                    if (gluer.glue(pageNo, vpageStart, dstPtr, pageSize)) {
                        S_DEBUG0("glued\n");
                        // logically should be done in the loop below, but
                        // do it here to avoid pageNo propagation/recalculation
                        page2protection_[pageNo] = PROT_NONE;
                        if (--limit == 0) break;
                        continue;
                    }
                    S_DEBUG0("not glued\n");

                    encrypt(gluer.dst_, gluer.src_, gluer.size_, gluer.minPageNo_);
                    gluer.reset();
                    gluer.glue(pageNo, vpageStart, dstPtr, pageSize);

                    flushedCnt++;
                    S_DEBUG0("    -> flushed\n");
                }
                // logically should be done in the loop below, but
                // do it here to avoid pageNo propagation/recalculation
                page2protection_[pageNo] = PROT_NONE;

                freedCout++;
                if (--limit == 0) break;
            }

            if (gluer.size_ > 0) {
                encrypt(gluer.dst_, gluer.src_, gluer.size_, gluer.minPageNo_);
            }

            // do it again with the same limit, so we will free pages which were
            // synced above
            limit = FLUSH_LIMIT;
            for (auto kv = vpage2ppage_.begin(); kv != vpage2ppage_.end();) {
                vpageStart = kv->first;
                if (mmap(vpageStart, pageSize_, PROT_NONE,
                    MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0) == MAP_FAILED) {
                    S_DEBUG0("unmap failed!");
                }

                // it is alread marked as PROT_NONE in the loop above

                memoryManager_.free(vpage2ppage_[vpageStart]);
                kv = vpage2ppage_.erase(kv);
                if (--limit == 0) break;
            }

            S_DEBUG1("flused/freed: %ld / %ld\n", flushedCnt, freedCout);
            p = memoryManager_.alloc();
            assert(p);
        }

        // this page
        unsigned char* srcPtr = mmaprawPtr_ + reqPageNo*pageSize_;

        decrypt(p->ptr_, srcPtr, pageSize_, reqPageNo);

        if(MAP_FAILED == mmap(reqPageStart, pageSize_, defaultPageProtection_, MAP_SHARED|MAP_FIXED, p->fd_, p->offset_)) {
           S_DEBUG0("mmap failed");
           assert(0); 
        }

        page2protection_[reqPageNo] = defaultPageProtection_;
        vpage2ppage_[reqPageStart] = p;
        S_DEBUG1("read reqPageNo: %d (x%llX - x%llX) PROT_NONE -> PROT_READ\n",
            reqPageNo, ptr2ull(reqPageStart),
            ptr2ull(reqPageStart)+pageSize_);

        // read ahead  // todo: implement this for recovery
        static size_t READ_AHEAD_CNT = 0; // how many pages should we read ahead
        size_t totalReadAhead = 0;
        for (size_t i = 0; i < READ_AHEAD_CNT; ++i) {
            reqPageNo = reqPageNo+1 < pagesCnt_ ? reqPageNo+1 : 0;
            // only not mapped pages
            if (page2protection_[reqPageNo] != PROT_NONE) {
                S_DEBUG1("read ahead reqPageNo: %d (x%llX - x%llX) already mapped. prot: %d\n",
                  reqPageNo, ptr2ull(page_start(reqPageNo)),
                  ptr2ull(page_start(reqPageNo))+pageSize_,
                  page2protection_[reqPageNo]);
                continue;
            }
            p = memoryManager_.alloc();
            if (!p) {
                // keep it simple for now. No swaping when read ahead.
                S_DEBUG1("read ahead reqPageNo: %d (x%llX - x%llX) no free pages.\n",
                  reqPageNo, ptr2ull(page_start(reqPageNo)),
                  ptr2ull(page_start(reqPageNo))+pageSize_);
                break;
            }
            unsigned char* srcPtr = mmaprawPtr_ + reqPageNo*pageSize_;
            decrypt(p->ptr_, srcPtr, pageSize_, reqPageNo);
            reqPageStart = page_start(reqPageNo);

            mmap(reqPageStart, pageSize_, defaultPageProtection_, MAP_SHARED|MAP_FIXED, p->fd_, p->offset_);
            page2protection_[reqPageNo] = defaultPageProtection_;
            vpage2ppage_[reqPageStart] = p;
            totalReadAhead++;
            S_DEBUG1("read ahead reqPageNo: %d (x%llX - x%llX) PROT_NONE -> PROT_READ\n",
              reqPageNo, ptr2ull(reqPageStart),
              ptr2ull(reqPageStart)+pageSize_);
        }
        S_DEBUG1("Read ahead %ld pages\n", totalReadAhead);
    } else if (page2protection_[reqPageNo] == PROT_READ) {
        // page is mapped, just mark is as dirty
        mprotectd(reqPageStart, pageSize_, PROT_READ | PROT_WRITE);
        S_DEBUG1("reqPageNo: %d PROT_READ -> PROT_READ | PROT_WRITE\n", reqPageNo);
    }
    S_DEBUG0("handle_signal <<<<<<<<<\n");
}


}  // namespace