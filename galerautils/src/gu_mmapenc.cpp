#include "gu_mmapenc.hpp"
#include "gu_throw.hpp"
#include "gu_logger.hpp"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/mman.h>
#include <mutex>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <cassert>


#define CLEAR_BUFFERS 0
namespace gu {

std::string generateRandomKey() {
    static int keyLength = 32;
    return "01234567890123456789012345678901";
}

static void swrite(const char* format, ...)
{
#if 1
#define buffer_len 8*1024
    char buffer[buffer_len];

    va_list args;
    va_start(args, format);

    sprintf(buffer, "KH: ");
//    sprintf(buffer, "");
    int offset = strlen(buffer);

    offset = offset;
    format = format;
    vsnprintf (buffer + offset, buffer_len-offset, format, args);

    write(STDERR_FILENO, buffer, strlen(buffer));
    va_end(args);
#endif
}

#define S_DEBUG0(format) //swrite(format)
#define S_DEBUG1(format, args...) //swrite(format, args)
#define S_DEBUG2(format, args...) //swrite(format, args)
// always
#define S_DEBUG_A0(format) swrite(format)
#define S_DEBUG_A(format, args...) swrite(format, args)

unsigned long long ptr(void * ptr) {
    return (unsigned long long)ptr;
}

inline std::size_t getCpuPageSize() {
    static const std::size_t nbytes = sysconf(_SC_PAGESIZE);
    return nbytes;
};

inline void dumpMemory(void *ptr, size_t size) {
    S_DEBUG1("DUMP START x%llX, size: %ld", (unsigned long long)ptr, size);
    unsigned char *p = (unsigned char*)ptr;
    for (size_t i = 0; i < size; ++i) {
        if(i%16==0) {
            S_DEBUG0("\n");
        }
        S_DEBUG1("%02x ", p[i]);
    }
    S_DEBUG1("\nDUMP END x%llX, size: %ld\n", (unsigned long long)ptr, size);
}

void EncMMap::mprotectd(void *ptr, size_t size, int prot) const {
    S_DEBUG1("mprotect ptr: x%llX, size: %ld, prot: %d\n",
      (unsigned long long)ptr, size, prot);
    if (0 != mprotect(ptr, size, prot)) {
        S_DEBUG1("mprotect failed. errno: %d, msg: %s\n", errno, strerror(errno));
    }
    (page2protection_.get())[page_number((char*)ptr)] = prot;
}

void set_file_size(int fd, off_t size)
{
#if MISSING_POSIX_FALLOCATE
    if (ftruncate(fd, size) == -1) {
	//    threrror("ftruncate");
    }
#else // !MISSING_POSIX_FALLOCATE
    // We prefer to allocate disk space now so as to throw an
    // exception in response to an error.  If we don't call fallocate,
    // then an out-of-disk space or over-quota condition will result
    // in confusing page faults at the time the pages are first
    // accessed (and hence allocated on-demand by the kernel).
    if (int err = posix_fallocate(fd, 0, size)) {
	errno = err;
	// threrror("fallocate");
    }
#endif // !MISSING_POSIX_FALLOCATE
}

int make_temp_file(off_t size)
{
    char path[] = "/tmp/XXXXXXXXXXXXXX";
    mode_t old_mask = umask(0077);
    int fd (mkstemp(path));
    umask(old_mask);
    if (fd == -1) {
        // troubles
    }
    unlink(path);
//    close_on_exec(fd);
    set_file_size(fd, size);
    return fd;
}

static const unsigned char FREE_PAGE_PATTERN = 0xAB;
static const unsigned char ALLOCATED_PAGE_PATTERN = 0xED;

PMemoryManager::PMemoryManager(size_t size, size_t allocPageSize)
: base_(0)
, size_(0)
, freePages_()
, fd_(-1)
, mapped_(false)
, allocPagesCnt_(0)
, allocPageSize_(allocPageSize) {
    // maximum 512 alloc pages
    static const int ALLOC_PAGES_MAX = 512;

    // allocPageSize has to be Cpu page aligned
    if (allocPageSize_ % getCpuPageSize()) {
        S_DEBUG_A("PMemoryManager::PMemoryManager() allocPageSize not aligned %ld\n", allocPageSize);
        gu_throw_error(errno) << "PMemoryManager::PMemoryManager() allocPageSize not aligned";
    }

    // how many pages do we need to satisfy size?
    allocPagesCnt_ = size / allocPageSize_;
    if (size % allocPageSize_) {
        // KH: todo: how should we handle not full page at the end when flushing?
        S_DEBUG_A("PMemoryManager::PMemoryManager() adding page, size not aligned to allocation unit: %ld\n", size);
        allocPagesCnt_++;
    }
    allocPagesCnt_ = allocPagesCnt_ < ALLOC_PAGES_MAX ? allocPagesCnt_ : ALLOC_PAGES_MAX;

    size_ = allocPagesCnt_ * allocPageSize_;
    fd_ = make_temp_file(size_);
    base_ = static_cast<char*>(mmap(nullptr, size_, PROT_READ|PROT_WRITE, MAP_SHARED, fd_, 0));
    mapped_ = (base_ != MAP_FAILED);
    if (!mapped_)
    {
        gu_throw_error(errno) << "PMemoryManager::PMemoryManager() mmap() failed";
    }
    if (mlock(base_, size_)) {
        S_DEBUG_A0("PMemoryManager::PMemoryManager() mlock failed");
        assert(0);
    }
#if CLEAR_BUFFERS
    memset(base_, FREE_PAGE_PATTERN, size_);
#endif
    S_DEBUG_A("PMemoryManager::PMemoryManager() (x%llX - x%llX). "
              "CpuPageSize: %ld, allocPageSize: %ld, allocPagesCnt: %ld\n",
      (unsigned long long)base_, (unsigned long long)base_ + size_,
      getCpuPageSize(), allocPageSize_, allocPagesCnt_);

    for (size_t i = 0; i < allocPagesCnt_; ++i) {
        auto page = std::make_shared<PPage>();
        page->fd_ = fd_;
        page->offset_ = i*allocPageSize_;
        page->ptr_ = base_ + page->offset_;
        freePages_.push(page);
    }
}

PMemoryManager::~PMemoryManager() {
    S_DEBUG_A("PMemoryManager::~PMemoryManager() (x%llX - x%llX)\n",
      (unsigned long long)base_, (unsigned long long)base_ + size_);

    if (freePages_.size() != allocPagesCnt_) {
        S_DEBUG_A("Some pages still allocated. Free pages cnt: %d\n", freePages_.size());
    }

    if (mapped_) {
        if (munmap (base_, size_) < 0) {
            S_DEBUG_A0("unmap failed");
        }
    }
    mapped_ = false;
}

std::shared_ptr<PPage> PMemoryManager::alloc() {
    // no free pages. Need to free some pages before allocating.
    S_DEBUG1("PMemoryManager::alloc() freePages: %d\n", freePages_.size());
    if (freePages_.empty()) {
        S_DEBUG0("PMemoryManager::alloc() no free pages\n");
        return std::shared_ptr<PPage>();
    }
    auto p = freePages_.front();
    freePages_.pop();

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
    freePages_.push(page);
}

struct MemDescriptor {
    char*   start_;
    char*   end_;
    size_t  size_;
};


// KH: some mutex around would be nice
std::map<EncMMap*, MemDescriptor> encMMaps;

static void addEncMMap(EncMMap *mmap, char* ptr, size_t size) {
    encMMaps[mmap] = {ptr, ptr+size, size};
}

static void delEncMMap(EncMMap *mmap) {
    encMMaps.erase(mmap);
}

static EncMMap* getEncMMap(char* ptr) {
    for (auto m : encMMaps) {
        if (ptr >= m.second.start_  &&  ptr < m.second.end_) {
            return m.first;
        }
    }
    return nullptr;
}

std::once_flag signal_handler_flag;
struct sigaction oldsigact;
static std::atomic_bool inside_handler(false);

void signal_handler(int sig, siginfo_t* info, void* ctx) {
#if 1
    bool expected = false;
    if (!inside_handler.compare_exchange_weak(expected, true)) {
        S_DEBUG_A0("signal_handler collision\n");
        return;
    }
    assert(inside_handler.load());
#endif
    char *addr = static_cast<char*>(info->si_addr);
    EncMMap*  encmmap = getEncMMap(addr);
#if 1
    assert(inside_handler.load());
    inside_handler.store(false);
#endif
    if (encmmap == nullptr) {
        S_DEBUG0("calling old signal handler\n");
        if (oldsigact.sa_flags == SA_SIGINFO) {
            oldsigact.sa_sigaction(sig, info, ctx);
        } else {
            oldsigact.sa_handler(sig);
        }
        return;
    }

    // this is our region. Dispatch to the proper EncMMap object.
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

// this is how many phisical pages will form 1 allocation unit
static const int ALLOC_PAGE_MULTIPLIER = 4;
// PMemoryManager allocation unit
static size_t ALLOC_PAGE_SIZE = ALLOC_PAGE_MULTIPLIER * getCpuPageSize();

EncMMap::EncMMap(const std::string& key, MMap &rawmmap, size_t encryptionStartOffset)
: key_(key)
, mmapraw_(rawmmap)
// mmap 2 pages more: 1st for aligning start, 2nd if the last underlying page is not aligned
, mmap_ptr_(static_cast<char*>(mmap(nullptr, mmapraw_.get_size() + 2*ALLOC_PAGE_SIZE, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)))
, base_(nullptr)
, memoryManager_(mmapraw_.get_size(), ALLOC_PAGE_SIZE)
, page2protection_()
, vpage2ppage_()
, pagesCnt_(0)
, mapped_(mmap_ptr_ != MAP_FAILED)
, lastPageSize_(ALLOC_PAGE_SIZE)
, encryptionStartOffset_(encryptionStartOffset)
, defaultPageProtection_(PROT_READ | PROT_WRITE)
, locked_(false) {

    if (!mapped_)
    {
        gu_throw_error(errno) << "EncMMap::EncMMap() mmap() on anonymous failed";
    }

    // we need base_ to be aligned with ALLOC_PAGE_SIZE for easier calculations later
    // here we will loose at most 4k at the beginning
    base_ = (char*)(((ptr(mmap_ptr_) + ALLOC_PAGE_SIZE) / ALLOC_PAGE_SIZE) * ALLOC_PAGE_SIZE);

    S_DEBUG_A("EncMMap::EncMMap() this: x%llX, mmap_ptr: x%llX aligned mapping: (x%llX - x%llX) (%ld bytes)\n",
        ptr(this), ptr(mmap_ptr_), ptr(base_), ptr(base_) + mmapraw_.get_size(), mmapraw_.get_size());
    // install signal handler
    std::call_once(signal_handler_flag, install_signal_handler);
    pagesCnt_ = mmapraw_.get_size() / ALLOC_PAGE_SIZE;
    if (mmapraw_.get_size() % ALLOC_PAGE_SIZE) {
        // if the size is not aligned, the last page is smaller than ALLOC_PAGE_SIZE
        lastPageSize_ = mmapraw_.get_size() % ALLOC_PAGE_SIZE;
        S_DEBUG_A("EncMMap::EncMMap() adding page, size not aligned: %ld, lastPageSize: %ld\n",
          mmapraw_.get_size(), lastPageSize_);
        pagesCnt_++;
    }

    S_DEBUG_A("EncMMap::EncMMap() allocated pages cnt: %ld\n", pagesCnt_);
    page2protection_ = std::shared_ptr<int>(new int[pagesCnt_], [](int *p) { delete[] p; });
    memset(page2protection_.get(), PROT_NONE, sizeof(int) * pagesCnt_);
    addEncMMap(this, base_, mmapraw_.get_size());
}

EncMMap::~EncMMap() {
    S_DEBUG_A("EncMMap::!EncMMap() this: x%llX, mmap_ptr: x%llX aligned mapping: (x%llX - x%llX) (%ld bytes)\n",
        ptr(this), ptr(mmap_ptr_), ptr(base_), ptr(base_) + mmapraw_.get_size(), mmapraw_.get_size());
    if (mapped_)
    {
        try { unmap(); } catch (Exception& e) { log_error << e.what(); }
    }

    delEncMMap(this);
}

bool EncMMap::lock() {
    bool expected = false;
    return locked_.compare_exchange_weak(expected, true);
}

void EncMMap::unlock() {
    assert(locked_.load());
    locked_.store(false);
}

size_t EncMMap::get_size() const {
    return mmapraw_.get_size();
}

void* EncMMap::get_ptr() const {
    return base_;
}

void EncMMap::dont_need() const {
    mmapraw_.dont_need();
}

void EncMMap::encrypt(char* dst, char* src, size_t size, int pageNumber) const {
    decrypt(dst, src, size, pageNumber);
}

void EncMMap::decrypt(char* dst, char* src, size_t size, int pageNumber) const {
    // the last page may be not full
    size = (pageNumber == pagesCnt_-1) ? lastPageSize_ : size;
#if 1
    size_t pageStartOffset = pageNumber * ALLOC_PAGE_SIZE;

    size_t i = 0;
    if (pageStartOffset < encryptionStartOffset_) {
        size_t unencryptedSize = std::min(size, encryptionStartOffset_);
        memcpy(dst, src, unencryptedSize);
        dst += unencryptedSize;
        src += unencryptedSize;
    }

    // normal encryption
    char ENC_KEY = key_[0];
    for (; i < size; ++i) {
        *dst = *src ^ ENC_KEY;
        dst++;
        src++;
    }
#else
    memcpy(dst, src, size);
#endif
}

void EncMMap::sync(void *addr, size_t length) const {
    int firstPageToSync = page_number((char*)addr);
    char* vpageEnd = (char*)addr + length;
    int lastPageToSync = page_number(vpageEnd);
    
    // calculate the real lenght to sync. It is pages bound
    char* syncAddrStart = page_start(firstPageToSync);
    char* syncAddrEnd = page_start(lastPageToSync) + ALLOC_PAGE_SIZE;
    size_t realSyncLen = syncAddrEnd - syncAddrStart;
    size_t syncStartOffset = base_ - (char*)addr;
    
    for (auto kv = vpage2ppage_.begin(); kv != vpage2ppage_.end(); ++kv) {
        int pageNo = page_number((char*)kv->first);
        if(pageNo < firstPageToSync || pageNo > lastPageToSync) {
            continue;
        }

        int protection = (page2protection_.get())[pageNo];
        char* vpageStart = (char*)kv->first;

        S_DEBUG1("sync pageNo: %d, prot: %d (x%llX - x%llX)\n",
            pageNo, (page2protection_.get())[pageNo], (unsigned long long)vpageStart, (unsigned long long)vpageStart+ALLOC_PAGE_SIZE);

        if(protection == (PROT_READ | PROT_WRITE)) {
            // flush
            mprotectd(vpageStart, ALLOC_PAGE_SIZE, PROT_READ);
            char* dstPtr = (char*)mmapraw_.get_ptr() + pageNo*ALLOC_PAGE_SIZE;
            encrypt(dstPtr, vpageStart, ALLOC_PAGE_SIZE, pageNo);
            S_DEBUG0("    -> flushed\n");
            mprotectd(vpageStart, ALLOC_PAGE_SIZE, defaultPageProtection_);
        }
    }
    // sync the underlaying file
    // we need to sync whole alloc pages
    mmapraw_.sync((char*)mmapraw_.get_ptr()+syncStartOffset, realSyncLen);
 }

void EncMMap::sync() const {
    for (auto kv = vpage2ppage_.begin(); kv != vpage2ppage_.end(); ++kv) {
        int pageNo = page_number((char*)kv->first);
        int protection = (page2protection_.get())[pageNo];
        char* vpageStart = (char*)kv->first;
        S_DEBUG1("sync pageNo: %d, prot: %d (x%llX - x%llX)\n",
            pageNo, (page2protection_.get())[pageNo], (unsigned long long)vpageStart, (unsigned long long)vpageStart+ALLOC_PAGE_SIZE);
        if(protection == (PROT_READ | PROT_WRITE)) {
            // flush
            mprotectd(vpageStart, ALLOC_PAGE_SIZE, PROT_READ);
            char* dstPtr = (char*)mmapraw_.get_ptr() + pageNo*ALLOC_PAGE_SIZE;
            encrypt(dstPtr, vpageStart, ALLOC_PAGE_SIZE, pageNo);
            S_DEBUG0("    -> flushed\n");
            mprotectd(vpageStart, ALLOC_PAGE_SIZE, defaultPageProtection_);
        }
    }
    // sync the underlaying file
    mmapraw_.sync(mmapraw_.get_ptr(), get_size());
}

void EncMMap::unmap() {
#if 1
    sync();
    for (auto p : vpage2ppage_) {
        memoryManager_.free(p.second);
    }
    vpage2ppage_.clear();
#endif
    if (munmap (mmap_ptr_, get_size() + ALLOC_PAGE_SIZE) < 0)
    {
        gu_throw_error(errno) << "munmap(" << ptr(mmap_ptr_) << ", " << get_size()
                                << ") failed";
    }
    S_DEBUG_A("EncMMap::unmap() (x%llX - x%llX) (%ld bytes)\n",
        (unsigned long long)base_, (unsigned long long)base_ + mmapraw_.get_size(), mmapraw_.get_size());
    base_ = nullptr;
    mapped_ = false;
}

char* EncMMap::page_start(unsigned long long pageNo) const {
    return base_ + ALLOC_PAGE_SIZE * pageNo;
}

char* EncMMap::page_start(char* addr) const {
    static size_t page_size = ALLOC_PAGE_SIZE;

    unsigned long long addr_u = ptr(addr);
    unsigned long long page_start = (addr_u / page_size) * page_size;
    return (char*)page_start;
}

unsigned long long EncMMap::page_number(char* addr) const {
    char* pstart = page_start(addr);
    unsigned long long offset = ptr(pstart) - ptr(base_);
    unsigned long long pageNo = offset / ALLOC_PAGE_SIZE;
    return pageNo;
}

void EncMMap::dumpMappings() {
    for (auto mm : encMMaps) {
        S_DEBUG_A("Mappings for EncMMap x%llX (x%llX - x%llX) size: %ld START\n",
        (unsigned long long)mm.first, (unsigned long long)mm.second.start_, (unsigned long long)mm.second.end_,
        mm.second.size_);
        mm.first->dumpMappingsInt();
    }
}
void dumpMappings() {
    EncMMap::dumpMappings();
}

void EncMMap::dumpMappingsInt()
{
    S_DEBUG_A0("vpage -> ppage mappings start\n");
    for (auto kv : vpage2ppage_) {
        S_DEBUG_A("vpage: x%llX, ppage: x%llX\n", (unsigned long long)kv.first, (unsigned long long)kv.second->ptr_);
    }
    S_DEBUG_A0("vpage -> ppage mappings end\n");
}

void EncMMap::handle_signal(siginfo_t* info) {
    S_DEBUG0("handle_signal >>>>>>>>>>>\n");
    char* p = static_cast<char*>(info->si_addr);
    unsigned long long reqPageNo = page_number(p);
    char* reqPageStart = page_start(p);

    S_DEBUG1("this: x%llX, p: x%llX, reqPageNo: %llu, (x%llX - x%llX)\n",
      ptr(this), ptr(p), reqPageNo, ptr(reqPageStart), ptr(reqPageStart)+ALLOC_PAGE_SIZE);

    assert(reqPageNo < pagesCnt_);

    S_DEBUG1("reqPageNo: %llu, prot: %d\n",
      reqPageNo, (page2protection_.get())[reqPageNo]);

    if ((page2protection_.get())[reqPageNo] == PROT_NONE) {
        // page is not mapped. Find free one
        auto p = memoryManager_.alloc();
        if (!p) {
            size_t freedCout = 0;
            size_t flushedCnt = 0;
            // try to find read page over dirty page
            char *vpageStart = nullptr;
            // free N pages, no more
            int limit = 100;
            S_DEBUG1("freeing ppages. allocated: %d\n", vpage2ppage_.size());
            for (auto kv = vpage2ppage_.begin(); kv != vpage2ppage_.end();) {
            //for (auto kv : vpage2ppage_) {
                //S_DEBUG1("freeing ppages. allocated: %d\n", vpage2ppage_.size());
                int pageNo = page_number((char*)kv->first);
                //S_DEBUG1("pageNo: %d\n", pageNo);
                int protection = (page2protection_.get())[pageNo];
                vpageStart = (char*)kv->first;
                S_DEBUG1("free pageNo: %d, prot: %d (x%llX - x%llX)\n",
                  pageNo, (page2protection_.get())[pageNo], (unsigned long long)vpageStart, (unsigned long long)vpageStart+ALLOC_PAGE_SIZE);
                if(protection == (PROT_READ | PROT_WRITE)) {
                    // flush
                    char* dstPtr = (char*)mmapraw_.get_ptr() + pageNo*ALLOC_PAGE_SIZE;
                    mprotectd(vpageStart, ALLOC_PAGE_SIZE, PROT_READ);
                    encrypt(dstPtr, vpageStart, ALLOC_PAGE_SIZE, pageNo);
//                    if (msync(dstPtr, ALLOC_PAGE_SIZE, MS_SYNC)) {
//                        assert(0);
//                    }
                    flushedCnt++;
                    S_DEBUG0("    -> flushed\n");
                }

                if (mmap(vpageStart, ALLOC_PAGE_SIZE, PROT_NONE,
                    MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0) == MAP_FAILED) {
                    S_DEBUG0("unmap failed!");
                }

                (page2protection_.get())[pageNo] = PROT_NONE;
                memoryManager_.free(vpage2ppage_[vpageStart]);
                kv = vpage2ppage_.erase(kv);
                freedCout++;
                if (--limit == 0) break;
            }
            S_DEBUG1("flused/freed: %ld / %ld\n", flushedCnt, freedCout);
            p = memoryManager_.alloc();
            assert(p);
        }

        // this page
        char* srcPtr = (char*)mmapraw_.get_ptr() + reqPageNo*ALLOC_PAGE_SIZE;

        decrypt(p->ptr_, srcPtr, ALLOC_PAGE_SIZE, reqPageNo);
        // make it visible through the file
        //msync(p->ptr_, ALLOC_PAGE_SIZE, MS_SYNC);

        if(MAP_FAILED == mmap(reqPageStart, ALLOC_PAGE_SIZE, defaultPageProtection_, MAP_SHARED|MAP_FIXED, p->fd_, p->offset_)) {
           S_DEBUG0("mmap failed");
           assert(0); 
        }

        (page2protection_.get())[reqPageNo] = defaultPageProtection_;
        vpage2ppage_[reqPageStart] = p;
        S_DEBUG1("read reqPageNo: %d (x%llX - x%llX) PROT_NONE -> PROT_READ\n",
            reqPageNo, (unsigned long long)reqPageStart,
            (unsigned long long)reqPageStart+ALLOC_PAGE_SIZE);

        // read ahead
        static size_t READ_AHEAD_CNT = 100; // how many pages should we read ahead
        size_t totalReadAhead = 0;
        for (size_t i = 0; i < READ_AHEAD_CNT; ++i) {
            reqPageNo = reqPageNo+1 < pagesCnt_ ? reqPageNo+1 : 0;
            // only not mapped pages
            if ((page2protection_.get())[reqPageNo] != PROT_NONE) {
                S_DEBUG1("read ahead reqPageNo: %d (x%llX - x%llX) already mapped. prot: %d\n",
                  reqPageNo, (unsigned long long)page_start(reqPageNo),
                  (unsigned long long)page_start(reqPageNo)+ALLOC_PAGE_SIZE,
                  (page2protection_.get())[reqPageNo]);
                continue;
            }
            p = memoryManager_.alloc();
            if (!p) {
                // keep it simple for now. No swaping when read ahead.
                S_DEBUG1("read ahead reqPageNo: %d (x%llX - x%llX) no free pages.\n",
                  reqPageNo, (unsigned long long)page_start(reqPageNo),
                  (unsigned long long)page_start(reqPageNo)+ALLOC_PAGE_SIZE);
                break;
            }
            char* srcPtr = (char*)mmapraw_.get_ptr() + reqPageNo*ALLOC_PAGE_SIZE;
            decrypt(p->ptr_, srcPtr, ALLOC_PAGE_SIZE, reqPageNo);
            reqPageStart = page_start(reqPageNo);

            mmap(reqPageStart, ALLOC_PAGE_SIZE, defaultPageProtection_, MAP_SHARED|MAP_FIXED, p->fd_, p->offset_);
            (page2protection_.get())[reqPageNo] = defaultPageProtection_;
            vpage2ppage_[reqPageStart] = p;
            totalReadAhead++;
            S_DEBUG1("read ahead reqPageNo: %d (x%llX - x%llX) PROT_NONE -> PROT_READ\n",
              reqPageNo, (unsigned long long)reqPageStart,
              (unsigned long long)reqPageStart+ALLOC_PAGE_SIZE);
        }
        S_DEBUG1("Read ahead %ld pages\n", totalReadAhead);
    } else if ((page2protection_.get())[reqPageNo] == PROT_READ) {
        // page is mapped, just mark is as dirty
        mprotectd(reqPageStart, ALLOC_PAGE_SIZE, PROT_READ | PROT_WRITE);
        S_DEBUG1("reqPageNo: %d PROT_READ -> PROT_READ | PROT_WRITE\n", reqPageNo);
    }
    S_DEBUG0("handle_signal <<<<<<<<<\n");
}


}  // namespace