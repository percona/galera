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
#include <atomic>

namespace gu {

static void swrite(const char* format, ...)
{
#if 1
#define buffer_len 8*1024
    char buffer[buffer_len];

    va_list args;
    va_start(args, format);

    sprintf(buffer, "KH: ");
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

inline std::size_t get_page_size() {
    static const std::size_t nbytes = sysconf(_SC_PAGESIZE);
    return nbytes;
};

struct PPage {
    int fd_;
    size_t offset_;
    char* ptr_;
};

class PMemoryManager {
public:
    PMemoryManager(size_t pagesCnt);
    std::shared_ptr<PPage> alloc();
    void free(std::shared_ptr<PPage> page);

private:
    char* base_;
    size_t size_;
    std::vector<std::shared_ptr<PPage>> freePages_;
    int fd_;

    PMemoryManager(const gu::PMemoryManager&);
    PMemoryManager operator=(const gu::PMemoryManager&);
};

void EncMMap::mprotectd(void *ptr, size_t size, int prot) const {
    S_DEBUG1("mprotect ptr: x%llX, size: %ld, prot: %d\n",
      (unsigned long long)ptr, size, prot);
    if (0 != mprotect(ptr, get_page_size(), prot)) {
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



PMemoryManager::PMemoryManager(size_t pagesCnt)
: base_(0)
, size_(0)
, freePages_()
, fd_(-1) {
    size_t page_size = get_page_size();
    size_ = pagesCnt * page_size;
    fd_ = make_temp_file(size_);
    base_ = static_cast<char*>(mmap(nullptr, size_, PROT_READ|PROT_WRITE, MAP_SHARED, fd_, 0));
    mlock(base_, size_);
    S_DEBUG_A("PMemoryManager::PMemoryManager() (x%llX - x%llX)\n",
      (unsigned long long)base_, (unsigned long long)base_ + size_);
    for (size_t i = 0; i < pagesCnt; ++i) {
        auto page = std::make_shared<PPage>();
        page->fd_ = fd_;
        page->offset_ = i*get_page_size();
        page->ptr_ = base_ + page->offset_;
        freePages_.push_back(page);
    }
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
    return p;
}

void PMemoryManager::free(std::shared_ptr<PPage> page) {
    freePages_.push_back(page);
}

struct MemDescriptor {
    char*   start_;
    char*   end_;
    size_t  size_;
};

static PMemoryManager memoryManager(512);

// KH: some mutex around would be nice
std::map<EncMMap*, MemDescriptor> encMMaps;

static void addEncMMap(EncMMap *mmap, char* ptr, size_t size) {
    encMMaps[mmap] = {ptr, ptr+size, size};
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
    bool expected = false;
    if (!inside_handler.compare_exchange_weak(expected, true)) return;
    assert(inside_handler.load());

    char *addr = static_cast<char*>(info->si_addr);
    EncMMap*  encmmap = getEncMMap(addr);

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
    encmmap->handle_signal(info);

    assert(inside_handler.load());
    inside_handler.store(false);
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

EncMMap::EncMMap(const std::string& key, MMap &rawmmap)
: key_(key)
, mmapraw_(rawmmap)
, ptr_(static_cast<char*>(mmap(nullptr, mmapraw_.get_size(), PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)))
, memoryManager_(memoryManager)
, page2protection_()
, vpage2ppage_()
, pagesCnt_(0)
, mapped_(ptr != MAP_FAILED) {
    if (!mapped_)
    {
        gu_throw_error(errno) << "EncMMap::EncMMap() mmap() on anonymous failed";
    }
    S_DEBUG_A("EncMMap::EncMMap() (x%llX - x%llX) (%ld bytes)\n",
        (unsigned long long)ptr_, (unsigned long long)ptr_ + mmapraw_.get_size(), mmapraw_.get_size());
    // install signal handler
    std::call_once(signal_handler_flag, install_signal_handler);
    pagesCnt_ = mmapraw_.get_size()/get_page_size();
    if (mmapraw_.get_size()%get_page_size()) {
        // KH: todo: how should we handle not full page at the end when flushing?
        S_DEBUG_A("EncMMap::EncMMap() adding page, size not aligned: %ld\n", mmapraw_.get_size());
        pagesCnt_++;
    }
    S_DEBUG_A("EncMMap::EncMMap() allocated pages cnt: %ld\n", pagesCnt_);
    page2protection_ = std::shared_ptr<int>(new int[pagesCnt_], [](int *p) { delete[] p; });
    memset(page2protection_.get(), PROT_NONE, sizeof(int) * pagesCnt_);
    addEncMMap(this, ptr_, mmapraw_.get_size());
}

EncMMap::~EncMMap() {
    if (mapped_)
    {
        try { unmap(); } catch (Exception& e) { log_error << e.what(); }
    }
}

size_t EncMMap::get_size() const {
    return mmapraw_.get_size();
}

void* EncMMap::get_ptr() const {
    return ptr_;
}

void EncMMap::dont_need() const {
    mmapraw_.dont_need();
}

static char ENC_KEY = 0x4C;
void EncMMap::encrypt(char* dst, char* src, size_t size, int pageNumber) const {
    decrypt(dst, src, size, pageNumber);
}

static size_t clear_header_size = 1024;
void EncMMap::decrypt(char* dst, char* src, size_t size, int pageNumber) const {
#if 1
    // header is not encrypted
    size_t pageStartOffset = pageNumber * get_page_size();
    for (size_t i = 0; i < size; ++i) {
        if (pageStartOffset + i < clear_header_size) {
            *dst = *src;
        } else {
            *dst = *src ^ ENC_KEY;
        }
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

    for (auto kv = vpage2ppage_.begin(); kv != vpage2ppage_.end(); ++kv) {
        int pageNo = page_number((char*)kv->first);
        if(pageNo < firstPageToSync || pageNo > lastPageToSync) {
            continue;
        }

        int protection = (page2protection_.get())[pageNo];
        char* vpageStart = (char*)kv->first;

        S_DEBUG1("sync pageNo: %d, prot: %d (x%llX - x%llX)\n",
            pageNo, (page2protection_.get())[pageNo], (unsigned long long)vpageStart, (unsigned long long)vpageStart+get_page_size());

        if(protection == (PROT_READ | PROT_WRITE)) {
            // flush
            mprotectd(vpageStart, get_page_size(), PROT_READ);
            char* dstPtr = (char*)mmapraw_.get_ptr() + pageNo*get_page_size();
            encrypt(dstPtr, vpageStart, get_page_size(), pageNo);

            //mprotectd(vpageStart, get_page_size(), PROT_READ | PROT_WRITE);
            S_DEBUG0("    -> flushed\n");
        }
    }
    // sync the underlaying file
    mmapraw_.sync(addr, length);
 }

void EncMMap::sync() const {
    for (auto kv = vpage2ppage_.begin(); kv != vpage2ppage_.end(); ++kv) {
        int pageNo = page_number((char*)kv->first);
        int protection = (page2protection_.get())[pageNo];
        char* vpageStart = (char*)kv->first;
        S_DEBUG1("sync pageNo: %d, prot: %d (x%llX - x%llX)\n",
            pageNo, (page2protection_.get())[pageNo], (unsigned long long)vpageStart, (unsigned long long)vpageStart+get_page_size());
        if(protection == (PROT_READ | PROT_WRITE)) {
            // flush
            mprotectd(vpageStart, get_page_size(), PROT_READ);
            char* dstPtr = (char*)mmapraw_.get_ptr() + pageNo*get_page_size();
            encrypt(dstPtr, vpageStart, get_page_size(), pageNo);
            //mprotectd(vpageStart, get_page_size(), PROT_READ | PROT_WRITE);
            S_DEBUG0("    -> flushed\n");
        }
    }
    // sync the underlaying file
    mmapraw_.sync(ptr_, get_size());
}

void EncMMap::unmap() {
    sync();

    if (munmap (ptr_, get_size()) < 0)
    {
        gu_throw_error(errno) << "munmap(" << ptr << ", " << get_size()
                                << ") failed";
    }

    mapped_ = false;

    S_DEBUG_A("EncMMap::unmap() (x%llX - x%llX) (%ld bytes)\n",
        (unsigned long long)ptr_, (unsigned long long)ptr_ + mmapraw_.get_size(), mmapraw_.get_size());
}

char* EncMMap::page_start(char* addr) const {
    static size_t page_size = get_page_size();

    unsigned long long addr_u = ptr(addr);
    unsigned long long page_start = (addr_u / page_size) * page_size;
    return (char*)page_start;
}

unsigned long long EncMMap::page_number(char* addr) const {
    char* pstart = page_start(addr);
    unsigned long long offset = ptr(pstart) - ptr(ptr_);
    unsigned long long pageNo = offset / get_page_size();
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
    S_DEBUG1("(x%llX) reqPageNo: %llu, prot: %d, (x%llX - x%llX)\n",
      (unsigned long long)p, reqPageNo, (page2protection_.get())[reqPageNo], (unsigned long long)reqPageStart, (unsigned long long)reqPageStart+get_page_size());

    if ((page2protection_.get())[reqPageNo] == PROT_NONE) {
        // page is not mapped. Find free one
        auto p = memoryManager_.alloc();
        if (!p) {
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
                  pageNo, (page2protection_.get())[pageNo], (unsigned long long)vpageStart, (unsigned long long)vpageStart+get_page_size());
                if(protection == (PROT_READ | PROT_WRITE)) {
                    // flush
                    char* dstPtr = (char*)mmapraw_.get_ptr() + pageNo*get_page_size();
                    mprotectd(vpageStart, get_page_size(), PROT_READ);
                    encrypt(dstPtr, vpageStart, get_page_size(), pageNo);
                    //memcpy(dstPtr, vpageStart, get_page_size());

                    S_DEBUG0("    -> flushed\n");
                }
#if 0
                mprotectd(vpageStart, get_page_size(), PROT_WRITE);
                memset(vpageStart, 0x11, get_page_size());
                memset(kv->second->ptr_, 0xFF, get_page_size());
#endif
                //mprotectd(vpageStart, get_page_size(), PROT_NONE);
                //munmap(vpageStart, get_page_size());
                if (mmap(vpageStart, get_page_size(), PROT_NONE,
                    MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0) == MAP_FAILED) {
                    S_DEBUG0("unmap failed!");
                }

                (page2protection_.get())[pageNo] = PROT_NONE;
                memoryManager_.free(vpage2ppage_[vpageStart]);
                kv = vpage2ppage_.erase(kv);
                if (limit-- == 0) break;
            }
            p = memoryManager_.alloc();
        }
#if 1
        char* srcPtr = (char*)mmapraw_.get_ptr() + reqPageNo*get_page_size();
        decrypt(p->ptr_, srcPtr, get_page_size(), reqPageNo);
        mmap(reqPageStart, get_page_size(), PROT_READ, MAP_SHARED|MAP_FIXED, p->fd_, p->offset_);
#else
        // map the new one.
        mmap(reqPageStart, get_page_size(), PROT_WRITE, MAP_SHARED|MAP_FIXED, p->fd_, p->offset_);
        // populate the cache (decryption happens here)
        char* srcPtr = (char*)mmapraw_.get_ptr() + reqPageNo*get_page_size();
        decrypt(reqPageStart, srcPtr, get_page_size(), reqPageNo);
        //memcpy(reqPageStart, srcPtr, get_page_size());
        mprotectd(reqPageStart, get_page_size(), PROT_READ);
#endif
        (page2protection_.get())[reqPageNo] = PROT_READ;
        vpage2ppage_[reqPageStart] = p;
        S_DEBUG1("reqPageNo: %d PROT_NONE -> PROT_READ\n", reqPageNo);
    } else if ((page2protection_.get())[reqPageNo] == PROT_READ) {
        // page is mapped, just mark is as dirty
        mprotectd(reqPageStart, get_page_size(), PROT_READ | PROT_WRITE);
        S_DEBUG1("reqPageNo: %d PROT_READ -> PROT_READ | PROT_WRITE\n", reqPageNo);
    }
    S_DEBUG0("handle_signal <<<<<<<<<\n");
}


}  // namespace