#ifndef __GCACHE_MMAPENC__
#define __GCACHE_MMAPENC__

#include <signal.h>
#include <queue>
#include <string>
#include <memory>
#include <map>
#include "gu_mmap.hpp"

namespace gu {

class PPage;
class PMemoryManager;

void dumpMappings();


struct PPage {
    int fd_;
    size_t offset_;
    char* ptr_;
};

class PMemoryManager {
public:
    PMemoryManager(size_t pagesCnt, size_t allocPageSize);
    ~PMemoryManager();
    std::shared_ptr<PPage> alloc();
    void free(std::shared_ptr<PPage> page);

private:
    char* base_;
    size_t size_;
    std::queue<std::shared_ptr<PPage>> freePages_;
    int fd_;
    bool mapped_;
    size_t allocPagesCnt_;

    PMemoryManager(const gu::PMemoryManager&);
    PMemoryManager operator=(const gu::PMemoryManager&);
};

class EncMMap : public IMMap
{
public:
    EncMMap(const std::string &key, MMap &mmap);
    size_t get_size() const override;
    void*  get_ptr() const override;

    void dont_need() const override;
    void sync(void *addr, size_t length) const override;
    void sync() const override;
    void unmap() override;
    ~EncMMap();

    void handle_signal(siginfo_t*);
    static void dumpMappings();
private:
    void encrypt(char* dst, char* src, size_t size, int pageNumber) const;
    void decrypt(char* dst, char* src, size_t size, int pageNumber) const;
    void dumpMappingsInt();
    std::string key_;
    MMap& mmapraw_;
    char* mmap_ptr_;
    char* base_;
    PMemoryManager memoryManager_;
    std::shared_ptr<int> page2protection_;
    std::map<void*, std::shared_ptr<PPage>> vpage2ppage_;
    size_t pagesCnt_;
    bool mapped_;

    char* page_start(char* addr) const;
    unsigned long long page_number(char* addr) const;
    void mprotectd(void *ptr, size_t size, int prot) const;

    EncMMap(const EncMMap&);
    EncMMap operator=(const EncMMap&);
};

} /* namespace gu */

#endif