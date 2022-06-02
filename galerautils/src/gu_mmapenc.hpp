#ifndef __GCACHE_MMAPENC__
#define __GCACHE_MMAPENC__

#include <signal.h>
#include <vector>
#include <string>
#include <memory>
#include <map>
#include "gu_mmap.hpp"

namespace gu {

class PPage;
class PMemoryManager;

void dumpMappings();

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
    char* ptr_;
    PMemoryManager &memoryManager_;
    std::shared_ptr<int> page2protection_;
    std::map<void*, std::shared_ptr<PPage>> vpage2ppage_;
    size_t pagesCnt_;

    char* page_start(char* addr) const;
    unsigned long long page_number(char* addr) const;
    void mprotectd(void *ptr, size_t size, int prot) const;

    EncMMap(const EncMMap&);
    EncMMap operator=(const EncMMap&);
};

} /* namespace gu */

#endif