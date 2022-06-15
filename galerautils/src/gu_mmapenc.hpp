#ifndef __GCACHE_MMAPENC__
#define __GCACHE_MMAPENC__

#include <signal.h>
#include <queue>
#include <string>
#include <memory>
#include <map>
#include <atomic>
#include "gu_mmap.hpp"
#include "enc_stream_cipher.h"
#include <mutex>
#include <condition_variable>
#include <thread>

namespace gu {

class PPage;
class PMemoryManager;

void dumpMappings();

std::string generateRandomKey();

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
    void reset();
private:
    char* base_;
    size_t size_;
    std::vector<std::shared_ptr<PPage>> freePages_;
    std::vector<std::shared_ptr<PPage>> myPages_;
    int fd_;
    bool mapped_;
    size_t allocPagesCnt_;
    size_t allocPageSize_;

    PMemoryManager(const gu::PMemoryManager&);
    PMemoryManager operator=(const gu::PMemoryManager&);
};

class EncMMap : public IMMap
{
public:
    EncMMap(const std::string &key, std::shared_ptr<MMap> mmap,
            size_t cachePageSize, size_t cacheSize, size_t encryptionStartOffset = 0);
    size_t get_size() const override;
    void*  get_ptr() const override;

    void dont_need() const override;
    void sync(void *addr, size_t length) const override;
    void sync() const override;
    void unmap() override;
    void set_key(const std::string& key) override;
    
    ~EncMMap();

    void handle_signal(siginfo_t*);

    bool lock();
    void unlock();

    static void dumpMappings();
private:
    void encrypt(char* dst, char* src, size_t size, int pageNumber) const;
    void decrypt(char* dst, char* src, size_t size, int pageNumber) const;
    void dumpMappingsInt();
    std::string key_;
    std::shared_ptr<MMap> mmapraw_;
    void* mmaprawPtr_;
    size_t vMemSize_;
    char* mmap_ptr_;
    char* base_;
    std::shared_ptr<PMemoryManager> memoryManagerP_;
    PMemoryManager &memoryManager_;
    std::shared_ptr<int> page2protection_;
    std::map<void*, std::shared_ptr<PPage>> vpage2ppage_;
    size_t pagesCnt_;
    bool mapped_;
    size_t lastPageSize_;
    size_t encryptionStartOffset_;
    int defaultPageProtection_;
    std::atomic_bool locked_;
    mutable Aes_ctr_encryptor encryptor_;
    mutable Aes_ctr_decryptor decryptor_;

    char* page_start(unsigned long long pageNo) const;
    char* page_start(char* addr) const;
    unsigned long long page_number(char* addr) const;
    void mprotectd(void *ptr, size_t size, int prot) const;

    EncMMap(const EncMMap&);
    EncMMap operator=(const EncMMap&);
};

} /* namespace gu */

#endif