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


class EncMMap : public IMMap
{
public:
    EncMMap(const std::string &key, std::shared_ptr<MMap> mmap,
            size_t cachePageSize, size_t cacheSize, bool syncOnDestroy = false,
            size_t encryptionStartOffset = 0);
    ~EncMMap();

    EncMMap(const EncMMap&) = delete;
    EncMMap operator=(const EncMMap&) = delete;

    size_t get_size() const override;
    void*  get_ptr() const override;

    void dont_need() const override;
    void sync(void *addr, size_t length) const override;
    void sync() const override;
    void unmap() override;
    void set_key(const std::string& key) override;

    void handle_signal(siginfo_t*);

    bool lock();
    void unlock();

    static void dumpMappings();
private:
    void encrypt(unsigned char* dst, unsigned char* src, size_t size, size_t pageNumber) const;
    void decrypt(unsigned char* dst, unsigned char* src, size_t size, size_t pageNumber) const;
    void dumpMappingsInt();
    std::shared_ptr<MMap> mmapraw_;
    size_t pageSize_;
    unsigned char* mmaprawPtr_;
    size_t vMemSize_;
    unsigned char* mmap_ptr_;
    unsigned char* base_;
    std::shared_ptr<PMemoryManager> memoryManagerP_;
    PMemoryManager &memoryManager_;
    std::shared_ptr<int> page2protectionGuard_;
    int* page2protection_;
    std::map<unsigned char*, std::shared_ptr<PPage>> vpage2ppage_;
    size_t pagesCnt_;
    bool mapped_;
    size_t lastPageSize_;
    size_t encryptionStartOffset_;
    int defaultPageProtection_;
    std::atomic_flag lock_;
    mutable Aes_ctr_encryptor encryptor_;
    mutable Aes_ctr_decryptor decryptor_;
    bool syncOnDestroy_;

    unsigned char* page_start(unsigned long long pageNo) const;
    unsigned char* page_start(unsigned char* addr) const;
    size_t page_number(unsigned char* addr) const;
    void mprotectd(unsigned char *ptr, size_t size, int prot) const;
};

} /* namespace gu */

#endif