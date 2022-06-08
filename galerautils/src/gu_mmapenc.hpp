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

struct encThdMsg {
    char* dst_;
    char* src_;
    size_t size_;
    int pageNo_;
};

// A threadsafe-queue.
template <class T>
class SafeQueue
{
public:
  SafeQueue(void)
    : q()
    , m()
    , c()
  {}

  ~SafeQueue(void)
  {}

  // Add an element to the queue.
  void enqueue(T t)
  {
    std::lock_guard<std::mutex> lock(m);
    q.push(t);
    c.notify_one();
  }

  // Get the "front"-element.
  // If the queue is empty, wait till a element is avaiable.
  T dequeue(void)
  {
    std::unique_lock<std::mutex> lock(m);
    while(q.empty())
    {
      // release lock as long as the wait and reaquire it afterwards.
      c.wait(lock);
    }
    T val = q.front();
    q.pop();
    return val;
  }

private:
  std::queue<T> q;
  mutable std::mutex m;
  std::condition_variable c;
};




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
    size_t allocPageSize_;

    PMemoryManager(const gu::PMemoryManager&);
    PMemoryManager operator=(const gu::PMemoryManager&);
};

class Encryptor {
public:
    Encryptor(unsigned char* key, unsigned char* iv,
              SafeQueue<encThdMsg>& queue, std::atomic_int& finishCounter);
    ~Encryptor();
    void stop();
    Encryptor(const gu::Encryptor&) = delete;
private:
    void thdFn();

    mutable Aes_ctr_encryptor encryptor_;
    std::atomic_bool finish_;
    SafeQueue<encThdMsg>& queue_;
    std::atomic_int& finishCounter_;
    std::thread thd_;
};

class EncMMap : public IMMap
{
public:
    EncMMap(const std::string &key, MMap &mmap, size_t encryptionStartOffset = 0);
    size_t get_size() const override;
    void*  get_ptr() const override;

    void dont_need() const override;
    void sync(void *addr, size_t length) const override;
    void sync() const override;
    void unmap() override;
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
    MMap& mmapraw_;
    char* mmap_ptr_;
    char* base_;
    PMemoryManager memoryManager_;
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

    SafeQueue<encThdMsg> encThreadQueue_;
    std::atomic_int encThreadFinishCounter_;
    std::vector<std::shared_ptr<Encryptor>> encryptors_;

    char* page_start(unsigned long long pageNo) const;
    char* page_start(char* addr) const;
    unsigned long long page_number(char* addr) const;
    void mprotectd(void *ptr, size_t size, int prot) const;

    EncMMap(const EncMMap&);
    EncMMap operator=(const EncMMap&);
};

} /* namespace gu */

#endif