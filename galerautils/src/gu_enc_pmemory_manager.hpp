#ifndef __ENC_PMEMORY_MANAGER__
#define __ENC_PMEMORY_MANAGER__

#include <memory>
#include <vector>

namespace gu {

struct PPage {
    int fd_;
    size_t offset_;
    char* ptr_;
};

/* PMemoryManger acts as the allocator of physical pages (PPage) for
   EncMMap. The size of physical memory is limited, so the client needs
   to handle this fact with proper management of them (flushing/fetching/etc)
*/
class PMemoryManager {
public:
    PMemoryManager(size_t pagesCnt, size_t allocPageSize);
    ~PMemoryManager();
    std::shared_ptr<PPage> alloc();
    void free(std::shared_ptr<PPage> page);
    /* Reset manager to its initial state. All pages are marked as free.
       This is useful for clients who decide to stop usage of physical memory
       without freeing allocated pages (e.g. they no longer care about the data)
    */
    void reset();
    void GetCreateParams(size_t* size, size_t* allocPageSize);

private:
    size_t createSize_;
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

    bool createTmpFile();
};

}  // namespace
#endif