/*
 * Copyright (C) 2009-2015 Codership Oy <info@codership.com>
 *
 * $Id$
 */

#include "gu_mmap.hpp"

#include "gu_logger.hpp"
#include "gu_throw.hpp"

#include <cerrno>
#include <sys/mman.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include "gu_limits.h"

#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

// to avoid -Wold-style-cast
extern "C" { static const void* const GU_MAP_FAILED = MAP_FAILED; }

namespace gu
{
    MMap::MMap (const FileDescriptor& fd, bool const sequential)
        :
        size   (fd.size()),
        ptr    (mmap (NULL, size, PROT_READ|PROT_WRITE,
                      MAP_SHARED|MAP_NORESERVE, fd.get(), 0)),
        mapped (ptr != GU_MAP_FAILED)
    {
        if (!mapped)
        {
            gu_throw_error(errno) << "mmap() on '" << fd.name()
                                  << "' failed";
        }

#if defined(MADV_DONTFORK)
        if (posix_madvise (ptr, size, MADV_DONTFORK))
        {
            int const err(errno);
            log_warn << "Failed to set MADV_DONTFORK on " << fd.name()
                     << ": " << err << " (" << strerror(err) << ")";
        }
#endif

        /* benefits are questionable */
        if (sequential && posix_madvise (ptr, size, MADV_SEQUENTIAL))
        {
            int const err(errno);
            log_warn << "Failed to set MADV_SEQUENTIAL on " << fd.name()
                     << ": " << err << " (" << strerror(err) << ")";
        }

        log_debug << "Memory mapped: " << ptr << " (" << size << " bytes)";
    }

    void
    MMap::dont_need() const
    {
        if (posix_madvise(reinterpret_cast<char*>(ptr), size, MADV_DONTNEED))
        {
            log_warn << "Failed to set MADV_DONTNEED on " << ptr << ": "
                     << errno << " (" << strerror(errno) << ')';
        }
    }

    void
    MMap::sync () const
    {
        log_info << "Flushing memory map to disk...";

        if (msync (ptr, size, MS_SYNC) < 0)
        {
            gu_throw_error(errno) << "msync(" << ptr << ", " << size
                                  << ") failed";
        }
    }

    void
    MMap::unmap ()
    {
        if (munmap (ptr, size) < 0)
        {
            gu_throw_error(errno) << "munmap(" << ptr << ", " << size
                                  << ") failed";
        }

        mapped = false;

        log_debug << "Memory unmapped: " << ptr << " (" << size <<" bytes)";
    }

    MMap::~MMap ()
    {
        if (mapped) unmap();
    }
}

/** Returns actual memory usage by allocated page range: **/

/*
 * Verify test macros to make sure we have mincore syscall:
 */
#if defined(_BSD_SOURCE) || defined(_SVID_SOURCE)

/*
 * The buffer size for mincore. 256 kilobytes is enough to request
 * information on the status of 1GB memory map (256K * 4096 bytes per
 * page = 1GB) in one syscall (when a 4096-byte pages). Increasing this
 * parameter allows us to save a few syscalls (when huge amounts of mmap),
 * but it also raises the memory requirements for temporary buffer:
 */
#define GU_AMU_CHUNK 0x40000 /* Currently 256K, must be power of two. */

size_t gu_actual_memory_usage (const void * const ptr, const size_t length)
{
    size_t size= 0;
    if (length)
    {
        /*
         * -PAGE_SIZE is same as ~(PAGE_SIZE-1), but creates less
         * potential problems due to implicit type cast in expressions:
         */
        uintptr_t first=
            reinterpret_cast<uintptr_t> (ptr) & -GU_PAGE_SIZE;
        const uintptr_t last=
           (reinterpret_cast<uintptr_t> (ptr) + length - 1) & -GU_PAGE_SIZE;
        const ptrdiff_t total=  last - first + GU_PAGE_SIZE;
        size_t          pages=  total / GU_PAGE_SIZE;
        size_t          chunks= pages / GU_AMU_CHUNK;
        unsigned char * const map=
            reinterpret_cast<unsigned char *> (malloc(chunks ? GU_AMU_CHUNK : pages));
        if (map)
        {
            while (chunks--)
            {
                if (mincore(reinterpret_cast<void *> (first),
                            (size_t) GU_AMU_CHUNK * GU_PAGE_SIZE, map) == 0)
                {
                    for (size_t i = 0; i < GU_AMU_CHUNK; i++)
                    {
                        if (map[i])
                        {
                            size += GU_PAGE_SIZE;
                        }
                    }
                }
                else
                {
                    log_fatal << "Unable to get in-core state vector "
                                 "for page range. Aborting.";
                    abort();
                }
                first += (size_t) GU_AMU_CHUNK * GU_PAGE_SIZE;
            }
            pages &= GU_AMU_CHUNK - 1;
            if (mincore(reinterpret_cast<void *> (first),
                        pages * GU_PAGE_SIZE, map) == 0)
            {
                for (size_t i = 0; i < pages; i++)
                {
                    if (map[i]) size += GU_PAGE_SIZE;
                }
            }
            else
            {
                log_fatal << "Unable to get in-core state vector "
                             "for page range. Aborting.";
                abort();
            }
            free(map);
        }
        else
        {
            log_fatal << "Unable to allocate memory for in-core state vector. "
                      << "Aborting.";
            abort();
        }
    }
    return size;
}

#else

/*
 * In case of absence mincore syscall we simply return the total size
 * of memory-mapped region:
 */
size_t gu_actual_memory_usage (const void * const ptr, const size_t length)
{
    return length;
}

#endif
