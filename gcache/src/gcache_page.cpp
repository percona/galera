/*
 * Copyright (C) 2010-2018 Codership Oy <info@codership.com>
 */

/*! @file page file class implementation */

#include "gcache_page.hpp"
#include "gcache_limits.hpp"
#include "gu_enc_mmap_factory.hpp"

#include <gu_throw.hpp>
#include <gu_logger.hpp>

// for posix_fadvise()
#if !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 600
#endif
#include <fcntl.h>

void
gcache::Page::reset ()
{
    if (gu_unlikely (used_ > 0))
    {
        log_fatal << "Attempt to reset a page '" << name()
                  << "' used by " << used_ << " buffers. Aborting.";
        abort();
    }

    space_ = mmap_.get_size();
    next_  = static_cast<uint8_t*>(mmap_.get_ptr());

#ifdef PXC
    BH_clear (reinterpret_cast<BufferHeader*>(next_));
#endif /* PXC */
}

void
gcache::Page::drop_fs_cache() const
{
    mmap_.dont_need();

#if !defined(__APPLE__)
#ifdef PXC
    int const err (posix_fadvise (fd_.get(), 0, size_,
                                  POSIX_FADV_DONTNEED));
#else
    int const err (posix_fadvise (fd_.get(), 0, fd_.size(),
                                  POSIX_FADV_DONTNEED));
#endif /* PXC */
    if (err != 0)
    {
        log_warn << "Failed to set POSIX_FADV_DONTNEED on " << fd_.name()
                 << ": " << err << " (" << strerror(err) << ")";
    }
#endif
}

gcache::Page::Page (void* ps, const std::string& name, size_t size, int dbg, bool encrypt, size_t encryptCachePageSize, size_t encryptCacheSize)
    :
#ifdef PXC
#ifdef HAVE_PSI_INTERFACE
    fd_   (name, WSREP_PFS_INSTR_TAG_GCACHE_PAGE_FILE, size, true, false),
#else
    fd_   (name, size, true, false),
#endif /* HAVE_PSI_INTERFACE */
#else
    fd_   (name, size, true, false),
#endif /* PXC */
    mmapptr_   (gu::MMapFactory::create(fd_, encrypt, encryptCachePageSize, encryptCacheSize, false, 0)),
    mmap_      (*mmapptr_),
    ps_   (ps),
    next_ (static_cast<uint8_t*>(mmap_.get_ptr())),
    space_(mmap_.get_size()),
    used_ (0),
#ifdef PXC
    size_ (mmap_.get_size()),
    min_space_ (space_),
#endif /* PXC */
    debug_(dbg)
{
    log_info << "Created page " << name << " of size " << space_
             << " bytes";
    BH_clear (reinterpret_cast<BufferHeader*>(next_));
}

void*
gcache::Page::malloc (size_type size)
{
    Limits::assert_size(size);

    if (size <= space_)
    {
        BufferHeader* bh(BH_cast(next_));

        bh->size    = size;
        bh->seqno_g = SEQNO_NONE;
        bh->ctx     = reinterpret_cast<BH_ctx_t>(this);
        bh->flags   = 0;
        bh->store   = BUFFER_IN_PAGE;

        assert(space_ >= size);
        space_ -= size;
        next_  += size;
        used_++;

#ifdef PXC
        if (min_space_ > space_)
        {
            min_space_ = space_;
        }
#endif /* PXC */

#ifndef NDEBUG
        if (space_ >= sizeof(BufferHeader))
        {
            BH_clear (BH_cast(next_));
            assert (reinterpret_cast<uint8_t*>(bh + 1) < next_);
        }

        assert (next_ <= static_cast<uint8_t*>(mmap_.get_ptr()) + mmap_.get_size());

        if (debug_) { log_info << name() << " allocd " << bh; }
#endif

        return (bh + 1);
    }
    else
    {
        log_debug << "Failed to allocate " << size << " bytes, space left: "
                  << space_ << " bytes, total allocated: "
                  << next_ - static_cast<uint8_t*>(mmap_.get_ptr());
        return 0;
    }
}

void*
gcache::Page::realloc (void* ptr, size_type size)
{
    Limits::assert_size(size);

    BufferHeader* bh(ptr2BH(ptr));

    if (bh == BH_cast(next_ - bh->size)) // last buffer, can shrink and expand
    {
        diff_type const diff_size (size - bh->size);

        if (gu_likely (diff_size < 0 || size_t(diff_size) < space_))
        {
            bh->size += diff_size;
            space_   -= diff_size;
            next_    += diff_size;

#ifdef PXC
            if (min_space_ > space_)
            {
                min_space_ = space_;
            }

#ifndef NDEBUG
            if (space_ >= static_cast<size_t>(sizeof(BufferHeader)))
            {
                BH_clear (BH_cast(next_));
                assert (reinterpret_cast<uint8_t*>(bh + 1) < next_);
            }

            assert (next_ <= static_cast<uint8_t*>(mmap_.get_ptr()) + mmap_.get_size());
#endif
#else
            BH_clear (BH_cast(next_));
#endif /* PXC */

            return ptr;
        }
        else return 0; // not enough space in this page
    }
    else
    {
        if (gu_likely(size > 0 && uint32_t(size) > bh->size))
        {
            void* const ret (malloc (size));

            if (ret)
            {
                memcpy (ret, ptr, bh->size - sizeof(BufferHeader));
                assert(used_ > 0);
                used_--;
            }

            return ret;
        }
        else
        {
            // do nothing, we can't shrink the buffer, it is locked
            return ptr;
        }
    }
}

#ifdef PXC
size_t gcache::Page::allocated_pool_size ()
{
    return mmap_.get_size() - min_space_;
}
#endif /* PXC */

void gcache::Page::print(std::ostream& os) const
{
    os << "page file: " << name() << ", size: " << size() << ", used: "
       << used_;

    if (used_ > 0 && debug_ > 0)
    {
        bool was_released(true);
        const uint8_t* const start(static_cast<uint8_t*>(mmap_.get_ptr()));
        const uint8_t* p(start);
        assert(p != next_);
        while (p != next_)
        {
            ptrdiff_t const offset(p - start);
            const BufferHeader* const bh(BH_const_cast(p));
            p += bh->size;
            if (!BH_is_released(bh))
            {
                os << "\noff: " << offset << ", " << bh;
                was_released = false;
            }
            else
            {
                if (!was_released && p != next_)
                {
                    os << "\n..."; /* indicate gap */
                }
                was_released = true;
            }
        }
    }
}
