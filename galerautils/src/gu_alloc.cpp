/* Copyright (C) 2013-2016 Codership Oy <info@codership.com> */
/*!
 * @file allocator main functions
 *
 * $Id$
 */

#include "gu_alloc.hpp"
#include "gu_throw.hpp"
#include "gu_assert.hpp"
#include "gu_arch.h"
#include "gu_limits.h"
#include "gu_enc_mmap_factory.hpp"
#include "gu_config.hpp"

#include <sstream>
#include <iomanip> // for std::setfill() and std::setw()

static bool g_encryptOffPages = false;
static size_t g_encryptCachePageSize = 0;
static size_t g_encryptCacheSize = 0;

gu::Allocator::HeapPage::HeapPage (page_size_type const size) :
    Page (static_cast<byte_t*>(::malloc(size)), size)
{
    assert(0 == (uintptr_t(base_ptr_) % GU_WORD_BYTES));
    if (0 == base_ptr_) gu_throw_error (ENOMEM);
}


gu::Allocator::Page*
gu::Allocator::HeapStore::my_new_page (page_size_type const size)
{
    if (gu_likely(size <= left_))
    {
        /* to avoid too frequent allocation, make it (at least) 64K */
        static page_size_type const PAGE_SIZE(gu_page_size_multiple(1 << 16));

        page_size_type const page_size
            (std::min(std::max(size, PAGE_SIZE), left_));

        Page* ret = new HeapPage (page_size);

        assert (ret != 0);

        left_ -= page_size;

        return ret;
    }

    gu_throw_error (ENOMEM) << "out of memory in RAM pool";
}


gu::Allocator::FilePage::FilePage (const std::string& name,
                                   page_size_type const size)
    :
    Page (0, 0),
#ifdef PXC
#ifdef HAVE_PSI_INTERFACE
    fd_  (name, WSREP_PFS_INSTR_TAG_RECORDSET_FILE, size, false, false),
#else
    fd_  (name, size, false, false),
#endif /* HAVE_PSI_INTERFACE */
#else
    fd_  (name, size, false, false),
#endif /* PXC */
    mmapptr_   (MMapFactory::create(fd_, g_encryptOffPages,
                g_encryptCachePageSize, std::min(g_encryptCacheSize, (size_t)size), false, 0)),
    mmap_      (*mmapptr_)
{
    base_ptr_ = static_cast<byte_t*>(mmap_.get_ptr());
    assert(0 == (uintptr_t(base_ptr_) % GU_WORD_BYTES));
    ptr_      = base_ptr_;
    left_     = mmap_.get_size();
}


gu::Allocator::Page*
gu::Allocator::FileStore::my_new_page (page_size_type const size)
{
    Page* ret = 0;

    try {
        std::ostringstream fname;

        fname << base_name_
              << '.' << std::dec << std::setfill('0') << std::setw(6) << n_;

        ret = new FilePage(fname.str(), std::max(size, page_size_));

        assert (ret != 0);

        ++n_;
    }
    catch (std::exception& e)
    {
        gu_throw_error(ENOMEM) << e.what();
    }

    return ret;
}

#ifdef GU_ALLOCATOR_DEBUG
void
gu::Allocator::add_current_to_bufs()
{
    page_size_type const current_size (current_page_->size());

    if (current_size)
    {
        if (bufs_->empty() || bufs_->back().ptr != current_page_->base())
        {
            Buf b = { current_page_->base(), current_size };
            bufs_->push_back (b);
        }
        else
        {
            bufs_->back().size = current_size;
        }
    }
}

size_t
gu::Allocator::gather (std::vector<gu::Buf>& out) const
{
    if (bufs_().size()) out.insert (out.end(), bufs_().begin(), bufs_().end());

    Buf b = { current_page_->base(), current_page_->size() };

    out.push_back (b);

    return size_;
}
#endif /* GU_ALLOCATOR_DEBUG */

gu::byte_t*
gu::Allocator::alloc (page_size_type const size, bool& new_page)
{
    new_page = false;

    if (gu_unlikely(0 == size)) return 0;

    byte_t* ret = current_page_->alloc (size);

    if (gu_unlikely(0 == ret))
    {
        Page* np = 0;

        try
        {
            np = current_store_->new_page(size);
        }
        catch (Exception& e)
        {
            if (current_store_ != &heap_store_) throw; /* no fallbacks left */

            /* fallback to disk store */
            current_store_ = &file_store_;

            np  = current_store_->new_page(size);
        }

        assert (np != 0); // it should have thrown above

        pages_().push_back (np);

#ifdef GU_ALLOCATOR_DEBUG
        add_current_to_bufs();
#endif /* GU_ALLOCATOR_DEBUG */

        current_page_ = np;

        new_page = true;
        ret      = np->alloc (size);

        assert (ret != 0); // the page should be sufficiently big
    }

    size_ += size;

    return ret;
}

gu::Allocator::BaseNameDefault const gu::Allocator::BASE_NAME_DEFAULT;

gu::Allocator::Allocator (const BaseName&         base_name,
                          void*                   reserved,
                          page_size_type          reserved_size,
                          heap_size_type          max_ram,
                          page_size_type          disk_page_size)
        :
    first_page_   (reserved, reserved_size),
    current_page_ (&first_page_),
    heap_store_   (max_ram),
    file_store_   (base_name, disk_page_size),
    current_store_(&heap_store_),
    pages_        (),
#ifdef GU_ALLOCATOR_DEBUG
    bufs_         (),
#endif /* GU_ALLOCATOR_DEBUG */
    size_         (0)
{
    assert (NULL != reserved || 0 == reserved_size);
    assert (0 == (uintptr_t(reserved) % GU_WORD_BYTES));
    assert (current_page_ != 0);
    pages_->push_back (current_page_);
}


gu::Allocator::~Allocator ()
{
    for (int i(pages_->size() - 1);
         i > 0 /* don't delete first_page_ - we didn't allocate it */;
         --i)
    {
        delete (pages_[i]);
    }
}

static const std::string ALLOCATOR_PARAMS_DISK_PAGES_ENCRYPTION("allocator.disk_pages_encryption");
static const std::string ALLOCATOR_DEFAULT_DISK_PAGES_ENCRYPTION("yes");
static const std::string ALLOCATOR_PARAMS_ENCRYPTION_CACHE_PAGE_SIZE("allocator.encryption_cache_page_size");
static const std::string ALLOCATOR_DEFAULT_ENCRYPTION_CACHE_PAGE_SIZE("32K");
static const std::string ALLOCATOR_PARAMS_ENCRYPTION_CACHE_SIZE("allocator.encryption_cache_size");
static const std::string ALLOCATOR_DEFAULT_ENCRYPTION_CACHE_SIZE("16777216");  // 512 x 32K

void gu::Allocator::register_params(gu::Config& conf)
{
    conf.add(ALLOCATOR_PARAMS_DISK_PAGES_ENCRYPTION, ALLOCATOR_DEFAULT_DISK_PAGES_ENCRYPTION);
    conf.add(ALLOCATOR_PARAMS_ENCRYPTION_CACHE_PAGE_SIZE, ALLOCATOR_DEFAULT_ENCRYPTION_CACHE_PAGE_SIZE);
    conf.add(ALLOCATOR_PARAMS_ENCRYPTION_CACHE_SIZE, ALLOCATOR_DEFAULT_ENCRYPTION_CACHE_SIZE);
}

// We can do it this way as these parameters cannot be changed in runtime
void gu::Allocator::configure_encryption(gu::Config& conf)
{
    g_encryptOffPages = conf.get<bool>(ALLOCATOR_PARAMS_DISK_PAGES_ENCRYPTION);
    g_encryptCachePageSize = conf.get<size_t>(ALLOCATOR_PARAMS_ENCRYPTION_CACHE_PAGE_SIZE);
    g_encryptCacheSize = conf.get<size_t>(ALLOCATOR_PARAMS_ENCRYPTION_CACHE_SIZE);
}
