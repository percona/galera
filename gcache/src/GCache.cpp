/*
 * Copyright (C) 2009-2025 Codership Oy <info@codership.com>
 */

#include "GCache.hpp"
#include "gcache_bh.hpp"

#include <gu_logger.hpp>

#include <cerrno>
#include <unistd.h>

namespace gcache
{
    void
    GCache::reset()
    {
        mem.reset();
        rb.reset();
        ps.reset();

        mallocs  = 0;
        reallocs = 0;
#ifdef PXC
        frees    = 0;
#endif /* PXC */

        gid            = gu::UUID();
        seqno_max      = SEQNO_NONE;
        seqno_released = SEQNO_NONE;
        seqno_low_     = SEQNO_NONE;
        seqno_locked   = SEQNO_MAX;
        seqno_locked_count = 0;

        seqno2ptr.clear(SEQNO_NONE);

#ifndef NDEBUG
        buf_tracker.clear();
#endif
    }

    GCache::GCache (ProgressCallback* pcb,
                    gu::Config& cfg, const std::string& data_dir,
                    gu::MasterKeyProvider* mk_provider)
        :
        config    (cfg),
        params    (config, data_dir),
#ifdef PXC
#ifdef HAVE_PSI_INTERFACE
        mtx       (WSREP_PFS_INSTR_TAG_GCACHE_MUTEX),
#else
         mtx       (),
#endif /* HAVE_PSI_INTERFACE */
#else
        mtx       (),
#endif /* PXC */
        seqno2ptr (SEQNO_NONE),
        gid       (),
        mem       (params.mem_size(), seqno2ptr, params.debug()),
        rb        (pcb, params.rb_name(), params.rb_size(), seqno2ptr, gid,
                   params.debug(), params.recover(), params.encrypt(),
                   params.encryption_cache_page_size(),
                   std::min(params.encryption_cache_size(), params.rb_size()),
                   mk_provider),
        ps        (*this,
                   params.dir_name(),
                   params.keep_pages_size(),
                   params.page_size(),
                   params.debug(),
#ifdef PXC
                   /* keep last page if PS is the only storage */
                   params.keep_pages_count() ?
                   params.keep_pages_count() :
                    !((params.mem_size() + params.rb_size()) > 0),
                   params.encrypt(),
                   params.encryption_cache_page_size(),
                   std::min(params.encryption_cache_size(), params.page_size())),
#else
                   !((params.mem_size() + params.rb_size()) > 0)),
#endif /* PXC */
        mallocs   (0),
        reallocs  (0),
        frees     (0),
        seqno_max     (seqno2ptr.empty() ?
                       SEQNO_NONE : seqno2ptr.index_back()),
        seqno_released(seqno_max),
        seqno_low_    (SEQNO_NONE),
        seqno_locked  (SEQNO_MAX),
        seqno_locked_count(0)
#ifndef NDEBUG
        ,buf_tracker()
        ,in_dtor(false)
#endif
    {}

    GCache::~GCache ()
    {
        gu::Lock lock(mtx);
        log_debug << "\n" << "GCache mallocs : " << mallocs
                  << "\n" << "GCache reallocs: " << reallocs
                  << "\n" << "GCache frees   : " << frees;
#ifndef NDEBUG
        in_dtor = true;
#endif
    }

#ifdef PXC
    size_t GCache::allocated_pool_size ()
    {
        gu::Lock lock(mtx);
        return mem.allocated_pool_size() +
               rb.allocated_pool_size() +
               ps.allocated_pool_size();
    }
#endif /* PXC */

    /*! prints object properties */
    void print (std::ostream& os) {}
}

#include "gcache.h"

gcache_t* gcache_create (gu_config_t* conf, const char* data_dir)
{
    /* this funciton is used only in tests */
    gcache::GCache* gc = new gcache::GCache (
        NULL, *reinterpret_cast<gu::Config*>(conf), data_dir);
    return reinterpret_cast<gcache_t*>(gc);
}

void gcache_destroy (gcache_t* gc)
{
    gcache::GCache* gcache = reinterpret_cast<gcache::GCache*>(gc);
    delete gcache;
}

void* gcache_malloc  (gcache_t* gc, int size)
{
    gcache::GCache* gcache = reinterpret_cast<gcache::GCache*>(gc);
    return gcache->malloc (size);
}

void  gcache_free    (gcache_t* gc, const void* ptr)
{
    gcache::GCache* gcache = reinterpret_cast<gcache::GCache*>(gc);
    gcache->free (const_cast<void*>(ptr));
}

void* gcache_realloc (gcache_t* gc, void* ptr, int size)
{
    gcache::GCache* gcache = reinterpret_cast<gcache::GCache*>(gc);
    return gcache->realloc (ptr, size);
}

int64_t gcache_seqno_min (gcache_t* gc)
{
    gcache::GCache* gcache = reinterpret_cast<gcache::GCache*>(gc);
    return gcache->seqno_min ();
}
