/*
 * Copyright (C) 2009-2018 Codership Oy <info@codership.com>
 */

#include "GCache.hpp"
// KH: gcache defaults
static const std::string GCACHE_PARAMS_DIR        ("gcache.dir");
static const std::string GCACHE_DEFAULT_DIR       ("");
static const std::string GCACHE_PARAMS_RB_NAME    ("gcache.name");
static const std::string GCACHE_DEFAULT_RB_NAME   ("galera.cache");
static const std::string GCACHE_PARAMS_MEM_SIZE   ("gcache.mem_size");
static const std::string GCACHE_DEFAULT_MEM_SIZE  ("0");
static const std::string GCACHE_PARAMS_RB_SIZE    ("gcache.size");
static const std::string GCACHE_DEFAULT_RB_SIZE   ("128M");
static const std::string GCACHE_PARAMS_PAGE_SIZE  ("gcache.page_size");
static const std::string GCACHE_DEFAULT_PAGE_SIZE (GCACHE_DEFAULT_RB_SIZE);
static const std::string GCACHE_PARAMS_KEEP_PAGES_SIZE("gcache.keep_pages_size");
static const std::string GCACHE_DEFAULT_KEEP_PAGES_SIZE("0");
#ifndef NDEBUG
static const std::string GCACHE_PARAMS_DEBUG      ("gcache.debug");
static const std::string GCACHE_DEFAULT_DEBUG     ("0");
#endif
static const std::string GCACHE_PARAMS_RECOVER    ("gcache.recover");
static const std::string GCACHE_DEFAULT_RECOVER   ("yes");

const std::string&
gcache::GCache::PARAMS_DIR                 (GCACHE_PARAMS_DIR);

#ifdef PXC
static const std::string GCACHE_PARAMS_KEEP_PAGES_COUNT("gcache.keep_pages_count");
static const std::string GCACHE_DEFAULT_KEEP_PAGES_COUNT("0");
static const std::string GCACHE_PARAMS_FREEZE_PURGE_SEQNO("gcache.freeze_purge_at_seqno");
static const std::string GCACHE_DEFAULT_FREEZE_PURGE_SEQNO("-1");
#endif /* PXC */
static const std::string GCACHE_PARAMS_ENCRYPTION("gcache.encryption");
static const std::string GCACHE_DEFAULT_ENCRYPTION("no");
static const std::string GCACHE_PARAMS_ENCRYPTION_CACHE_PAGE_SIZE("gcache.encryption_cache_page_size");
static const std::string GCACHE_DEFAULT_ENCRYPTION_CACHE_PAGE_SIZE("32K");
static const std::string GCACHE_PARAMS_ENCRYPTION_CACHE_SIZE("gcache.encryption_cache_size");
static const std::string GCACHE_DEFAULT_ENCRYPTION_CACHE_SIZE("16777216");  // 512 x 32K

void
gcache::GCache::Params::register_params(gu::Config& cfg)
{
    cfg.add(GCACHE_PARAMS_DIR,             GCACHE_DEFAULT_DIR);
    cfg.add(GCACHE_PARAMS_RB_NAME,         GCACHE_DEFAULT_RB_NAME);
    cfg.add(GCACHE_PARAMS_MEM_SIZE,        GCACHE_DEFAULT_MEM_SIZE);
    cfg.add(GCACHE_PARAMS_RB_SIZE,         GCACHE_DEFAULT_RB_SIZE);
    cfg.add(GCACHE_PARAMS_PAGE_SIZE,       GCACHE_DEFAULT_PAGE_SIZE);
    cfg.add(GCACHE_PARAMS_KEEP_PAGES_SIZE, GCACHE_DEFAULT_KEEP_PAGES_SIZE);
#ifndef NDEBUG
    cfg.add(GCACHE_PARAMS_DEBUG,           GCACHE_DEFAULT_DEBUG);
#endif
    cfg.add(GCACHE_PARAMS_RECOVER,         GCACHE_DEFAULT_RECOVER);
#ifdef PXC
    cfg.add(GCACHE_PARAMS_KEEP_PAGES_COUNT, GCACHE_DEFAULT_KEEP_PAGES_COUNT);
    cfg.add(GCACHE_PARAMS_FREEZE_PURGE_SEQNO, GCACHE_DEFAULT_FREEZE_PURGE_SEQNO);
#endif /* PXC */
    cfg.add(GCACHE_PARAMS_ENCRYPTION, GCACHE_DEFAULT_ENCRYPTION);
    cfg.add(GCACHE_PARAMS_ENCRYPTION_CACHE_PAGE_SIZE, GCACHE_DEFAULT_ENCRYPTION_CACHE_PAGE_SIZE);
    cfg.add(GCACHE_PARAMS_ENCRYPTION_CACHE_SIZE, GCACHE_DEFAULT_ENCRYPTION_CACHE_SIZE);
}

static const std::string
name_value (gu::Config& cfg, const std::string& data_dir)
{
    std::string dir(cfg.get(GCACHE_PARAMS_DIR));

    /* fallback to data_dir if gcache dir is not set */
    if (GCACHE_DEFAULT_DIR == dir && !data_dir.empty())
    {
        dir = data_dir;
        cfg.set (GCACHE_PARAMS_DIR, dir);
    }

    std::string rb_name(cfg.get (GCACHE_PARAMS_RB_NAME));

    /* prepend directory name to RB file name if the former is not empty and
     * the latter is not an absolute path */
    if ('/' != rb_name[0] && !dir.empty())
    {
        rb_name = dir + '/' + rb_name;
    }

    return rb_name;
}

gcache::GCache::Params::Params (gu::Config& cfg, const std::string& data_dir)
    :
    rb_name_  (name_value (cfg, data_dir)),
    dir_name_ (cfg.get(GCACHE_PARAMS_DIR)),
    mem_size_ (cfg.get<size_t>(GCACHE_PARAMS_MEM_SIZE)),
    rb_size_  (cfg.get<size_t>(GCACHE_PARAMS_RB_SIZE)),
    page_size_(cfg.get<size_t>(GCACHE_PARAMS_PAGE_SIZE)),
    keep_pages_size_(cfg.get<size_t>(GCACHE_PARAMS_KEEP_PAGES_SIZE)),
#ifndef NDEBUG
    debug_    (cfg.get<int>(GCACHE_PARAMS_DEBUG)),
#else
    debug_    (0),
#endif
    recover_  (cfg.get<bool>(GCACHE_PARAMS_RECOVER))
#ifdef PXC
    ,
    keep_pages_count_(cfg.get<size_t>(GCACHE_PARAMS_KEEP_PAGES_COUNT)),
    freeze_purge_at_seqno_(cfg.get<seqno_t>(GCACHE_PARAMS_FREEZE_PURGE_SEQNO)),
    encrypt_(cfg.get<bool>(GCACHE_PARAMS_ENCRYPTION)),
    encryption_cache_page_size_(cfg.get<size_t>(GCACHE_PARAMS_ENCRYPTION_CACHE_PAGE_SIZE)),
    encryption_cache_size_(cfg.get<size_t>(GCACHE_PARAMS_ENCRYPTION_CACHE_SIZE))
#endif /* PXC */
{}

void
gcache::GCache::param_set (const std::string& key, const std::string& val)
{
    if (key == GCACHE_PARAMS_RB_NAME)
    {
        gu_throw_error(EPERM) << "Can't change ring buffer name in runtime.";
    }
    else if (key == GCACHE_PARAMS_DIR)
    {
        gu_throw_error(EPERM) << "Can't change data dir in runtime.";
    }
    else if (key == GCACHE_PARAMS_ENCRYPTION ||
             key == GCACHE_PARAMS_ENCRYPTION_CACHE_PAGE_SIZE ||
             key == GCACHE_PARAMS_ENCRYPTION_CACHE_SIZE)
    {
        gu_throw_error(EPERM) << "Can't change gcache encryption parameters in runtime.";
    }
    else if (key == GCACHE_PARAMS_MEM_SIZE)
    {
        size_t tmp_size = gu::Config::from_config<size_t>(val);

#ifdef PXC
        if (tmp_size)
        {
            log_warn << GCACHE_PARAMS_MEM_SIZE
                     << " parameter is buggy and DEPRECATED,"
                     << " use it with care.";
        }
#endif /* PXC */

        gu::Lock lock(mtx);
        /* locking here serves two purposes: ensures atomic setting of config
         * and params.ram_size and syncs with malloc() method */

        config.set<size_t>(key, tmp_size);
        params.mem_size(tmp_size);
        mem.set_max_size(params.mem_size());
    }
    else if (key == GCACHE_PARAMS_RB_SIZE)
    {
        gu_throw_error(EPERM) << "Can't change ring buffer size in runtime.";
    }
    else if (key == GCACHE_PARAMS_PAGE_SIZE)
    {
        size_t tmp_size = gu::Config::from_config<size_t>(val);

        gu::Lock lock(mtx);
        /* locking here serves two purposes: ensures atomic setting of config
         * and params.ram_size and syncs with malloc() method */

        config.set<size_t>(key, tmp_size);
        params.page_size(tmp_size);
        ps.set_page_size(params.page_size());
    }
    else if (key == GCACHE_PARAMS_KEEP_PAGES_SIZE)
    {
        size_t tmp_size = gu::Config::from_config<size_t>(val);

        gu::Lock lock(mtx);
        /* locking here serves two purposes: ensures atomic setting of config
         * and params.ram_size and syncs with malloc() method */

        config.set<size_t>(key, tmp_size);
        params.keep_pages_size(tmp_size);
        ps.set_keep_size(params.keep_pages_size());
    }
    else if (key == GCACHE_PARAMS_RECOVER)
    {
        gu_throw_error(EINVAL) << "'" << key
                               << "' has a meaning only on startup.";
    }
#ifndef NDEBUG
    else if (key == GCACHE_PARAMS_DEBUG)
    {
        int d = gu::Config::from_config<int>(val);

        gu::Lock lock(mtx);
        /* locking here serves two purposes: ensures atomic setting of config
         * and params.ram_size and syncs with malloc() method */

        config.set<int>(key, d);
        params.debug(d);
        mem.set_debug(params.debug());
        rb.set_debug(params.debug());
        ps.set_debug(params.debug());
    }
#endif
#ifdef PXC
    else if (key == GCACHE_PARAMS_KEEP_PAGES_COUNT)
    {
        size_t tmp_size = gu::Config::from_config<size_t>(val);

        gu::Lock lock(mtx);
        /* locking here serves two purposes: ensures atomic setting of config
         * and params.ram_size and syncs with malloc() method */

        config.set<size_t>(key, tmp_size);
        params.keep_pages_count(tmp_size);
        /* keep last page if PS is the only storage: */
        ps.set_keep_count(params.keep_pages_count() ?
                          params.keep_pages_count() :
                          !((params.mem_size() + params.rb_size()) > 0));
   }
   else if (key == GCACHE_PARAMS_FREEZE_PURGE_SEQNO)
   {
        seqno_t seqno = -1;

        gu::Lock lock(mtx);
        /* locking here serves two purposes: ensures atomic setting of config
         * and params. */

        if (val.compare("now") == 0)
            seqno = (seqno2ptr.empty() ? 1 : seqno2ptr.index_begin());
        else
        {
            seqno = gu::Config::from_config<seqno_t>(val);

            if (seqno != SEQNO_ILL && seqno2ptr.find(seqno) == seqno2ptr.end())
            {
                log_info << "Freezing gcache purge failed "
                         << " (seqno not found in gcache)";
                throw gu::NotFound();
            }
        }

        log_info << "Freezing gcache purge at " << seqno;

        config.set<seqno_t>(key, seqno);
        params.freeze_purge_at_seqno(seqno);
        rb.set_freeze_purge_at_seqno(seqno);
   }
#endif /* PXC */
    else
    {
        throw gu::NotFound();
    }
}
