/*
 * Copyright (C) 2009-2016 Codership Oy <info@codership.com>
 *
 * $Id$
 */

#ifndef __GCACHE_MMAP__
#define __GCACHE_MMAP__

#include "gu_fdesc.hpp"

namespace gu
{

class IMMap
{
public:
    virtual size_t get_size() const = 0;
    virtual void*  get_ptr() const = 0;

    virtual void dont_need() const = 0;
    virtual void sync(void *addr, size_t length) const = 0;
    virtual void sync() const = 0;
    virtual void unmap() = 0;

    virtual void set_key(const std::string& key) = 0;

    enum AccessMode {
        READ,
        READ_WRITE
    };
    virtual void set_access_mode(AccessMode mode) = 0;
    virtual ~IMMap(){};
};

class MMap : public IMMap
{
public:
    size_t const size;
    void*  const ptr;
    size_t get_size() const override { return size; }
    void*  get_ptr() const override { return ptr; }

    MMap (const FileDescriptor& fd, bool sequential = false);

    ~MMap ();

    void dont_need() const override;
    void sync(void *addr, size_t length) const override;
    void sync() const override;
    void unmap() override;
    void set_key(const std::string& key) override {}
    void set_access_mode(AccessMode mode) override {};

private:

    bool mapped;

    // This class is definitely non-copyable
    MMap (const MMap&);
    MMap& operator = (const MMap);
};

} /* namespace gu */

#endif /* __GCACHE_MMAP__ */
