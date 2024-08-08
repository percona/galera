//
// Copyright (C) 2013-2024 Codership Oy <info@codership.com>
//

#include "key_set.hpp"

#include "gu_logger.hpp"
#include "gu_hexdump.hpp"

#include <limits>
#include <algorithm> // std::transform

namespace galera
{

void
KeySet::throw_version(int ver)
{
    gu_throw_error(EINVAL) << "Unsupported KeySet version: " << ver;
}

static const char* ver_str[KeySet::MAX_VERSION + 1] =
{
    "EMPTY", "FLAT8", "FLAT8A", "FLAT16", "FLAT16A"
};

KeySet::Version
KeySet::version (const std::string& ver)
{
    std::string tmp(ver);
    std::transform(tmp.begin(), tmp.end(), tmp.begin(), ::toupper);

    for (int i(EMPTY); i <= MAX_VERSION; ++i)
    {
        if (tmp == ver_str[i]) return version(i);
    }

    gu_throw_error(EINVAL) << "Unsupported KeySet version: " << ver; throw;
}

static const char* type_str[4] = { "SH", "RE", "UP", "EX" };

const char*
KeySet::type(wsrep_key_type_t t)
{
    assert(size_t(t) < sizeof(type_str) / sizeof(type_str[0]));
    return type_str[t];
}

size_t
KeySet::KeyPart::store_annotation (const wsrep_buf_t* const parts,
                                   int                const part_num,
                                   gu::byte_t*              buf,
                                   int                const size,
                                   int                const alignment)
{
    assert(size >= 0);

    /* max len representable in one byte */
    static size_t const max_part_len(std::numeric_limits<gu::byte_t>::max());

    /* max multiple of alignment_ len representable in ann_size_t */
    ann_size_t const max_ann_len(std::numeric_limits<ann_size_t>::max() /
                                 alignment * alignment);

    ann_size_t ann_size;
    int        tmp_size(sizeof(ann_size));

    for (int i(0); i <= part_num; ++i)
    {
        tmp_size += 1 + std::min(parts[i].len, max_part_len);
    }

    assert(tmp_size > 0);

    /* Make sure that final annotation size is
     * 1) is a multiple of alignment
     * 2) is representable with ann_size_t
     * 3) doesn't exceed dst buffer size
     */
    ann_size = std::min<size_t>(GU_ALIGN(tmp_size, alignment), max_ann_len);
    ann_size = std::min<size_t>(ann_size, size / alignment * alignment);
    assert (ann_size <= size);
    assert ((ann_size % alignment) == 0);

    ann_size_t const pad_size(tmp_size < ann_size ? ann_size - tmp_size : 0);

    if (gu_likely(ann_size > 0))
    {
        ann_size_t const tmp(gu::htog(ann_size));
        ann_size_t       off(sizeof(tmp));

        ::memcpy(buf, &tmp, off);

        for (int i(0); i <= part_num && off < ann_size; ++i)
        {
            size_t const left(ann_size - off - 1);
            gu::byte_t const part_len
                (std::min(std::min(parts[i].len, left), max_part_len));

            buf[off] = part_len; ++off;

            const gu::byte_t* const from(
                static_cast<const gu::byte_t*>(parts[i].ptr));

            std::copy(from, from + part_len, buf + off);

            off += part_len;
        }

        if (pad_size > 0)
        {
            ::memset(buf + off, 0, pad_size);
            off += pad_size;
        }

        assert (off == ann_size);
    }
//    log_info << "stored annotation of size: " << ann_size;

    return ann_size;
}

void
KeySet::KeyPart::print_annotation(std::ostream& os, const gu::byte_t* buf)
{
    ann_size_t const ann_size(gu::gtoh<ann_size_t>(
                                  *reinterpret_cast<const ann_size_t*>(buf)));

    size_t const begin(sizeof(ann_size_t));
    size_t off(begin);

    while (off < ann_size)
    {
        if (off != begin) os << '/';

        gu::byte_t const part_len(buf[off]); ++off;

        bool const last(ann_size == off + part_len);

        /* this is an attempt to guess whether we should interpret key part as
         * a string or numerical value */
        bool const alpha(!last || part_len > 8);

        os << gu::Hexdump (buf + off, part_len, alpha);

        off += part_len;
    }
}

void
KeySet::KeyPart::throw_buffer_too_short (size_t expected, size_t got)
{
#ifndef NDEBUG
    log_fatal
#else
    gu_throw_error(EINVAL)
#endif /* NDEBUG */
        << "Buffer too short: expected " << expected << ", got " << got;
    assert(0);
}

void
KeySet::KeyPart::throw_bad_type_version (wsrep_key_type_t t, int v)
{
#ifndef NDEBUG
    log_fatal
#else
    gu_throw_error(EINVAL)
#endif /* NDEBUG */
        << "Internal program error: wsrep key type: " << t
        << ", writeset version: " << v;
    assert(0);
}

void
KeySet::KeyPart::throw_bad_prefix (gu::byte_t p)
{
#ifndef NDEBUG
    log_fatal
#else
    gu_throw_error(EPROTO)
#endif /* NDEBUG */
        << "Unsupported key prefix: " << int(p);
    assert(0);
}

void
KeySet::KeyPart::throw_match_empty_key (Version my, Version other)
{
#ifndef NDEBUG
    log_fatal
#else
    gu_throw_error(EINVAL)
#endif /* NDEBUG */
        << "Attempt to match against an empty key (" << my << ',' << other <<')';
    assert(0);
}

void
KeySet::KeyPart::print (std::ostream& os) const
{
    Version const ver(version());

    size_t const size(ver != EMPTY ? base_size(ver, data_, 1) : 0);

    os << '(' << prefix() << ',' << ver_str[ver] << ')'
       << gu::Hexdump(data_, size);

    if (annotated(ver))
    {
        os << "=";
        print_annotation (os, data_ + size);
    }
}

/* returns true if left type is stronger than right */
static inline bool
key_prefix_is_stronger_than(int const left,
                            int const right)
{
    return left > right;
}

KeySetOut::KeyPart::KeyPart (KeyParts&      added,
                             KeySetOut&     store,
                             const KeyPart* parent,
                             const KeyData& kd,
                             int const      part_num,
                             int const      ws_ver,
                             int const      alignment)
    :
    hash_ (parent->hash_),
    part_ (0),
    value_(static_cast<const gu::byte_t*>(kd.parts[part_num].ptr)),
    size_ (kd.parts[part_num].len),
    ver_  (parent->ver_),
    own_  (false)
{
    assert (ver_);
    uint32_t const s(gu::htog(size_));
    hash_.append (&s, sizeof(s));
    hash_.append (value_, size_);

    KeySet::KeyPart::TmpStore ts;
    KeySet::KeyPart::HashData hd;

    hash_.gather<sizeof(hd.buf)>(hd.buf);

    /* only leaf part of the key can be not of branch type */
    bool const leaf (part_num + 1 == kd.parts_num);
    wsrep_key_type_t const type (leaf ? kd.type : KeyData::BRANCH_KEY_TYPE);
    int const prefix (KeySet::KeyPart::prefix(type, ws_ver));

//    log_info << "Part " << part_num +1 << '/' << kd.parts_num << ": leaf: " << leaf << ", kd.type: " << kd.type << ", type: " << type << ", prefix: " << prefix;
    assert (kd.parts_num > part_num);

    KeySet::KeyPart kp(ts, hd, kd.parts, ver_, prefix, part_num, alignment);

    std::pair<KeyParts::iterator, bool> const inserted(added.insert(kp));

    if (inserted.second)
    {
        /* The key part was successfully inserted, store it in the key set
           buffer */
        inserted.first->store (store);
    }
    else
    {
        /* A matching key part instance is already present in the set,
           check constraints */
        if (key_prefix_is_stronger_than(prefix, inserted.first->prefix()))
        {
            /* The key part instance present in the set has weaker constraint,
               store this instance as well and update inserted to point there.
               (we can't update already stored data - it was checksummed, so we
               have to store a duplicate with a stronger constraint) */
            kp.store (store);
            inserted.first->update_ptr(kp.ptr());
            /* It is a hack, but it should be safe to modify key part already
               inserted into unordered set, as long as modification does not
               change hash and equality test results. And we get it to point to
               a duplicate here.*/
        }
        else if (leaf || key_prefix_is_stronger_than(inserted.first->prefix(),
                                                     prefix))
        {
            /* we don't throw DUPLICATE for branch parts, just ignore them.
               DUPLICATE is thrown only when the whole key is a duplicate. */
#ifndef NDEBUG
            if (leaf)
                log_debug << "KeyPart ctor: full duplicate of "
                          << *inserted.first;
            else
                log_debug << "Duplicate of exclusive: " << *inserted.first;
#endif
            throw DUPLICATE();
        }
    }

    part_ = &(*inserted.first);
}

void
KeySetOut::KeyPart::print (std::ostream& os) const
{
    if (part_)
        os << *part_;
    else
        os << "0x0";

    os << '(' << gu::Hexdump(value_, size_, true) << ')';
}

/* Uncomment to enable KeySetOut::append() debug logging */
// #define GALERA_KSO_APPEND_DEBUG 1
#ifdef GALERA_KSO_APPEND_DEBUG
#define KSO_APPEND_DEBUG(...) log_info << __VA_ARGS__
#else
#define KSO_APPEND_DEBUG(...)
#endif

int KeySetOut::find_common_ancestor_with_previous(const KeyData& kd) const
{
    int i(0);
    for (;
         i < kd.parts_num &&
             size_t(i + 1) < prev_.size() &&
             prev_[i + 1].match(kd.parts[i].ptr, kd.parts[i].len);
         ++i)
    {
        KSO_APPEND_DEBUG("prev[" << (i+1) << "]\n"
                         << prev_[i+1]
                         << "\nmatches\n"
                         << gu::Hexdump(kd.parts[i].ptr, kd.parts[i].len, true));
    }
    assert(size_t(i) < prev_.size());
    return i;
}

size_t
KeySetOut::append (const KeyData& kd)
{
    int i = find_common_ancestor_with_previous(kd);

    KSO_APPEND_DEBUG("Append " << kd);
    /* if we have a fully matched key OR common ancestor is stronger, return */
    if (i > 0)
    {
        int const kd_leaf_prefix(KeySet::KeyPart::prefix(kd.type, ws_ver_));
        bool const common_ancestor_is_kd_leaf = (kd.parts_num == i);
        int const branch_prefix
            (KeySet::KeyPart::prefix(KeyData::BRANCH_KEY_TYPE, ws_ver_));
        int const exclusive_prefix
            (KeySet::KeyPart::prefix(WSREP_KEY_EXCLUSIVE, ws_ver_));
        int const common_ancestor_prefix = prev_[i].prefix();
        bool const common_ancestor_is_prev_leaf = (prev_.size() == (i + 1U));

        KSO_APPEND_DEBUG("Found common ancestor " << prev_[i] << " at position " << i);

        /* The common ancestor is already the strongest possible key. */
        if (common_ancestor_prefix == exclusive_prefix)
        {
            KSO_APPEND_DEBUG("Common ancestor is exclusive");
            return 0;
        }

        /* Common ancestor is leaf and is strong enough to cover both kd
         * leaf and branch. */
        if (common_ancestor_is_prev_leaf
            && common_ancestor_prefix > kd_leaf_prefix
            && common_ancestor_prefix > branch_prefix)
        {
            KSO_APPEND_DEBUG("Common ancestor is previous leaf and stronger");
            return 0;
        }

        if (common_ancestor_is_kd_leaf)
        {
            KSO_APPEND_DEBUG("Common ancestor is kd leaf");
            if (kd_leaf_prefix <= common_ancestor_prefix)
            {
                KSO_APPEND_DEBUG("Common ancestor covers kd leaf");
                return 0;
            }

            assert(common_ancestor_prefix <= kd_leaf_prefix);
            /* need to add a stronger copy of the leaf */
            --i;
        }
    }

    int const anc(i);
    KSO_APPEND_DEBUG("Append key parts after ancestor " << i);
    const KeyPart* parent(&prev_[anc]);

    /* create parts that didn't match previous key and add to the set
     * of previously added keys. */
    size_t const old_size (size());
    int j(0);
    for (; i < kd.parts_num; ++i, ++j)
    {
        try
        {
            KeyPart kp(added_, *this, parent, kd, i, ws_ver_, alignment());
            if (size_t(j) < new_.size())
            {
                new_[j] = kp;
            }
            else
            {
                new_().push_back (kp);
            }
            parent = &new_[j];
        }
        catch (KeyPart::DUPLICATE& e)
        {
            assert (i + 1 == kd.parts_num);
            /* There is a very small probability that child part throws DUPLICATE
             * even after parent was added as a new key. It does not matter:
             * a duplicate will be a duplicate in certification as well. */
            goto out;
        }
    }

    assert (i == kd.parts_num);
    assert (anc + j == kd.parts_num);

    /* copy new parts to prev_ */
    prev_().resize(1 + kd.parts_num);
    std::copy(new_().begin(), new_().begin() + j, prev_().begin() + anc + 1);

    /* acquire key part value if it is volatile */
    if (kd.copy)
        for (int k(anc + 1); size_t(k) < prev_.size(); ++k)
        {
            prev_[k].acquire();
        }

out:
    return size() - old_size;
}

#undef KSO_APPEND_DEBUG

} /* namespace galera */
