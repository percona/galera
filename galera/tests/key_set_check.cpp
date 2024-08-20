/* copyright (C) 2013-2024 Codership Oy <info@codership.com>
 *
 * $Id$
 */

#undef NDEBUG

#include "test_key.hpp"
#include "../src/key_set.hpp"
#include "../src/write_set_ng.hpp"

#include "gu_logger.hpp"
#include "gu_hexdump.hpp"

#include <check.h>

using namespace galera;

class TestBaseName : public gu::Allocator::BaseName
{
    std::string str_;

public:

    TestBaseName(const char* name) : str_(name) {}
    void print(std::ostream& os) const { os << str_; }
};

static size_t version_to_hash_size (KeySet::Version const ver)
{
    switch (ver)
    {
    case KeySet::FLAT16:  ck_abort_msg("FLAT16 is not supported by test");
    case KeySet::FLAT16A: return 16;
    case KeySet::FLAT8:   ck_abort_msg( "FLAT8 is not supported by test");
    case KeySet::FLAT8A:  return 8;
    default:              ck_abort_msg("Unsupported KeySet verison: %d", ver);
    }

    abort();
}

static void test_ver(gu::RecordSet::Version const rsv, int const ws_ver)
{
    int const alignment
        (rsv >= gu::RecordSet::VER2 ? gu::RecordSet::VER2_ALIGNMENT : 1);
    KeySet::Version const tk_ver(KeySet::FLAT16A);
    size_t const base_size(version_to_hash_size(tk_ver));

    union { gu::byte_t buf[1024]; gu_word_t align; } reserved;
    assert((uintptr_t(reserved.buf) % GU_WORD_BYTES) == 0);
    TestBaseName const str("key_set_test");
    KeySetOut kso (reserved.buf, sizeof(reserved.buf), str, tk_ver, rsv, ws_ver);

    ck_assert(kso.count() == 0);
    size_t total_size(kso.size());
    log_info << "Start size: " << total_size;

    TestKey tk0(tk_ver, WSREP_KEY_SHARED, false, "a0");
    kso.append(tk0());
    ck_assert(kso.count() == 1);

    total_size += base_size + 2 + 1*4;
    total_size = GU_ALIGN(total_size, alignment);
    ck_assert_msg(total_size == kso.size(), "Size: %zu, expected: %zu",
                  kso.size(), total_size);

    kso.append(tk0());
    ck_assert(kso.count() == 1);

    ck_assert_msg(total_size == kso.size(), "Size: %zu, expected: %zu",
                  kso.size(), total_size);

    TestKey tk1(tk_ver, WSREP_KEY_SHARED, true, "a0", "a1", "a2");
    mark_point();
    kso.append(tk1());
    int expected_count(3);
    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());

    total_size += base_size + 2 + 2*4;
    total_size = GU_ALIGN(total_size, alignment);
    total_size += base_size + 2 + 3*4;
    total_size = GU_ALIGN(total_size, alignment);
    ck_assert_msg(total_size == kso.size(), "Size: %zu, expected: %zu",
                  kso.size(), total_size);

    TestKey tk2(tk_ver, WSREP_KEY_EXCLUSIVE, false, "a0", "a1", "b2");
    kso.append(tk2());
    expected_count += (ws_ver > 3);
    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());

    if (expected_count == 4)
    {
        total_size += base_size + 2 + 3*4;
        total_size = GU_ALIGN(total_size, alignment);
    }
    ck_assert_msg(total_size == kso.size(), "Size: %zu, expected: %zu",
                  kso.size(), total_size);

    /* this should update a sronger version of "a2" */
    TestKey tk2_(tk_ver, WSREP_KEY_UPDATE, false, "a0", "a1", "a2");
    kso.append(tk2_());
    expected_count += 1;
    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());

    total_size += base_size + 2 + 3*4;
    total_size = GU_ALIGN(total_size, alignment);
    ck_assert_msg(total_size == kso.size(), "Size: %zu, expected: %zu",
                  kso.size(), total_size);

    /* it is a duplicate, but it should add an exclusive verision of the key */
    TestKey tk3(tk_ver, WSREP_KEY_EXCLUSIVE, true, "a0", "a1");
    log_info << "######## Appending exclusive duplicate tk3: begin";
    kso.append(tk3());
    expected_count += (ws_ver <= 3 ? 0 : 1);
    log_info << "######## Appending exclusive duplicate tk3: end";
    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());

    if (ws_ver > 3)
    {
        total_size += base_size + 2 + 2*4;
        total_size = GU_ALIGN(total_size, alignment);
    }
    ck_assert_msg(total_size == kso.size(), "Size: %zu, expected: %zu",
                  kso.size(), total_size);

    /* tk3 should make it impossible to add anything past a0:a1 */
    TestKey tk4(tk_ver, WSREP_KEY_EXCLUSIVE, false, "a0", "a1", "c2");
    log_info << "######## Appending exclusive duplicate tk4: begin";
    kso.append(tk4());
    log_info << "######## Appending exclusive duplicate tk4: end";
    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());

    ck_assert_msg(total_size == kso.size(), "Size: %zu, expected: %zu",
                  kso.size(), total_size);

    /* adding shared key should have no effect */
    TestKey tk5(tk_ver, WSREP_KEY_SHARED, true, "a0", "a1");
    kso.append(tk5());
    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());

    ck_assert_msg(total_size == kso.size(), "Size: %zu, expected: %zu",
                  kso.size(), total_size);

    /* adding REFERENCE key should have no effect */
    TestKey tk5_1(tk_ver, WSREP_KEY_REFERENCE, true, "a0", "a1");
    kso.append(tk5_1());
    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());

    ck_assert_msg(total_size == kso.size(), "Size: %zu, expected: %zu",
                  kso.size(), total_size);

    /* adding UPDATE key should have no effect */
    TestKey tk5_2(tk_ver, WSREP_KEY_UPDATE, true, "a0", "a1");
    kso.append(tk5_2());
    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());

    ck_assert_msg(total_size == kso.size(), "Size: %zu, expected: %zu",
                  kso.size(), total_size);

    /* tk5 should not make any changes */
    TestKey tk6(tk_ver, WSREP_KEY_EXCLUSIVE, false, "a0", "a1", "c2");
    kso.append(tk6());
    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());

    ck_assert_msg(total_size == kso.size(), "Size: %zu, expected: %zu",
                  kso.size(), total_size);

    /* a0:b1:... should still be possible, should add 2 keys: b1 and c2 */
    TestKey tk7(tk_ver, WSREP_KEY_REFERENCE, true, "a0", "b1", "c2");
    kso.append(tk7());
    expected_count += 2;
    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());

    total_size += base_size + 2 + 2*4;
    total_size = GU_ALIGN(total_size, alignment);
    total_size += base_size + 2 + 3*4;
    total_size = GU_ALIGN(total_size, alignment);
    ck_assert_msg(total_size == kso.size(), "Size: %zu, expected: %zu",
                  kso.size(), total_size);

    /* make sure a0:b1:b2 is possible despite we have a0:a1:b2 already
     * (should be no collision on b2) */
    TestKey tk8(tk_ver, WSREP_KEY_REFERENCE, false, "a0", "b1", "b2");
    kso.append(tk8());
    expected_count += (ws_ver > 3);
    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());

    if (ws_ver > 3)
    {
        total_size += base_size + 2 + 3*4;
        total_size = GU_ALIGN(total_size, alignment);
    }
    ck_assert_msg(total_size == kso.size(), "Size: %zu, expected: %zu",
                  kso.size(), total_size);

    TestKey tk8_1(tk_ver, WSREP_KEY_UPDATE, false, "a0", "b1", "b2");
    kso.append(tk8_1());
    if (3 == ws_ver || 4 == ws_ver)
    {
        /* versions 3, 4 do not distinguish REEFERENCE and UPDATE,
           the key should be ignored */
    }
    else if (5 <= ws_ver)
    {
        /* in version 5 UPDATE is a stronger key than REFERENCE - should be
         * added to the set */

        expected_count++;
        total_size += base_size + 2 + 3*4;
        total_size = GU_ALIGN(total_size, alignment);
    }
    else abort();

    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());
    ck_assert_msg(total_size == kso.size(), "Size: %zu, expected: %zu",
                  kso.size(), total_size);

    TestKey tk8_2(tk_ver, WSREP_KEY_EXCLUSIVE, false, "a0", "b1", "b2");
    kso.append(tk8_2());
    if (3 == ws_ver)
    {
        /* version 3 does not distinguish REFERENCE, UPDATE and EXCLUSIVE,
           the key should be ignored */
    }
    else if (4 <= ws_ver)
    {
        /* in version 4 EXCLUSIVE is a stronger key than REFERENCE and
         * in version 5 EXCLUSIVE is a stronger key than UPDATE - should be
         * added to the set */

        expected_count++;
        total_size += base_size + 2 + 3*4;
        total_size = GU_ALIGN(total_size, alignment);
    }
    else abort();

    ck_assert_msg(kso.count() == expected_count,"key count: expected %d, got %d",
                  expected_count, kso.count());
    ck_assert_msg(total_size == kso.size(), "Size: %zu, expected: %zu",
                  kso.size(), total_size);

    TestKey tk8_3(tk_ver, WSREP_KEY_UPDATE, false, "a0", "b1", "b2");
    kso.append(tk8_3());
    /* UPDATE key is weaker than EXCLUSIVE, should be ignored */

    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());
    ck_assert_msg(total_size == kso.size(), "Size: %zu, expected: %zu",
                  kso.size(), total_size);

    log_info << "size before huge key: " << total_size;

    char huge_key[2048];
    memset (huge_key, 'x', sizeof(huge_key));
    huge_key[ sizeof(huge_key) - 1 ] = 0;
    TestKey tk9(tk_ver, WSREP_KEY_EXCLUSIVE, false, huge_key, huge_key,huge_key);
    kso.append(tk9());
    expected_count += 3;
    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());

    total_size += base_size + 2 + 1*256;
    total_size = GU_ALIGN(total_size, alignment);
    total_size += base_size + 2 + 2*256;
    total_size = GU_ALIGN(total_size, alignment);
    total_size += base_size + 2 + 3*256;
    total_size = GU_ALIGN(total_size, alignment);
    ck_assert_msg(total_size == kso.size(), "Size: %zu, expected: %zu",
                  kso.size(), total_size);

    log_info << "End size: " << kso.size();

    // Verify that SHARED keys are added as a first leaf bunt not over REFERENCE
    TestKey tk10_ref1(tk_ver, WSREP_KEY_REFERENCE, true, "s0");
    kso.append(tk10_ref1());
    expected_count += 1;
    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());
    // Should add SHARED even though s1 weaker than s0 (for ver > 3)
    TestKey tk10_sh(tk_ver, WSREP_KEY_SHARED, true, "s0", "s1");
    kso.append(tk10_sh());
    expected_count += (ws_ver > 3); // at ver<=3 REF is considered EXC
    assert(kso.count() == expected_count);
    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());
    TestKey tk10_ref2(tk_ver, WSREP_KEY_REFERENCE, true, "s0", "s1");
    kso.append(tk10_ref2());
    expected_count += (ws_ver > 3);
    assert(kso.count() == expected_count);
    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());
    // Try same SHARED once again, should not add anything
    kso.append(tk10_sh());
    ck_assert_msg(kso.count() == expected_count, "key count: expected %d, got %d",
                  expected_count, kso.count());


    KeySetOut::GatherVector out;
    out->reserve(kso.page_count());
    size_t const out_size(kso.gather(out));

    log_info << "Gather size: " << out_size << ", buf count: " << out->size();
    ck_assert_msg(0 == out_size % alignment, "out size not aligned by %zd",
                  out_size % alignment);

    std::vector<gu::byte_t> in;
    in.reserve(out_size);
    for (size_t i(0); i < out->size(); ++i)
    {
        const gu::byte_t* ptr(reinterpret_cast<const gu::byte_t*>(out[i].ptr));
        in.insert (in.end(), ptr, ptr + out[i].size);
    }

    ck_assert(in.size() == out_size);

    KeySetIn ksi (kso.version(), in.data(), in.size());

    ck_assert_msg(ksi.count() == kso.count(),
                  "Received keys: %d, expected: %d", ksi.count(), kso.count());
    ck_assert_msg(ksi.size() == kso.size(),
                  "Received size: %zu, expected: %zu", ksi.size(), kso.size());

    try
    {
        ksi.checksum();
    }
    catch (std::exception& e)
    {
        ck_abort_msg("%s", e.what());
    }

    int branch(0); // to stiffle clang complaints about unused variables

    int const P_BRANCH(KeySet::KeyPart::prefix(KeyData::BRANCH_KEY_TYPE,ws_ver));

    for (int i(0); i < ksi.count(); ++i)
    {
        KeySet::KeyPart kp(ksi.next());
        branch += (kp.prefix() == P_BRANCH);
    }

    KeySetIn ksi_empty;

    ck_assert_msg(ksi_empty.count() == 0,
                  "Received keys: %d, expected: %d", ksi_empty.count(), 0);
    ck_assert_msg(ksi_empty.size() == 0,
                  "Received size: %zu, expected: %d", ksi_empty.size(), 0);

    ksi_empty.init (kso.version(), in.data(), in.size());

    ck_assert_msg(ksi_empty.count() == kso.count(),
                  "Received keys: %d, expected: %d",
                  ksi_empty.count(),kso.count());
    ck_assert_msg(ksi_empty.size() == kso.size(),
                  "Received size: %zu, expected: %zu",
                  ksi_empty.size(), kso.size());

    try
    {
        ksi_empty.checksum();
    }
    catch (std::exception& e)
    {
        ck_abort_msg("%s", e.what());
    }

    for (int i(0); i < ksi_empty.count(); ++i)
    {
        KeySet::KeyPart kp(ksi_empty.next());
        branch += (kp.prefix() == P_BRANCH);
    }

    ksi_empty.rewind();

    for (int i(0); i < ksi_empty.count(); ++i)
    {
        KeySet::KeyPart kp(ksi_empty.next());
        branch += (kp.prefix() == P_BRANCH);
    }

    ck_assert(0 != branch);
}

#ifndef GALERA_ONLY_ALIGNED
START_TEST (ver1_3)
{
    test_ver(gu::RecordSet::VER1, 3);
}
END_TEST
#endif /* GALERA_ONLY_ALIGNED */

START_TEST (ver2_3)
{
    test_ver(gu::RecordSet::VER2, 3);
}
END_TEST

START_TEST (ver2_4)
{
    test_ver(gu::RecordSet::VER2, 4);
}
END_TEST

START_TEST (ver2_5)
{
    test_ver(gu::RecordSet::VER2, 5);
}
END_TEST

struct KsoFixture
{
    union Res
    {
        gu::byte_t buf[1024];
        gu_word_t align;
    };
    Res res{};
    TestBaseName basename{ "ksof" };
    galera::KeySetOut kso{ res.buf,
                           sizeof(res.buf),
                           basename,
                           galera::KeySet::FLAT8A,
                           gu::RecordSet::VER2,
                           galera::WriteSetNG::MAX_VERSION };
    void append(const std::vector<const char*> key, wsrep_key_type_t type)
    {

        TestKey k{ galera::KeySet::FLAT8A, type, key };
        kso.append(k());
    }
};

/*
 * Shared leaf
 */

START_TEST(kso_append_shared_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_SHARED);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_shared_over_shared_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_SHARED);
    f.append({ "b", "l" }, WSREP_KEY_SHARED);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_reference_over_shared_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_SHARED);
    f.append({ "b", "l" }, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST

START_TEST(kso_append_update_over_shared_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_SHARED);
    f.append({ "b", "l" }, WSREP_KEY_UPDATE);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST

START_TEST(kso_append_exclusive_over_shared_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_SHARED);
    f.append({ "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST

START_TEST(kso_append_shared_branch_over_shared_leaf)
{
    KsoFixture f;
    f.append({"b", "b"}, WSREP_KEY_SHARED);
    f.append({"b", "b", "l"}, WSREP_KEY_SHARED);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST

START_TEST(kso_append_reference_branch_over_shared_leaf)
{
    KsoFixture f;
    f.append({"b", "b"}, WSREP_KEY_SHARED);
    f.append({"b", "b", "l"}, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST

START_TEST(kso_append_update_branch_over_shared_leaf)
{
    KsoFixture f;
    f.append({"b", "b"}, WSREP_KEY_SHARED);
    f.append({"b", "b", "l"}, WSREP_KEY_UPDATE);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST

START_TEST(kso_append_exclusive_branch_over_shared_leaf)
{
    KsoFixture f;
    f.append({"b", "b"}, WSREP_KEY_SHARED);
    f.append({"b", "b", "l"}, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST

START_TEST(kso_append_shared_leaf_over_branch)
{
    KsoFixture f;
    f.append({"b", "l"}, WSREP_KEY_SHARED);
    f.append({"b"}, WSREP_KEY_SHARED);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

/*
 * Reference leaf
 */

START_TEST(kso_append_reference_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_shared_over_reference_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_REFERENCE);
    f.append({ "b", "l" }, WSREP_KEY_SHARED);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_reference_over_reference_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_REFERENCE);
    f.append({ "b", "l" }, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_update_over_reference_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_REFERENCE);
    f.append({ "b", "l" }, WSREP_KEY_UPDATE);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST

START_TEST(kso_append_exclusive_over_reference_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_REFERENCE);
    f.append({ "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST

START_TEST(kso_append_shared_branch_over_reference_leaf)
{
    KsoFixture f;
    f.append({"b", "b"}, WSREP_KEY_REFERENCE);
    f.append({"b", "b", "l"}, WSREP_KEY_SHARED);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST

START_TEST(kso_append_reference_branch_over_reference_leaf)
{
    KsoFixture f;
    f.append({"b", "b"}, WSREP_KEY_REFERENCE);
    f.append({"b", "b", "l"}, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST

START_TEST(kso_append_update_branch_over_reference_leaf)
{
    KsoFixture f;
    f.append({"b", "b"}, WSREP_KEY_REFERENCE);
    f.append({"b", "b", "l"}, WSREP_KEY_UPDATE);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST

START_TEST(kso_append_exclusive_branch_over_reference_leaf)
{
    KsoFixture f;
    f.append({"b", "b"}, WSREP_KEY_REFERENCE);
    f.append({"b", "b", "l"}, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST

START_TEST(kso_append_reference_leaf_over_branch)
{
    KsoFixture f;
    f.append({"b", "l"}, WSREP_KEY_SHARED);
    f.append({"b"}, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

/*
 * Update leaf
 */

START_TEST(kso_append_update_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_UPDATE);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_shared_over_update_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_UPDATE);
    f.append({ "b", "l" }, WSREP_KEY_SHARED);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_reference_over_update_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_UPDATE);
    f.append({ "b", "l" }, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_update_over_update_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_UPDATE);
    f.append({ "b", "l" }, WSREP_KEY_UPDATE);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_exclusive_over_update_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_UPDATE);
    f.append({ "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST

START_TEST(kso_append_shared_branch_over_update_leaf)
{
    KsoFixture f;
    f.append({"b", "b"}, WSREP_KEY_UPDATE);
    f.append({"b", "b", "l"}, WSREP_KEY_SHARED);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_reference_branch_over_update_leaf)
{
    KsoFixture f;
    f.append({"b", "b"}, WSREP_KEY_UPDATE);
    f.append({"b", "b", "l"}, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_update_branch_over_update_leaf)
{
    KsoFixture f;
    f.append({"b", "b"}, WSREP_KEY_UPDATE);
    f.append({"b", "b", "l"}, WSREP_KEY_UPDATE);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST

START_TEST(kso_append_exclusive_branch_over_update_leaf)
{
    KsoFixture f;
    f.append({"b", "b"}, WSREP_KEY_UPDATE);
    f.append({"b", "b", "l"}, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST

START_TEST(kso_append_update_leaf_over_branch)
{
    KsoFixture f;
    f.append({"b", "l"}, WSREP_KEY_SHARED);
    f.append({"b"}, WSREP_KEY_UPDATE);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST


/*
 * Exclusive leaf
 */

START_TEST(kso_append_exclusive_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_shared_over_exclusive_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_EXCLUSIVE);
    f.append({ "b", "l" }, WSREP_KEY_SHARED);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_reference_over_exclusive_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_EXCLUSIVE);
    f.append({ "b", "l" }, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_update_over_exclusive_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_EXCLUSIVE);
    f.append({ "b", "l" }, WSREP_KEY_UPDATE);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_exclusive_over_exclusive_leaf)
{
    KsoFixture f;
    f.append({ "b", "l" }, WSREP_KEY_EXCLUSIVE);
    f.append({ "b", "l" }, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_shared_branch_over_exclusive_leaf)
{
    KsoFixture f;
    f.append({"b", "b"}, WSREP_KEY_EXCLUSIVE);
    f.append({"b", "b", "l"}, WSREP_KEY_SHARED);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_reference_branch_over_exclusive_leaf)
{
    KsoFixture f;
    f.append({"b", "b"}, WSREP_KEY_EXCLUSIVE);
    f.append({"b", "b", "l"}, WSREP_KEY_REFERENCE);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_update_branch_over_exclusive_leaf)
{
    KsoFixture f;
    f.append({"b", "b"}, WSREP_KEY_EXCLUSIVE);
    f.append({"b", "b", "l"}, WSREP_KEY_UPDATE);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_exclusive_branch_over_exclusive_leaf)
{
    KsoFixture f;
    f.append({"b", "b"}, WSREP_KEY_EXCLUSIVE);
    f.append({"b", "b", "l"}, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(f.kso.count(), 2);
}
END_TEST

START_TEST(kso_append_exclusive_leaf_over_branch)
{
    KsoFixture f;
    f.append({"b", "l"}, WSREP_KEY_SHARED);
    f.append({"b"}, WSREP_KEY_EXCLUSIVE);
    ck_assert_int_eq(f.kso.count(), 3);
}
END_TEST

Suite* key_set_suite ()
{
    TCase* t = tcase_create ("KeySet");
#ifndef GALERA_ONLY_ALIGNED
    tcase_add_test (t, ver1_3);
#endif
    tcase_add_test (t, ver2_3);
    tcase_add_test (t, ver2_4);
    tcase_add_test (t, ver2_5);
    tcase_set_timeout(t, 60);


    tcase_add_test(t, kso_append_shared_leaf);
    tcase_add_test(t, kso_append_shared_over_shared_leaf);
    tcase_add_test(t, kso_append_reference_over_shared_leaf);
    tcase_add_test(t, kso_append_update_over_shared_leaf);
    tcase_add_test(t, kso_append_exclusive_over_shared_leaf);
    tcase_add_test(t, kso_append_shared_branch_over_shared_leaf);
    tcase_add_test(t, kso_append_reference_branch_over_shared_leaf);
    tcase_add_test(t, kso_append_update_branch_over_shared_leaf);
    tcase_add_test(t, kso_append_exclusive_branch_over_shared_leaf);
    tcase_add_test(t, kso_append_shared_leaf_over_branch);

    tcase_add_test(t, kso_append_reference_leaf);
    tcase_add_test(t, kso_append_shared_over_reference_leaf);
    tcase_add_test(t, kso_append_reference_over_reference_leaf);
    tcase_add_test(t, kso_append_update_over_reference_leaf);
    tcase_add_test(t, kso_append_exclusive_over_reference_leaf);
    tcase_add_test(t, kso_append_shared_branch_over_reference_leaf);
    tcase_add_test(t, kso_append_reference_branch_over_reference_leaf);
    tcase_add_test(t, kso_append_update_branch_over_reference_leaf);
    tcase_add_test(t, kso_append_exclusive_branch_over_reference_leaf);
    tcase_add_test(t, kso_append_reference_leaf_over_branch);

    tcase_add_test(t, kso_append_update_leaf);
    tcase_add_test(t, kso_append_shared_over_update_leaf);
    tcase_add_test(t, kso_append_reference_over_update_leaf);
    tcase_add_test(t, kso_append_update_over_update_leaf);
    tcase_add_test(t, kso_append_exclusive_over_update_leaf);
    tcase_add_test(t, kso_append_shared_branch_over_update_leaf);
    tcase_add_test(t, kso_append_reference_branch_over_update_leaf);
    tcase_add_test(t, kso_append_update_branch_over_update_leaf);
    tcase_add_test(t, kso_append_exclusive_branch_over_update_leaf);
    tcase_add_test(t, kso_append_update_leaf_over_branch);

    tcase_add_test(t, kso_append_exclusive_leaf);
    tcase_add_test(t, kso_append_shared_over_exclusive_leaf);
    tcase_add_test(t, kso_append_reference_over_exclusive_leaf);
    tcase_add_test(t, kso_append_update_over_exclusive_leaf);
    tcase_add_test(t, kso_append_exclusive_over_exclusive_leaf);
    tcase_add_test(t, kso_append_shared_branch_over_exclusive_leaf);
    tcase_add_test(t, kso_append_reference_branch_over_exclusive_leaf);
    tcase_add_test(t, kso_append_update_branch_over_exclusive_leaf);
    tcase_add_test(t, kso_append_exclusive_branch_over_exclusive_leaf);
    tcase_add_test(t, kso_append_exclusive_leaf_over_branch);

    Suite* s = suite_create ("KeySet");
    suite_add_tcase (s, t);

    return s;
}
