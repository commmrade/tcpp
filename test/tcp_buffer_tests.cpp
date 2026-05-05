#include <gtest/gtest.h>
#include "../src/tcpp/net/buffer.hpp"

// ─── helpers ─────────────────────────────────────────────────────────────────

static std::vector<std::byte> make_payload(std::size_t n, std::byte val = std::byte{0xAB})
{
    return std::vector<std::byte>(n, val);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TcpSegment
// ═══════════════════════════════════════════════════════════════════════════════

TEST(TcpSegment, PlainPayload)
{
    auto p = make_payload(100);
    TcpSegment s{1000, p};
    EXPECT_EQ(s.seq_start(),    1000u);
    EXPECT_EQ(s.seq_end(),      1100u);
    EXPECT_EQ(s.size_in_seq(),  100u);
    EXPECT_EQ(s.payload_size(), 100u);
    EXPECT_FALSE(s.syn());
    EXPECT_FALSE(s.fin());
}

TEST(TcpSegment, SynNoPayload)
{
    std::vector<std::byte> empty;
    TcpSegment s{1000, empty, true, false};
    EXPECT_EQ(s.seq_start(),    1000u);
    EXPECT_EQ(s.seq_end(),      1001u);
    EXPECT_EQ(s.size_in_seq(),  1u);
    EXPECT_EQ(s.payload_size(), 0u);
    EXPECT_TRUE(s.syn());
    EXPECT_FALSE(s.fin());
}

TEST(TcpSegment, FinNoPayload)
{
    std::vector<std::byte> empty;
    TcpSegment s{2000, empty, false, true};
    EXPECT_EQ(s.seq_start(),   2000u);
    EXPECT_EQ(s.seq_end(),     2001u);
    EXPECT_EQ(s.size_in_seq(), 1u);
    EXPECT_TRUE(s.fin());
    EXPECT_FALSE(s.syn());
}

TEST(TcpSegment, SynWithPayload)
{
    auto p = make_payload(99);
    TcpSegment s{1000, p, true, false};
    EXPECT_EQ(s.size_in_seq(), 100u);
    EXPECT_EQ(s.seq_end(),     1100u);
}

TEST(TcpSegment, FinWithPayload)
{
    auto p = make_payload(50);
    TcpSegment s{500, p, false, true};
    EXPECT_EQ(s.size_in_seq(), 51u);
    EXPECT_EQ(s.seq_end(),     551u);
}

TEST(TcpSegment, SynFin)
{
    std::vector<std::byte> empty;
    TcpSegment s{0, empty, true, true};
    EXPECT_EQ(s.size_in_seq(), 2u);
    EXPECT_EQ(s.seq_end(),     2u);
}

TEST(TcpSegment, ZeroPayload)
{
    std::vector<std::byte> empty;
    TcpSegment s{500, empty};
    EXPECT_EQ(s.size_in_seq(),  0u);
    EXPECT_EQ(s.payload_size(), 0u);
    EXPECT_EQ(s.seq_start(),    500u);
    EXPECT_EQ(s.seq_end(),      500u);
}

TEST(TcpSegment, PayloadContents)
{
    auto p = make_payload(4, std::byte{0x42});
    TcpSegment s{0, p};
    auto view = s.payload();
    ASSERT_EQ(view.size(), 4u);
    for (auto b : view)
        EXPECT_EQ(b, std::byte{0x42});
}

class TcpSegmentTest : public ::testing::Test
{
protected:
    TcpSegment seg{1000, make_payload(100)};
    void set_fin(bool val)
    {
        seg.set_fin(val);
    }
};

TEST_F(TcpSegmentTest, EnableDisableFin)
{
    ASSERT_EQ(seg.seq_end(), 1100);
    set_fin(true);
    ASSERT_EQ(seg.seq_end(), 1101);
    set_fin(true);
    ASSERT_EQ(seg.seq_end(), 1101);
    set_fin(false);
    ASSERT_EQ(seg.seq_end(), 1100);
    set_fin(false);
    ASSERT_EQ(seg.seq_end(), 1100);
}
// ═══════════════════════════════════════════════════════════════════════════════
// TcpBuffer fixture
// ═══════════════════════════════════════════════════════════════════════════════

class TcpBufferTest : public ::testing::Test
{
protected:
    TcpBuffer buf;

    const std::list<TcpSegment>& inner() const
    {
        return buf.segs_;
    }
};

// ─── insert ──────────────────────────────────────────────────────────────────

TEST_F(TcpBufferTest, StartsEmpty)
{
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size_segs(), 0u);
}

TEST_F(TcpBufferTest, InsertSingle)
{
    buf.insert(TcpSegment{1000, make_payload(100)});
    EXPECT_EQ(buf.size_segs(), 1u);
    EXPECT_FALSE(buf.empty());
}

TEST_F(TcpBufferTest, InsertInOrder)
{
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1100, p});
    buf.insert(TcpSegment{1200, p});

    ASSERT_EQ(buf.size_segs(), 3u);
    auto it = inner().cbegin();
    EXPECT_EQ(it->seq_start(), 1000u); ++it;
    EXPECT_EQ(it->seq_start(), 1100u); ++it;
    EXPECT_EQ(it->seq_start(), 1200u);
}

TEST_F(TcpBufferTest, InsertReverseOrder)
{
    auto p = make_payload(100);
    buf.insert(TcpSegment{1200, p});
    buf.insert(TcpSegment{1100, p});
    buf.insert(TcpSegment{1000, p});

    ASSERT_EQ(buf.size_segs(), 3u);
    auto it = inner().cbegin();
    EXPECT_EQ(it->seq_start(), 1000u); ++it;
    EXPECT_EQ(it->seq_start(), 1100u); ++it;
    EXPECT_EQ(it->seq_start(), 1200u);
}

TEST_F(TcpBufferTest, InsertMiddle)
{
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1200, p});
    buf.insert(TcpSegment{1100, p});

    ASSERT_EQ(buf.size_segs(), 3u);
    auto it = inner().cbegin();
    EXPECT_EQ(it->seq_start(), 1000u); ++it;
    EXPECT_EQ(it->seq_start(), 1100u); ++it;
    EXPECT_EQ(it->seq_start(), 1200u);
}

TEST_F(TcpBufferTest, InsertWithGap)
{
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1300, p});

    ASSERT_EQ(buf.size_segs(), 2u);
    auto it = inner().cbegin();
    EXPECT_EQ(it->seq_start(), 1000u); ++it;
    EXPECT_EQ(it->seq_start(), 1300u);
}

TEST_F(TcpBufferTest, InsertDuplicate)
{
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1000, p});
    EXPECT_EQ(buf.size_segs(), 1u);
}

TEST_F(TcpBufferTest, InsertManyRandomOrder)
{
    auto p = make_payload(50);
    for (int i = 9; i >= 0; --i)
        buf.insert(TcpSegment{static_cast<std::uint32_t>(1000 + i * 50), p});

    ASSERT_EQ(buf.size_segs(), 10u);
    std::uint32_t prev_seq = 0;
    for (const auto& s : inner()) {
        EXPECT_GT(s.seq_start(), prev_seq);
        prev_seq = s.seq_start();
    }
}

// ─── front ───────────────────────────────────────────────────────────────────

TEST_F(TcpBufferTest, FrontReturnFirstSegment)
{
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1100, p});
    EXPECT_EQ(buf.front().seq_start(), 1000u);
}

TEST_F(TcpBufferTest, FrontOnEmpty)
{
    EXPECT_DEATH(buf.front(), "");
}

// ─── consume ─────────────────────────────────────────────────────────────────

TEST_F(TcpBufferTest, ConsumeExactSeqEnd)
{
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1100, p});

    buf.consume_seq(1100u);
    ASSERT_EQ(buf.size_segs(), 1u);
    EXPECT_EQ(buf.front().seq_start(), 1100u);
}

TEST_F(TcpBufferTest, ConsumeAll)
{
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1100, p});
    buf.insert(TcpSegment{1200, p});

    buf.consume_seq(1300u);
    EXPECT_TRUE(buf.empty());
}

TEST_F(TcpBufferTest, ConsumeSYNSegment)
{
    buf.insert(TcpSegment{1000, {}, true, false});
    ASSERT_EQ(buf.size_segs(), 1);
    buf.consume_seq(1001);
    EXPECT_TRUE(buf.empty());
}

TEST_F(TcpBufferTest, ConsumeNone)
{
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});

    buf.consume_seq(1000u);
    ASSERT_EQ(buf.size_segs(), 1u);
}

TEST_F(TcpBufferTest, ConsumeMiddleOfSegment)
{
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});

    buf.consume_seq(1050u);
    EXPECT_EQ(buf.size_segs(), 1);
    EXPECT_EQ(inner().cbegin()->seq_start(), 1050);
}

TEST_F(TcpBufferTest, ConsumeEmptyBuffer)
{
    EXPECT_NO_THROW(buf.consume_seq(9999u));
    EXPECT_TRUE(buf.empty());
}

TEST_F(TcpBufferTest, ConsumePartial)
{
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1100, p});
    buf.insert(TcpSegment{1200, p});

    buf.consume_seq(1200u);
    ASSERT_EQ(buf.size_segs(), 1u);
    EXPECT_EQ(buf.front().seq_start(), 1200u);
}

// ─── read ────────────────────────────────────────────────────────────────────

// Helper to make byte spans
static std::vector<std::byte> make_bytes(std::initializer_list<uint8_t> vals) {
    std::vector<std::byte> v;
    for (auto b : vals) v.push_back(static_cast<std::byte>(b));
    return v;
}
static std::vector<std::byte> make_bytes_n(uint8_t val, std::size_t n) {
    return std::vector<std::byte>(n, static_cast<std::byte>(val));
}

// ─── check_gaps ───────────────────────────────────────────────────────────────

class TcpReceiverBufferCheckGapsTest : public testing::Test {};

TEST_F(TcpReceiverBufferCheckGapsTest, SingleInOrderSegment) {
    TcpReceiverBuffer buf;
    auto data = make_bytes({1, 2, 3});
    TcpSegment seg(100, data);
    buf.insert(seg);
    // recv_nxt == seg.seq_start → should advance to 103
    EXPECT_EQ(buf.check_gaps(100), 103u);
}

TEST_F(TcpReceiverBufferCheckGapsTest, SingleOutOfOrderSegment) {
    TcpReceiverBuffer buf;
    auto data = make_bytes({1, 2, 3});
    TcpSegment seg(200, data);
    buf.insert(seg);
    // recv_nxt=100, segment starts at 200 → gap, return recv_nxt unchanged
    EXPECT_EQ(buf.check_gaps(100), 100u);
}

TEST_F(TcpReceiverBufferCheckGapsTest, TwoContiguousSegments) {
    TcpReceiverBuffer buf;
    auto d1 = make_bytes({1, 2, 3});
    auto d2 = make_bytes({4, 5});
    buf.insert(TcpSegment(0, d1));
    buf.insert(TcpSegment(3, d2));
    EXPECT_EQ(buf.check_gaps(0), 5u);
}

TEST_F(TcpReceiverBufferCheckGapsTest, GapBetweenTwoSegments) {
    TcpReceiverBuffer buf;
    auto d1 = make_bytes({1, 2, 3});
    auto d2 = make_bytes({4, 5});
    buf.insert(TcpSegment(0, d1));
    buf.insert(TcpSegment(10, d2)); // gap at 3..9
    EXPECT_EQ(buf.check_gaps(0), 3u);
}

TEST_F(TcpReceiverBufferCheckGapsTest, ThreeContiguousSegments) {
    TcpReceiverBuffer buf;
    buf.insert(TcpSegment(0,  make_bytes({1})));
    buf.insert(TcpSegment(1,  make_bytes({2})));
    buf.insert(TcpSegment(2,  make_bytes({3})));
    EXPECT_EQ(buf.check_gaps(0), 3u);
}

TEST_F(TcpReceiverBufferCheckGapsTest, GapFilledAfterInsert) {
    TcpReceiverBuffer buf;
    buf.insert(TcpSegment(0,  make_bytes({1, 2})));
    buf.insert(TcpSegment(5,  make_bytes({6, 7})));
    // gap: recv_nxt advances only to 2
    EXPECT_EQ(buf.check_gaps(0), 2u);

    buf.insert(TcpSegment(2,  make_bytes({3, 4, 5}))); // fills gap
    EXPECT_EQ(buf.check_gaps(0), 7u);
}

TEST_F(TcpReceiverBufferCheckGapsTest, RecvNxtAlreadyAheadOfBuffer) {
    TcpReceiverBuffer buf;
    buf.insert(TcpSegment(0, make_bytes({1, 2, 3})));
    // recv_nxt beyond what buffer starts — first seg seq_start(0) <= recv_nxt(5)
    // cur_seq starts at 0, advances to 3, then loop ends, returns 3 (< recv_nxt)
    // This is a degenerate state but check_gaps shouldn't crash
    EXPECT_NO_FATAL_FAILURE(buf.check_gaps(5));
}

TEST_F(TcpReceiverBufferCheckGapsTest, SynSegmentConsumesOneSeqByte) {
    TcpReceiverBuffer buf;
    std::span<const std::byte> empty{};
    TcpSegment syn_seg(0, empty, /*syn=*/true);
    buf.insert(syn_seg);
    EXPECT_EQ(buf.check_gaps(0), 1u);
}

TEST_F(TcpReceiverBufferCheckGapsTest, FinSegmentConsumesOneSeqByte) {
    TcpReceiverBuffer buf;
    auto data = make_bytes({1, 2});
    TcpSegment seg(0, data, false, /*fin=*/true);
    buf.insert(seg);
    EXPECT_EQ(buf.check_gaps(0), 3u); // 2 bytes data + 1 FIN
}

TEST_F(TcpReceiverBufferCheckGapsTest, SynDataFinContiguous) {
    TcpReceiverBuffer buf;
    auto data = make_bytes({1, 2, 3});
    TcpSegment seg(0, data, /*syn=*/true, /*fin=*/true);
    buf.insert(seg);
    EXPECT_EQ(buf.check_gaps(0), 5u); // SYN+3+FIN
}

// ─── read ────────────────────────────────────────────────────────────────────

class TcpReceiverBufferReadTest : public testing::Test {};

TEST_F(TcpReceiverBufferReadTest, EmptyBuffer) {
    TcpReceiverBuffer buf;
    auto [result, seq_n] = buf.read(100, 0);
    EXPECT_TRUE(result.empty());
}

TEST_F(TcpReceiverBufferReadTest, ReadSingleSegmentFully) {
    TcpReceiverBuffer buf;
    auto data = make_bytes({1, 2, 3, 4, 5});
    buf.insert(TcpSegment(0, data));
    auto [result, seq_n] = buf.read(100, 5);
    EXPECT_EQ(result.size(), 5u);
    EXPECT_EQ(result, data);
}

TEST_F(TcpReceiverBufferReadTest, ReadLimitedByMaxSize) {
    TcpReceiverBuffer buf;
    auto data = make_bytes({1, 2, 3, 4, 5});
    buf.insert(TcpSegment(0, data));
    auto [result, seq_n] = buf.read(3, 5);
    EXPECT_EQ(result.size(), 3u);
    EXPECT_EQ(result, (make_bytes({1, 2, 3})));
}

TEST_F(TcpReceiverBufferReadTest, ReadTwoContiguousSegments) {
    TcpReceiverBuffer buf;
    auto d1 = make_bytes({1, 2, 3});
    auto d2 = make_bytes({4, 5, 6});
    buf.insert(TcpSegment(0, d1));
    buf.insert(TcpSegment(3, d2));
    auto [result, seq_n] = buf.read(100, 6);
    EXPECT_EQ(result.size(), 6u);
    EXPECT_EQ(result, (make_bytes({1, 2, 3, 4, 5, 6})));
}

TEST_F(TcpReceiverBufferReadTest, ReadStopsAtGap) {
    TcpReceiverBuffer buf;
    auto d1 = make_bytes({1, 2, 3});
    auto d2 = make_bytes({7, 8, 9});
    buf.insert(TcpSegment(0, d1));
    buf.insert(TcpSegment(10, d2)); // gap
    auto [result, seq_n] = buf.read(100, 3);
    EXPECT_EQ(result.size(), 3u);
    EXPECT_EQ(result, d1);
}

TEST_F(TcpReceiverBufferReadTest, OnlyOutOfOrderSegments) {
    TcpReceiverBuffer buf;
    auto data = make_bytes({1, 2, 3});
    buf.insert(TcpSegment(50, data));
    // recv_nxt=0, buffer starts at 50 — all OOO
    auto [result, seq_n] = buf.read(100, 0);
    EXPECT_TRUE(result.empty());
}

TEST_F(TcpReceiverBufferReadTest, MaxSizeZero) {
    TcpReceiverBuffer buf;
    auto data = make_bytes({1, 2, 3});
    buf.insert(TcpSegment(0, data));
    auto [result, seq_n] = buf.read(0, 3);
    EXPECT_TRUE(result.empty());
}

TEST_F(TcpReceiverBufferReadTest, ReadExactSegmentBoundary) {
    TcpReceiverBuffer buf;
    auto d1 = make_bytes({1, 2, 3});
    auto d2 = make_bytes({4, 5, 6});
    buf.insert(TcpSegment(0, d1));
    buf.insert(TcpSegment(3, d2));
    // max_size exactly covers first segment
    auto [result, seq_n] = buf.read(3, 6);
    EXPECT_EQ(result.size(), 3u);
    EXPECT_EQ(result, d1);
}

TEST_F(TcpReceiverBufferReadTest, LargePayloadSingleSegment) {
    TcpReceiverBuffer buf;
    auto data = make_bytes_n(0xAB, 65535);
    buf.insert(TcpSegment(0, data));
    auto [result, seq_n] = buf.read(65535, 65535);
    EXPECT_EQ(result.size(), 65535u);
    EXPECT_EQ(result, data);
}

TEST_F(TcpReceiverBufferReadTest, ReadManyContiguousSegments) {
    TcpReceiverBuffer buf;
    std::vector<std::byte> expected;
    uint32_t seq = 0;
    for (int i = 0; i < 20; ++i) {
        auto chunk = make_bytes_n(static_cast<uint8_t>(i), 10);
        buf.insert(TcpSegment(seq, chunk));
        expected.insert(expected.end(), chunk.begin(), chunk.end());
        seq += 10;
    }
    auto [result, seq_n] = buf.read(1000, seq);
    EXPECT_EQ(result.size(), 200u);
    EXPECT_EQ(result, expected);
}

// ─── insert ──────────────────────────────────────────────────────────────────

class TcpReceiverBufferInsertTest : public testing::Test {};

TEST_F(TcpReceiverBufferInsertTest, InsertInOrder) {
    TcpReceiverBuffer buf;
    EXPECT_TRUE(buf.insert(TcpSegment(0, make_bytes({1}))));
    EXPECT_TRUE(buf.insert(TcpSegment(1, make_bytes({2}))));
    EXPECT_EQ(buf.size_segs(), 2u);
}

TEST_F(TcpReceiverBufferInsertTest, InsertOutOfOrder) {
    TcpReceiverBuffer buf;
    EXPECT_TRUE(buf.insert(TcpSegment(10, make_bytes({1}))));
    EXPECT_TRUE(buf.insert(TcpSegment(0,  make_bytes({2}))));
    // Should be sorted: 0 then 10
    EXPECT_EQ(buf.front().seq_start(), 0u);
    EXPECT_EQ(buf.back().seq_start(), 10u);
}

TEST_F(TcpReceiverBufferInsertTest, DuplicateSegmentRejected) {
    TcpReceiverBuffer buf;
    TcpSegment seg(0, make_bytes({1, 2, 3}));
    EXPECT_TRUE(buf.insert(seg));
    EXPECT_FALSE(buf.insert(seg));
    EXPECT_EQ(buf.size_segs(), 1u);
}

TEST_F(TcpReceiverBufferInsertTest, InsertThreeOutOfOrder) {
    TcpReceiverBuffer buf;
    buf.insert(TcpSegment(20, make_bytes({3})));
    buf.insert(TcpSegment(0,  make_bytes({1})));
    buf.insert(TcpSegment(10, make_bytes({2})));
    EXPECT_EQ(buf.at(0).seq_start(), 0u);
    EXPECT_EQ(buf.at(1).seq_start(), 10u);
    EXPECT_EQ(buf.at(2).seq_start(), 20u);
}

// ─── interaction: insert → check_gaps → read ─────────────────────────────────

class TcpReceiverBufferIntegrationTest : public testing::Test {};

TEST_F(TcpReceiverBufferIntegrationTest, OOOSegmentFilledByLaterInsert) {
    TcpReceiverBuffer buf;
    auto d1 = make_bytes({1, 2, 3});
    auto d2 = make_bytes({4, 5, 6});
    auto d3 = make_bytes({7, 8, 9});

    buf.insert(TcpSegment(0, d1));
    buf.insert(TcpSegment(6, d3)); // out of order

    uint32_t nxt = buf.check_gaps(0);
    EXPECT_EQ(nxt, 3u); // gap at 3

    buf.insert(TcpSegment(3, d2)); // fills gap
    nxt = buf.check_gaps(0);
    EXPECT_EQ(nxt, 9u);

    auto [result, seq_n] = buf.read(100, nxt);
    EXPECT_EQ(result, (make_bytes({1,2,3,4,5,6,7,8,9})));
}

TEST_F(TcpReceiverBufferIntegrationTest, ReadAfterPartialConsumeViaCheckGaps) {
    TcpReceiverBuffer buf;
    buf.insert(TcpSegment(0,  make_bytes({10, 20})));
    buf.insert(TcpSegment(2,  make_bytes({30, 40})));
    buf.insert(TcpSegment(10, make_bytes({50}))); // OOO gap at 4..9

    uint32_t nxt = buf.check_gaps(0);
    EXPECT_EQ(nxt, 4u);

    auto [result, seq_n] = buf.read(100, nxt);
    EXPECT_EQ(result, (make_bytes({10, 20, 30, 40})));
}

TEST_F(TcpReceiverBufferIntegrationTest, ReadIsIdempotent) {
    TcpReceiverBuffer buf;
    auto data = make_bytes({1, 2, 3});
    buf.insert(TcpSegment(0, data));
    auto r1 = buf.read(100, 3);
    auto r2 = buf.read(100, 3);
    EXPECT_EQ(r1, r2); // read must not mutate state
}

TEST_F(TcpReceiverBufferIntegrationTest, CheckGapsIdempotent) {
    TcpReceiverBuffer buf;
    buf.insert(TcpSegment(0, make_bytes({1, 2, 3})));
    auto n1 = buf.check_gaps(0);
    auto n2 = buf.check_gaps(0);
    EXPECT_EQ(n1, n2);
}

TEST_F(TcpReceiverBufferIntegrationTest, SeqWrapAround) {
    TcpReceiverBuffer buf;
    // Sequence space near UINT32_MAX
    const uint32_t base = 0xFFFFFF00u;
    auto d1 = make_bytes_n(0xAA, 128); // seq: base..base+128, wraps
    auto d2 = make_bytes_n(0xBB, 64);
    buf.insert(TcpSegment(base, d1));
    buf.insert(TcpSegment(base + 128, d2));
    // check_gaps should advance through both
    uint32_t nxt = buf.check_gaps(base);
    EXPECT_EQ(nxt, base + 192);
}

TEST_F(TcpReceiverBufferIntegrationTest, SingleByteSegmentsContiguous) {
    TcpReceiverBuffer buf;
    for (uint32_t i = 0; i < 256; ++i) {
        buf.insert(TcpSegment(i, make_bytes({static_cast<uint8_t>(i)})));
    }
    EXPECT_EQ(buf.check_gaps(0), 256u);
    auto [result, seq_n] = buf.read(256, 256);
    EXPECT_EQ(result.size(), 256u);
    for (int i = 0; i < 256; ++i) {
        EXPECT_EQ(result[i], static_cast<std::byte>(i));
    }
}
