#include "include/tcp_common.hpp"

#include <gtest/gtest.h>
#include "../../src/tcpp/net/buffer.hpp"

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

class TcpReceiverBufTest : public TcpConnectionTest
{
protected:
    // Sends an arbitrary segment from the peer side.
    // Always expects exactly one write() call (ACK or dup-ACK).
    void peer_send(const std::uint32_t seqn,
                   std::span<const std::byte> payload,
                   const bool fin = false)
    {
        auto seg = helpers::make_tcp({
            .sport  = PEER_PORT,
            .dport  = LOCAL_PORT,
            .seqn   = seqn,
            .ackn   = get_send_iss() + 1,
            .window = 65535,
            .ack    = true,
            .fin    = fin,
        });
        const auto seg_d = seg.serialize();
        const netparser::TcpHeaderView seg_view{seg_d};

        EXPECT_CALL(mock_io_, write(_)).Times(AnyNumber());
        conn_.on_packet(seg_view, payload);
        Mock::VerifyAndClearExpectations(&mock_io_);
    }

    ssize_t conn_read(void* buf, const std::size_t n)
    {
        return conn_.read(buf, n);
    }
};

// -------------------------------------------------------------------
// Test 1: read all data, then read again → EOF (0)
// -------------------------------------------------------------------
TEST_F(TcpReceiverBufTest, ReadDataThenFin_ReturnsDataThenEof)
{
    do_handshake();

    constexpr std::size_t DATA_LEN = 200;
    std::vector<std::byte> payload(DATA_LEN);
    std::memset(payload.data(), 'A', DATA_LEN);

    // In-order data segment: seq [PEER_ISN+1, PEER_ISN+201)
    peer_send(PEER_ISN + 1, payload);
    ASSERT_EQ(recv_nxt(), PEER_ISN + 1 + DATA_LEN);

    // FIN: seq = PEER_ISN+201, no payload
    peer_send(PEER_ISN + 1 + DATA_LEN, {}, /*fin=*/true);

    // Read all data
    std::vector<std::byte> read_buf(DATA_LEN + 64, std::byte{0});
    ssize_t n = conn_read(read_buf.data(), read_buf.size());
    ASSERT_EQ(n, static_cast<ssize_t>(DATA_LEN));
    ASSERT_EQ(std::memcmp(read_buf.data(), payload.data(), DATA_LEN), 0);

    // Second read: FIN consumed → EOF
    n = conn_read(read_buf.data(), read_buf.size());
    ASSERT_EQ(n, 0);
}

// -------------------------------------------------------------------
// Test 2: partial read doesn't consume more than requested
// -------------------------------------------------------------------
TEST_F(TcpReceiverBufTest, PartialRead_ConsumesOnlyRequested)
{
    do_handshake();

    constexpr std::size_t DATA_LEN = 300;
    std::vector<std::byte> payload(DATA_LEN);
    for (std::size_t i = 0; i < DATA_LEN; ++i)
        payload[i] = static_cast<std::byte>(i & 0xFF);

    peer_send(PEER_ISN + 1, payload);

    std::vector<std::byte> buf(100, std::byte{0});

    ssize_t n = conn_read(buf.data(), 100);
    ASSERT_EQ(n, 100);
    ASSERT_EQ(std::memcmp(buf.data(), payload.data(), 100), 0);

    n = conn_read(buf.data(), 100);
    ASSERT_EQ(n, 100);
    ASSERT_EQ(std::memcmp(buf.data(), payload.data() + 100, 100), 0);

    n = conn_read(buf.data(), 100);
    ASSERT_EQ(n, 100);
    ASSERT_EQ(std::memcmp(buf.data(), payload.data() + 200, 100), 0);
}

// -------------------------------------------------------------------
// Test 3: out-of-order arrival; recv.nxt doesn't advance until gap filled
// -------------------------------------------------------------------
TEST_F(TcpReceiverBufTest, OutOfOrder_RecvNxtHoldsUntilGapFilled)
{
    conn_.set_option(ConnectionOption::QUICKACK, true);
    do_handshake();

    // In-order [0, 1200): seq PEER_ISN+1 .. PEER_ISN+1201
    std::vector<std::byte> p1(1200, std::byte{1});
    peer_send(PEER_ISN + 1, p1);
    ASSERT_EQ(recv_nxt(), PEER_ISN + 1201);

    // OOO: [1400, 1500): gap at [1200, 1400)
    std::vector<std::byte> p3(100, std::byte{3});
    peer_send(PEER_ISN + 1401, p3);
    // recv.nxt must NOT advance past the gap
    ASSERT_EQ(recv_nxt(), PEER_ISN + 1201);

    // Fill lower half of gap [1200, 1300)
    std::vector<std::byte> p2a(100, std::byte{2});
    peer_send(PEER_ISN + 1201, p2a);
    ASSERT_EQ(recv_nxt(), PEER_ISN + 1301);

    // Fill upper half of gap [1300, 1400): now gap is closed, p3 becomes contiguous
    std::vector<std::byte> p2b(100, std::byte{2});
    peer_send(PEER_ISN + 1301, p2b);
    ASSERT_EQ(recv_nxt(), PEER_ISN + 1501);
}

// -------------------------------------------------------------------
// Test 4: single large OOO segment, then in-order fill, recv.nxt jumps
// -------------------------------------------------------------------
TEST_F(TcpReceiverBufTest, OutOfOrder_SingleGapFill_RecvNxtJumps)
{
    do_handshake();

    // OOO first: [500, 1000) — nothing in order yet
    std::vector<std::byte> late(500, std::byte{0xBB});
    peer_send(PEER_ISN + 501, late);
    ASSERT_EQ(recv_nxt(), PEER_ISN + 1); // nxt still at start

    // In-order [0, 500): fills the gap, chained with the OOO segment
    std::vector<std::byte> early(500, std::byte{0xAA});
    peer_send(PEER_ISN + 1, early);
    ASSERT_EQ(recv_nxt(), PEER_ISN + 1001);

    // Data is readable in order: first 'early', then 'late'
    std::vector<std::byte> buf(1000);
    const ssize_t n = conn_read(buf.data(), buf.size());
    ASSERT_EQ(n, 1000);
    ASSERT_EQ(buf[0],   std::byte{0xAA});
    ASSERT_EQ(buf[499], std::byte{0xAA});
    ASSERT_EQ(buf[500], std::byte{0xBB});
    ASSERT_EQ(buf[999], std::byte{0xBB});
}


class TcpConnectionSendBufTest : public TcpConnectionTest
{

};

TEST_F(TcpConnectionSendBufTest, InsertSeveralUnderMss)
{
    do_handshake();

    std::array<std::byte, 4> buf{};
    std::memset(buf.data(), 'c', buf.size());

    write(buf);
    write(buf);
    write(buf);
    ASSERT_EQ(send_buf_size_segs(), 1);
    ASSERT_EQ(send_buf_pl_size(), 4 * 3);
}

TEST_F(TcpConnectionSendBufTest, InsertSeveralOverMss)
{
    do_handshake();

    const auto send_mss_ = send_mss();
    std::vector<std::byte> buf;
    buf.resize(send_mss_);
    std::memset(buf.data(), 'c', buf.size());

    write(std::span<const std::byte>{buf.data(), static_cast<std::size_t>(send_mss_ - 10)});
    write(buf);
    ASSERT_EQ(send_buf_size_segs(), 2);
    ASSERT_EQ(send_buf_pl_size(), send_mss_ - 10 + buf.size());
}

TEST_F(TcpConnectionSendBufTest, InsertSeveralMss)
{
    do_handshake();

    const auto send_mss_ = send_mss();
    std::vector<std::byte> buf;
    buf.resize(send_mss_ * 3);
    std::memset(buf.data(), 'c', buf.size());

    write(buf);
    ASSERT_EQ(send_buf_size_segs(), 3);
    ASSERT_EQ(send_buf_pl_size(), buf.size());
}
