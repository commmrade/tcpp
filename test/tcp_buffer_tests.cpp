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

    buf.consume(1100u);
    ASSERT_EQ(buf.size_segs(), 1u);
    EXPECT_EQ(buf.front().seq_start(), 1100u);
}

TEST_F(TcpBufferTest, ConsumeAll)
{
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1100, p});
    buf.insert(TcpSegment{1200, p});

    buf.consume(1300u);
    EXPECT_TRUE(buf.empty());
}

TEST_F(TcpBufferTest, ConsumeSYNSegment)
{
    buf.insert(TcpSegment{1000, {}, true, false});
    ASSERT_EQ(buf.size_segs(), 1);
    buf.consume(1001);
    EXPECT_TRUE(buf.empty());
}

TEST_F(TcpBufferTest, ConsumeNone)
{
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});

    buf.consume(1000u);
    ASSERT_EQ(buf.size_segs(), 1u);
}

TEST_F(TcpBufferTest, ConsumeMiddleOfSegment)
{
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});

    buf.consume(1050u);
    EXPECT_EQ(buf.size_segs(), 1);
    EXPECT_EQ(inner().cbegin()->seq_start(), 1050);
}

TEST_F(TcpBufferTest, ConsumeEmptyBuffer)
{
    EXPECT_NO_THROW(buf.consume(9999u));
    EXPECT_TRUE(buf.empty());
}

TEST_F(TcpBufferTest, ConsumePartial)
{
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1100, p});
    buf.insert(TcpSegment{1200, p});

    buf.consume(1200u);
    ASSERT_EQ(buf.size_segs(), 1u);
    EXPECT_EQ(buf.front().seq_start(), 1200u);
}

// ─── read ────────────────────────────────────────────────────────────────────

TEST_F(TcpBufferTest, ReadExactSegment)
{
    auto p = make_payload(100, std::byte{0x42});
    buf.insert(TcpSegment{1000, p});

    auto data = buf.read(100);
    ASSERT_EQ(data.size(), 100u);
    for (auto b : data)
        EXPECT_EQ(b, std::byte{0x42});
}

TEST_F(TcpBufferTest, ReadTwoSegments)
{
    auto p = make_payload(100, std::byte{0x42});
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1100, p});

    ASSERT_EQ(buf.size_segs(), 2);
    auto data = buf.read(200);
    ASSERT_EQ(data.size(), 200);
}

TEST_F(TcpBufferTest, ReadTwoAndHalfSegments)
{
    auto p = make_payload(100, std::byte{0x42});
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1100, p});
    buf.insert(TcpSegment{1200, p});

    ASSERT_EQ(buf.size_segs(), 3);
    auto data = buf.read(250);
    ASSERT_EQ(data.size(), 250);
}

TEST_F(TcpBufferTest, ReadNotConseqSegments)
{
    auto p = make_payload(100, std::byte{0x42});
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1200, p});

    auto data = buf.read(200);
    ASSERT_EQ(data.size(), 100);
}

TEST_F(TcpBufferTest, ReadFromMidSegment)
{
    auto p = make_payload(100, std::byte{0xFF});
    buf.insert(TcpSegment{1000, p});

    auto data = buf.read(50);
    EXPECT_FALSE(data.empty());
}

TEST_F(TcpBufferTest, ReadEmptyBuffer)
{
    auto data = buf.read(100);
    EXPECT_TRUE(data.empty());
}

// ─── append ──────────────────────────────────────────────────────────────────

TEST_F(TcpBufferTest, AppendLessThanMss)
{
    auto p = make_payload(50);
    auto big_p = make_payload(1000);
    buf.insert(TcpSegment{1000, p});

    constexpr auto MSS = 536;
    ASSERT_LT(buf.back().size_in_seq(), MSS);

    const auto space_left = MSS - buf.back().size_in_seq();
    const auto to_write_n = std::min(space_left, big_p.size());
    buf.append_back(std::span{big_p.data(), to_write_n});

    ASSERT_EQ(buf.size_segs(), 1);
    EXPECT_EQ(inner().cbegin()->size_in_seq(), 536u);
    EXPECT_EQ(inner().cbegin()->payload_size(), 536u);
}

TEST_F(TcpBufferTest, AppendFailsWhenEmpty)
{
    const auto pl = make_payload(100);
    EXPECT_ANY_THROW(buf.append_back(pl));
}