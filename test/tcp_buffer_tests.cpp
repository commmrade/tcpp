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
    EXPECT_EQ(s.size_in_seq(),  100u); // 99 + 1 SYN
    EXPECT_EQ(s.seq_end(),      1100u);
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

// ═══════════════════════════════════════════════════════════════════════════════
// TcpBuffer — insert
// ═══════════════════════════════════════════════════════════════════════════════

TEST(TcpBuffer, StartsEmpty)
{
    TcpBuffer buf;
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0u);
}

TEST(TcpBuffer, InsertSingle)
{
    TcpBuffer buf;
    buf.insert(TcpSegment{1000, make_payload(100)});
    EXPECT_EQ(buf.size(), 1u);
    EXPECT_FALSE(buf.empty());
}

TEST(TcpBuffer, InsertInOrder)
{
    TcpBuffer buf;
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1100, p});
    buf.insert(TcpSegment{1200, p});

    ASSERT_EQ(buf.size(), 3u);
    auto it = buf.inner().cbegin();
    EXPECT_EQ(it->seq_start(), 1000u); ++it;
    EXPECT_EQ(it->seq_start(), 1100u); ++it;
    EXPECT_EQ(it->seq_start(), 1200u);
}

TEST(TcpBuffer, InsertReverseOrder)
{
    TcpBuffer buf;
    auto p = make_payload(100);
    buf.insert(TcpSegment{1200, p});
    buf.insert(TcpSegment{1100, p});
    buf.insert(TcpSegment{1000, p});

    ASSERT_EQ(buf.size(), 3u);
    auto it = buf.inner().cbegin();
    EXPECT_EQ(it->seq_start(), 1000u); ++it;
    EXPECT_EQ(it->seq_start(), 1100u); ++it;
    EXPECT_EQ(it->seq_start(), 1200u);
}

TEST(TcpBuffer, InsertMiddle)
{
    TcpBuffer buf;
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1200, p});
    buf.insert(TcpSegment{1100, p}); // в середину

    ASSERT_EQ(buf.size(), 3u);
    auto it = buf.inner().cbegin();
    EXPECT_EQ(it->seq_start(), 1000u); ++it;
    EXPECT_EQ(it->seq_start(), 1100u); ++it;
    EXPECT_EQ(it->seq_start(), 1200u);
}

TEST(TcpBuffer, InsertWithGap)
{
    TcpBuffer buf;
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1300, p}); // gap [1100, 1300)

    ASSERT_EQ(buf.size(), 2u);
    auto it = buf.inner().cbegin();
    EXPECT_EQ(it->seq_start(), 1000u); ++it;
    EXPECT_EQ(it->seq_start(), 1300u);
}

TEST(TcpBuffer, InsertDuplicate)
{
    // Два сегмента с одинаковым seq_start — оба вставляются (или один? — тест покажет)
    TcpBuffer buf;
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1000, p});

    // Документируем фактическое поведение
    EXPECT_EQ(buf.size(), 1u);
}

TEST(TcpBuffer, InsertManyRandomOrder)
{
    TcpBuffer buf;
    auto p = make_payload(50);
    for (int i = 9; i >= 0; --i)
        buf.insert(TcpSegment{static_cast<std::uint32_t>(1000 + i * 50), p});

    ASSERT_EQ(buf.size(), 10u);
    std::uint32_t prev_seq = 0;
    for (const auto& s : buf.inner()) {
        EXPECT_GT(s.seq_start(), prev_seq);
        prev_seq = s.seq_start();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TcpBuffer — front
// ═══════════════════════════════════════════════════════════════════════════════

TEST(TcpBuffer, FrontReturnFirstSegment)
{
    TcpBuffer buf;
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1100, p});

    auto f = buf.front();
    EXPECT_EQ(f.seq_start(), 1000u);
}

TEST(TcpBuffer, FrontOnEmpty)
{
    TcpBuffer buf;
    EXPECT_DEATH(buf.front(), ""); // assert(!empty())
}

// ═══════════════════════════════════════════════════════════════════════════════
// TcpBuffer — consume
// ═══════════════════════════════════════════════════════════════════════════════

TEST(TcpBuffer, ConsumeExactSeqEnd)
{
    TcpBuffer buf;
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p}); // seq_end = 1100
    buf.insert(TcpSegment{1100, p}); // seq_end = 1200

    buf.consume(1100u); // первый сегмент уходит (seq_end==1100 <= 1100)
    ASSERT_EQ(buf.size(), 1u);
    EXPECT_EQ(buf.front().seq_start(), 1100u);
}

TEST(TcpBuffer, ConsumeAll)
{
    TcpBuffer buf;
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1100, p});
    buf.insert(TcpSegment{1200, p});

    buf.consume(1300u); // seq_end последнего == 1300
    EXPECT_TRUE(buf.empty());
}

TEST(TcpBuffer, ConsumeNone)
{
    TcpBuffer buf;
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p}); // seq_end = 1100

    buf.consume(1000u); // 1000 < 1100 — ничего не удаляется
    ASSERT_EQ(buf.size(), 1u);
}

TEST(TcpBuffer, ConsumeMiddleOfSegment)
{
    // to_seg_n попадает внутрь сегмента: 1000 <= 1050 < 1100
    // поведение зависит от реализации — тест документирует что происходит
    TcpBuffer buf;
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p}); // seq_end = 1100

    buf.consume(1050u);
    // Сегмент не должен быть удалён полностью — хотя бы 0 или 1 сегмент
    EXPECT_EQ(buf.size(), 1);

    const auto iter = buf.inner().cbegin();
    EXPECT_EQ(iter->seq_start(), 1050);
}

TEST(TcpBuffer, ConsumeEmptyBuffer)
{
    TcpBuffer buf;
    EXPECT_NO_THROW(buf.consume(9999u));
    EXPECT_TRUE(buf.empty());
}

TEST(TcpBuffer, ConsumePartial)
{
    TcpBuffer buf;
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p}); // seq_end = 1100
    buf.insert(TcpSegment{1100, p}); // seq_end = 1200
    buf.insert(TcpSegment{1200, p}); // seq_end = 1300

    buf.consume(1200u); // удаляет первые два (seq_end 1100 и 1200 <= 1200)
    ASSERT_EQ(buf.size(), 1u);
    EXPECT_EQ(buf.front().seq_start(), 1200u);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TcpBuffer — read
// ═══════════════════════════════════════════════════════════════════════════════

TEST(TcpBuffer, ReadExactSegment)
{
    TcpBuffer buf;
    auto p = make_payload(100, std::byte{0x42});
    buf.insert(TcpSegment{1000, p});

    auto data = buf.read(1000, 100);
    ASSERT_EQ(data.size(), 100u);
    for (auto b : data)
        EXPECT_EQ(b, std::byte{0x42});
}

TEST(TcpBuffer, ReadTwoSegments)
{
    TcpBuffer buf;
    auto p = make_payload(100, std::byte{0x42});
    buf.insert(TcpSegment{1000, p});
    buf.insert(TcpSegment{1100, p});

    ASSERT_EQ(buf.size(), 2);

    auto data = buf.read(1000, 200);
    ASSERT_EQ(data.size(), 200);
}

TEST(TcpBuffer, ReadFromMidSegment)
{
    TcpBuffer buf;
    auto p = make_payload(100, std::byte{0xFF});
    buf.insert(TcpSegment{1000, p});

    // seq_n=1050 попадает внутрь сегмента [1000, 1100)
    auto data = buf.read(1050, 50);
    EXPECT_FALSE(data.empty());
}

TEST(TcpBuffer, ReadMissReturnsEmpty)
{
    TcpBuffer buf;
    auto p = make_payload(100);
    buf.insert(TcpSegment{1000, p});

    auto data = buf.read(2000, 100); // нет такого сегмента
    EXPECT_TRUE(data.empty());
}

TEST(TcpBuffer, ReadFromSecondSegment)
{
    TcpBuffer buf;
    auto p1 = make_payload(100, std::byte{0x01});
    auto p2 = make_payload(100, std::byte{0x02});
    buf.insert(TcpSegment{1000, p1});
    buf.insert(TcpSegment{1100, p2});

    auto data = buf.read(1100, 100);
    ASSERT_EQ(data.size(), 100u);
    for (auto b : data)
        EXPECT_EQ(b, std::byte{0x02});
}

TEST(TcpBuffer, ReadEmptyBuffer)
{
    TcpBuffer buf;
    auto data = buf.read(0, 100);
    EXPECT_TRUE(data.empty());
}