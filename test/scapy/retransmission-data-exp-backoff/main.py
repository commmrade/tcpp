import threading
import time
import unittest

from scapy.all import *
from scapy.layers.inet import IP, TCP

TUN_IFACE = "tun1"
DST_IP = "10.0.0.2"
SRC_IP = "10.0.0.1"
DST_PORT = 8090
SRC_PORT = 54675
seq_num = 1000


def do_handshake(src_port):
    """Perform full TCP handshake, returns (our_seq, server_seq) after handshake."""

    def is_synack(pkt):
        return (
            pkt.haslayer(TCP)
            and pkt[TCP].flags & 0x12 == 0x12
            and pkt[TCP].sport == DST_PORT
            and pkt[TCP].dport == src_port
        )

    results = []
    sniffer_ready = threading.Event()

    def sniff_synack():
        sniffer_ready.set()
        pkts = sniff(iface=TUN_IFACE, lfilter=is_synack, count=1, timeout=10)
        results.extend(pkts)

    t = threading.Thread(target=sniff_synack)
    t.start()
    sniffer_ready.wait()
    time.sleep(0.05)

    syn = IP(src=SRC_IP, dst=DST_IP) / TCP(
        sport=src_port, dport=DST_PORT, seq=seq_num, flags="S"
    )
    send(syn, iface=TUN_IFACE, verbose=False)
    t.join()

    assert len(results) == 1, "Handshake failed: no SYNACK received"
    synack = results[0]

    our_seq = synack[TCP].ack
    server_seq = synack[TCP].seq + 1

    ack = IP(src=SRC_IP, dst=DST_IP) / TCP(
        sport=src_port,
        dport=DST_PORT,
        seq=our_seq,
        ack=server_seq,
        flags="A",
    )
    send(ack, iface=TUN_IFACE, verbose=False)
    print(f"Handshake complete: our_seq={our_seq}, server_seq={server_seq}")
    return our_seq, server_seq


class TestTcpDataRetrans(unittest.TestCase):
    def test_data_exponential_backoff(self):
        """
        Handshake, send data, ACK the server's echo to confirm receipt,
        then stop ACKing — forcing the server to retransmit the echo
        with exponential backoff. Filter on payload presence so it works
        regardless of whether ACK is piggybacked inside the data segment.
        """
        NEW_SRC_PORT = SRC_PORT + 2
        NUM_RETRANSMITS = 4
        DELTA = 0.3
        PAYLOAD = b"hello"

        our_seq, server_seq = do_handshake(NEW_SRC_PORT)

        # --- Step 1: send data, wait for server's echo ---
        # The echo carries a payload so filter on Raw + correct seq direction.
        # Deliberately NOT filtering on flags — works whether server sends a
        # pure data segment or a piggybacked ACK+data in one segment.
        echo_result = []
        echo_ready = threading.Event()

        def is_server_data(pkt):
            """Any segment from server that carries a payload (echo or piggyback)."""
            return (
                pkt.haslayer(TCP)
                and pkt.haslayer(Raw)
                and pkt[TCP].sport == DST_PORT
                and pkt[TCP].dport == NEW_SRC_PORT
            )

        def sniff_echo():
            echo_ready.set()
            pkts = sniff(iface=TUN_IFACE, lfilter=is_server_data, count=1, timeout=10)
            echo_result.extend(pkts)

        t_echo = threading.Thread(target=sniff_echo)
        t_echo.start()
        echo_ready.wait()
        time.sleep(0.05)

        data_pkt = (
            IP(src=SRC_IP, dst=DST_IP)
            / TCP(
                sport=NEW_SRC_PORT,
                dport=DST_PORT,
                seq=our_seq,
                ack=server_seq,
                flags="PA",
            )
            / Raw(load=PAYLOAD)
        )
        send(data_pkt, iface=TUN_IFACE, verbose=False)
        print(f"Sent data: {PAYLOAD}")

        t_echo.join()
        self.assertEqual(len(echo_result), 1, "Did not receive server echo")

        echo_pkt = echo_result[0]
        echo_seq = echo_pkt[TCP].seq  # server's data seq — retransmits will repeat this
        echo_payload_len = len(echo_pkt[Raw].load)
        print(f"Echo received: seq={echo_seq}, payload={echo_pkt[Raw].load}")

        # --- Step 2: ACK the echo so server knows we got it once ---
        # This resets the server's retransmit timer cleanly from this point.
        our_seq_after = our_seq + len(PAYLOAD)
        ack_echo = IP(src=SRC_IP, dst=DST_IP) / TCP(
            sport=NEW_SRC_PORT,
            dport=DST_PORT,
            seq=our_seq_after,
            ack=echo_seq + echo_payload_len,  # ack past the echo data
            flags="A",
        )
        send(ack_echo, iface=TUN_IFACE, verbose=False)
        print("ACKed echo — now going silent to trigger retransmits")

        # --- Step 3: send more data, then stop ACKing to cause retransmission ---
        retrans_results = []
        retrans_ready = threading.Event()

        # The retransmit filter: same as before — payload present, right ports.
        # seq will equal retrans_echo_seq on every retransmit, we assert this below.
        def is_retrans(pkt):
            return (
                pkt.haslayer(TCP)
                and pkt.haslayer(Raw)
                and pkt[TCP].sport == DST_PORT
                and pkt[TCP].dport == NEW_SRC_PORT
            )

        def sniff_retrans():
            retrans_ready.set()
            pkts = sniff(
                iface=TUN_IFACE,
                lfilter=is_retrans,
                count=NUM_RETRANSMITS + 1,
                timeout=35,
            )
            retrans_results.extend(pkts)

        t_retrans = threading.Thread(target=sniff_retrans)
        t_retrans.start()
        retrans_ready.wait()
        time.sleep(0.05)

        # Send second payload — server will echo it, we will NOT ack this one
        second_payload = b"world"
        data_pkt2 = (
            IP(src=SRC_IP, dst=DST_IP)
            / TCP(
                sport=NEW_SRC_PORT,
                dport=DST_PORT,
                seq=our_seq_after,
                ack=echo_seq + echo_payload_len,
                flags="PA",
            )
            / Raw(load=second_payload)
        )
        send(data_pkt2, iface=TUN_IFACE, verbose=False)
        print(f"Sent second data: {second_payload} — going silent now")

        t_retrans.join()

        self.assertEqual(
            len(retrans_results),
            NUM_RETRANSMITS + 1,
            f"Expected {NUM_RETRANSMITS + 1} data segments, got {len(retrans_results)}",
        )

        # All must be retransmits of the same segment (seq never advances)
        first_seq = retrans_results[0][TCP].seq
        for i, pkt in enumerate(retrans_results):
            self.assertEqual(
                pkt[TCP].seq,
                first_seq,
                f"Segment {i} seq={pkt[TCP].seq} differs from first={first_seq} — not a retransmit",
            )

        # Verify exponential backoff: ~1s, ~2s, ~4s, ~8s
        expected_gap = 1.0
        for i in range(1, len(retrans_results)):
            gap = retrans_results[i].time - retrans_results[i - 1].time
            print(f"Gap {i}: {gap:.3f}s (expected ~{expected_gap:.1f}s)")
            self.assertAlmostEqual(
                gap,
                expected_gap,
                delta=DELTA,
                msg=f"Gap {i} was {gap:.3f}s, expected ~{expected_gap:.1f}s",
            )
            expected_gap *= 2

        # Clean up — ACK everything so server can close gracefully
        last_pkt = retrans_results[-1]
        final_ack = IP(src=SRC_IP, dst=DST_IP) / TCP(
            sport=NEW_SRC_PORT,
            dport=DST_PORT,
            seq=our_seq_after + len(second_payload),
            ack=last_pkt[TCP].seq + len(last_pkt[Raw].load),
            flags="A",
        )
        send(final_ack, iface=TUN_IFACE, verbose=False)
        print("Final ACK sent — server data acknowledged")


if __name__ == "__main__":
    unittest.main()
