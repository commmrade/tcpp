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


class TestTcpSynRetrans(unittest.TestCase):
    def test_syn(self):
        def is_synack(pkt):
            return (
                pkt.haslayer(TCP)
                and pkt[TCP].flags & 0x12 == 0x12
                and pkt[TCP].sport == DST_PORT
                and pkt[TCP].dport == SRC_PORT
            )

        results = []
        sniffer_ready = threading.Event()

        def sniff_two():
            sniffer_ready.set()
            pkts = sniff(iface=TUN_IFACE, lfilter=is_synack, count=2, timeout=10)
            results.extend(pkts)

        t = threading.Thread(target=sniff_two)
        t.start()
        sniffer_ready.wait()
        time.sleep(0.05)

        syn_packet = IP(src=SRC_IP, dst=DST_IP) / TCP(
            sport=SRC_PORT, dport=DST_PORT, seq=seq_num, flags="S"
        )
        send(syn_packet, iface=TUN_IFACE, verbose=False)

        t.join()

        self.assertEqual(len(results), 2, "Did not receive 2 SYNACKs")

        t1 = results[0].time
        t2 = results[1].time
        diff = t2 - t1
        print(f"First SYNACK at {t1:.3f}, second at {t2:.3f}, diff={diff:.3f}s")
        self.assertAlmostEqual(
            diff, 1.0, delta=0.2, msg=f"Retransmit gap was {diff:.3f}s, expected ~1s"
        )

        synack_pkt = results[1]
        ack_packet = IP(src=SRC_IP, dst=DST_IP) / TCP(
            sport=SRC_PORT,
            dport=DST_PORT,
            seq=synack_pkt[TCP].ack,
            ack=synack_pkt[TCP].seq + 1,
            flags="A",
        )
        send(ack_packet, iface=TUN_IFACE, verbose=False)
        print("ACK sent — handshake complete")

    def test_syn_exponential_backoff(self):
        # Expected gaps: 1s, 2s, 4s, 8s, ... between consecutive SYNACKs
        NUM_RETRANSMITS = 4  # original + 4 retransmits = 5 packets total
        DELTA = 0.3  # tolerance per gap
        NEW_SRC_PORT = SRC_PORT + 1

        def is_synack(pkt):
            return (
                pkt.haslayer(TCP)
                and pkt[TCP].flags & 0x12 == 0x12
                and pkt[TCP].sport == DST_PORT
                and pkt[TCP].dport == NEW_SRC_PORT
            )

        results = []
        sniffer_ready = threading.Event()

        def sniff_all():
            sniffer_ready.set()
            # total timeout: 1+2+4+8 = 15s of gaps plus margin
            pkts = sniff(
                iface=TUN_IFACE,
                lfilter=is_synack,
                count=NUM_RETRANSMITS + 1,
                timeout=30,
            )
            results.extend(pkts)

        t = threading.Thread(target=sniff_all)
        t.start()
        sniffer_ready.wait()
        time.sleep(0.05)

        syn_packet = IP(src=SRC_IP, dst=DST_IP) / TCP(
            sport=NEW_SRC_PORT, dport=DST_PORT, seq=seq_num, flags="S"
        )
        send(syn_packet, iface=TUN_IFACE, verbose=False)

        t.join()

        self.assertEqual(
            len(results),
            NUM_RETRANSMITS + 1,
            f"Expected {NUM_RETRANSMITS + 1} SYNACKs, got {len(results)}",
        )

        # Verify each gap doubles the previous one
        expected_gap = 1.0
        for i in range(1, len(results)):
            gap = results[i].time - results[i - 1].time
            print(f"Gap {i}: {gap:.3f}s (expected ~{expected_gap:.1f}s)")
            self.assertAlmostEqual(
                gap,
                expected_gap,
                delta=DELTA,
                msg=f"Gap {i} was {gap:.3f}s, expected ~{expected_gap:.1f}s",
            )
            expected_gap *= 2

        # Send ACK after the last retransmitted SYNACK
        synack_pkt = results[-1]
        ack_packet = IP(src=SRC_IP, dst=DST_IP) / TCP(
            sport=NEW_SRC_PORT,
            dport=DST_PORT,
            seq=synack_pkt[TCP].ack,
            ack=synack_pkt[TCP].seq + 1,
            flags="A",
        )
        send(ack_packet, iface=TUN_IFACE, verbose=False)
        print("ACK sent — handshake complete")


if __name__ == "__main__":
    unittest.main()
