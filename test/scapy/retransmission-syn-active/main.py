import threading
import time
import unittest

from scapy.all import *
from scapy.layers.inet import IP, TCP

TUN_IFACE = "tun1"
DST_IP = "10.0.0.2"  # your TCP stack
SRC_IP = "10.0.0.1"  # us, the "server"
SERVER_PORT = 8090
SEQ_NUM = 5000


class TestActiveSynRetrans(unittest.TestCase):
    def _collect_syns(self, dst_port_hint, count, timeout):
        """Sniff SYNs coming from the stack toward our server port."""

        def is_syn(pkt):
            return (
                pkt.haslayer(TCP)
                and pkt[TCP].flags & 0x12 == 0x02  # SYN set, ACK clear
                and pkt[TCP].dport == SERVER_PORT
                and (dst_port_hint is None or pkt[TCP].sport == dst_port_hint)
            )

        results = []
        ready = threading.Event()

        def _sniff():
            ready.set()
            pkts = sniff(iface=TUN_IFACE, lfilter=is_syn, count=count, timeout=timeout)
            results.extend(pkts)

        t = threading.Thread(target=_sniff)
        t.start()
        ready.wait()
        time.sleep(0.05)  # let sniff arm before stack fires
        return t, results

    def test_syn_exponential_backoff(self):
        """
        Stack sends a SYN, we never reply.
        Expected gaps between consecutive SYNs: 1s, 2s, 4s, 8s
        (original + 4 retransmits = 5 packets total).
        """
        NUM_RETRANSMITS = 4
        DELTA = 0.3

        t, results = self._collect_syns(None, count=NUM_RETRANSMITS + 1, timeout=30)
        t.join()

        self.assertEqual(
            len(results),
            NUM_RETRANSMITS + 1,
            f"Expected {NUM_RETRANSMITS + 1} SYNs, got {len(results)}",
        )

        # All retransmits must carry identical sport / seq
        sport = results[0][TCP].sport
        seq = results[0][TCP].seq
        for i, pkt in enumerate(results[1:], 1):
            self.assertEqual(
                pkt[TCP].sport,
                sport,
                f"Packet {i}: sport changed ({pkt[TCP].sport} != {sport})",
            )
            self.assertEqual(
                pkt[TCP].seq, seq, f"Packet {i}: SEQ changed ({pkt[TCP].seq} != {seq})"
            )

        # Verify doubling gaps
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


if __name__ == "__main__":
    unittest.main()
