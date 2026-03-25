import threading
import time
import unittest

from scapy.all import *
from scapy.layers.inet import IP, TCP

TUN_IFACE = "tun1"
DST_IP = "10.0.0.2"
SRC_IP = "10.0.0.1"
DST_PORT = 8090
SRC_PORT = 54695
seq_num = 1000


def do_handshake(src_port):
    def is_synack(pkt):
        return (
            pkt.haslayer(TCP)
            and pkt[TCP].flags & 0x12 == 0x12
            and pkt[TCP].sport == DST_PORT
            and pkt[TCP].dport == src_port
        )

    results = []
    ready = threading.Event()

    def _sniff():
        ready.set()
        pkts = sniff(iface=TUN_IFACE, lfilter=is_synack, count=1, timeout=10)
        results.extend(pkts)

    t = threading.Thread(target=_sniff)
    t.start()
    ready.wait()
    time.sleep(0.05)

    send(
        IP(src=SRC_IP, dst=DST_IP)
        / TCP(sport=src_port, dport=DST_PORT, seq=seq_num, flags="S"),
        iface=TUN_IFACE,
        verbose=False,
    )
    t.join()

    assert len(results) == 1, "Handshake failed: no SYNACK"
    synack = results[0]
    our_seq = synack[TCP].ack
    server_seq = synack[TCP].seq + 1

    send(
        IP(src=SRC_IP, dst=DST_IP)
        / TCP(
            sport=src_port,
            dport=DST_PORT,
            seq=our_seq,
            ack=server_seq,
            flags="A",
        ),
        iface=TUN_IFACE,
        verbose=False,
    )
    print(f"Handshake complete: our_seq={our_seq}, server_seq={server_seq}")
    return our_seq, server_seq


def sniff_ack(src_port, timeout=5):
    """Wait for a pure ACK (or ACK+data) from the stack for our port."""

    def is_ack(pkt):
        return (
            pkt.haslayer(TCP)
            and pkt[TCP].flags & 0x10  # ACK bit set
            and pkt[TCP].sport == DST_PORT
            and pkt[TCP].dport == src_port
        )

    result = []
    ready = threading.Event()

    def _sniff():
        ready.set()
        pkts = sniff(iface=TUN_IFACE, lfilter=is_ack, count=1, timeout=timeout)
        result.extend(pkts)

    t = threading.Thread(target=_sniff)
    t.start()
    ready.wait()
    time.sleep(0.05)
    return t, result


class TestDuplicateSegmentHandling(unittest.TestCase):
    def test_retransmit_already_acked_segment(self):
        """
        Simulate a lost ACK from our side:
          1. Send a data segment to the stack.
          2. Stack sends ACK — we receive it but pretend we didn't (ignore it).
          3. Retransmit the exact same segment (same seq, same payload).
          4. Stack must respond with ACK again and not break.
          5. Send next segment with advanced seq — stack must ACK it correctly,
             proving it didn't double-count the duplicate.
        """
        our_seq, server_seq = do_handshake(SRC_PORT)

        PAYLOAD = b"hello"

        # ── Step 1: arm sniffer, send segment ────────────────────────────────
        t1, ack1_result = sniff_ack(SRC_PORT)

        seg = (
            IP(src=SRC_IP, dst=DST_IP)
            / TCP(
                sport=SRC_PORT,
                dport=DST_PORT,
                seq=our_seq,
                ack=server_seq,
                flags="PA",
            )
            / Raw(load=PAYLOAD)
        )

        send(seg, iface=TUN_IFACE, verbose=False)
        print(f"Sent original segment: seq={our_seq}, payload={PAYLOAD}")

        t1.join()
        self.assertEqual(len(ack1_result), 1, "Stack did not ACK the original segment")

        ack1 = ack1_result[0]
        expected_ack_no = our_seq + len(PAYLOAD)
        self.assertEqual(
            ack1[TCP].ack,
            expected_ack_no,
            f"ACK number wrong: got {ack1[TCP].ack}, expected {expected_ack_no}",
        )
        print(f"Got ACK (ignored — simulating loss): ack={ack1[TCP].ack}")

        # ── Step 2: retransmit the exact same segment (ACK "lost") ───────────
        time.sleep(0.1)  # small pause, like a real retransmit timer firing

        t2, ack2_result = sniff_ack(SRC_PORT)

        send(seg, iface=TUN_IFACE, verbose=False)  # identical packet, same seq
        print(f"Retransmitted duplicate: seq={our_seq}, payload={PAYLOAD}")

        t2.join()
        self.assertEqual(
            len(ack2_result),
            1,
            "Stack did not ACK the duplicate segment — expected a repeat ACK",
        )

        ack2 = ack2_result[0]
        self.assertEqual(
            ack2[TCP].ack,
            expected_ack_no,
            f"Duplicate ACK number wrong: got {ack2[TCP].ack}, expected {expected_ack_no} "
            f"(stack may have double-counted the payload)",
        )
        print(f"Got ACK for duplicate: ack={ack2[TCP].ack} ✓")

        # ── Step 3: advance seq normally — proves stack state is intact ───────
        PAYLOAD2 = b"world"
        next_seq = our_seq + len(PAYLOAD)  # advance past first payload, NOT doubled

        t3, ack3_result = sniff_ack(SRC_PORT)

        seg2 = (
            IP(src=SRC_IP, dst=DST_IP)
            / TCP(
                sport=SRC_PORT,
                dport=DST_PORT,
                seq=next_seq,
                ack=server_seq,
                flags="PA",
            )
            / Raw(load=PAYLOAD2)
        )

        send(seg2, iface=TUN_IFACE, verbose=False)
        print(f"Sent next segment: seq={next_seq}, payload={PAYLOAD2}")

        t3.join()
        self.assertEqual(len(ack3_result), 1, "Stack did not ACK the follow-up segment")

        ack3 = ack3_result[0]
        expected_ack3 = next_seq + len(PAYLOAD2)
        self.assertEqual(
            ack3[TCP].ack,
            expected_ack3,
            f"Follow-up ACK wrong: got {ack3[TCP].ack}, expected {expected_ack3} "
            f"(seq window corrupted by duplicate?)",
        )
        print(f"Got ACK for follow-up: ack={ack3[TCP].ack} ✓ — stack state intact")


if __name__ == "__main__":
    unittest.main()
