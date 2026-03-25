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


def send_and_recv(src_port, our_seq, server_seq, payload):
    """Send a data segment, wait for echo, return (echo_pkt, our_seq_after)."""

    def is_server_data(pkt):
        return (
            pkt.haslayer(TCP)
            and pkt.haslayer(Raw)
            and pkt[TCP].sport == DST_PORT
            and pkt[TCP].dport == src_port
        )

    result = []
    ready = threading.Event()

    def _sniff():
        ready.set()
        pkts = sniff(iface=TUN_IFACE, lfilter=is_server_data, count=1, timeout=10)
        result.extend(pkts)

    t = threading.Thread(target=_sniff)
    t.start()
    ready.wait()
    time.sleep(0.05)

    pkt = (
        IP(src=SRC_IP, dst=DST_IP)
        / TCP(
            sport=src_port,
            dport=DST_PORT,
            seq=our_seq,
            ack=server_seq,
            flags="PA",
        )
        / Raw(load=payload)
    )
    send(pkt, iface=TUN_IFACE, verbose=False)
    print(f"Sent: {payload}")
    t.join()

    assert len(result) == 1, f"Expected echo for {payload!r}, got nothing"
    echo = result[0]
    print(f"Echo received: seq={echo[TCP].seq}, payload={echo[Raw].load}")
    return echo, our_seq + len(payload)


def ack_pkt(src_port, our_seq, echo_pkt):
    """ACK a received data segment, returns updated server_seq."""
    echo_seq = echo_pkt[TCP].seq
    echo_len = len(echo_pkt[Raw].load)
    ack = IP(src=SRC_IP, dst=DST_IP) / TCP(
        sport=src_port,
        dport=DST_PORT,
        seq=our_seq,
        ack=echo_seq + echo_len,
        flags="A",
    )
    send(ack, iface=TUN_IFACE, verbose=False)
    print(f"ACKed up to server seq {echo_seq + echo_len}")
    return echo_seq + echo_len  # new server_seq


def recv_retransmits(src_port, count, timeout):
    """Collect `count` retransmitted data segments from the server."""

    def is_server_data(pkt):
        return (
            pkt.haslayer(TCP)
            and pkt.haslayer(Raw)
            and pkt[TCP].sport == DST_PORT
            and pkt[TCP].dport == src_port
        )

    result = []
    ready = threading.Event()

    def _sniff():
        ready.set()
        pkts = sniff(
            iface=TUN_IFACE, lfilter=is_server_data, count=count, timeout=timeout
        )
        result.extend(pkts)

    t = threading.Thread(target=_sniff)
    t.start()
    ready.wait()
    time.sleep(0.05)
    return t, result


class TestTcpDataRetransDouble(unittest.TestCase):
    def _assert_two_backoff_gaps(self, pkts, label):
        """Given 3 packets (original + 2 retransmits), assert gaps are ~1s then ~2s."""
        self.assertEqual(
            len(pkts),
            3,
            f"[{label}] Expected original + 2 retransmits (3 total), got {len(pkts)}",
        )

        first_seq = pkts[0][TCP].seq
        for i, pkt in enumerate(pkts):
            self.assertEqual(
                pkt[TCP].seq,
                first_seq,
                f"[{label}] Packet {i} seq={pkt[TCP].seq} != first={first_seq}, not a retransmit",
            )

        gap1 = pkts[1].time - pkts[0].time
        gap2 = pkts[2].time - pkts[1].time
        print(
            f"[{label}] Gap 1: {gap1:.3f}s (expected ~1.0s), Gap 2: {gap2:.3f}s (expected ~2.0s)"
        )

        self.assertAlmostEqual(
            gap1,
            1.0,
            delta=0.3,
            msg=f"[{label}] First retransmit gap {gap1:.3f}s, expected ~1s",
        )
        self.assertAlmostEqual(
            gap2,
            2.0,
            delta=0.3,
            msg=f"[{label}] Second retransmit gap {gap2:.3f}s, expected ~2s",
        )

    def test_two_rounds_of_backoff(self):
        """
        Handshake, then repeat twice:
          1. Send a segment, receive echo, ACK it.
          2. Send another segment, do NOT ACK — observe 2 retransmits (~1s, ~2s gaps).
        """
        SRC_PORT = 54680

        our_seq, server_seq = do_handshake(SRC_PORT)

        # ── Round 1 ──────────────────────────────────────────────────────────

        # Step 1a: send "ping1", receive echo, ACK it
        echo1a, our_seq = send_and_recv(SRC_PORT, our_seq, server_seq, b"ping1")
        server_seq = ack_pkt(SRC_PORT, our_seq, echo1a)

        # Step 1b: start sniffer BEFORE sending so we catch the original + retransmits
        t1, retrans1 = recv_retransmits(SRC_PORT, count=3, timeout=15)

        data1b = (
            IP(src=SRC_IP, dst=DST_IP)
            / TCP(
                sport=SRC_PORT,
                dport=DST_PORT,
                seq=our_seq,
                ack=server_seq,
                flags="PA",
            )
            / Raw(load=b"drop1")
        )
        send(data1b, iface=TUN_IFACE, verbose=False)
        print("Sent drop1 — going silent, waiting for 2 retransmits (~3s total)")

        t1.join()
        self._assert_two_backoff_gaps(retrans1, "Round1")

        # ACK the last retransmit to let the server advance before round 2
        last1 = retrans1[-1]
        our_seq_r1 = our_seq + len(b"drop1")
        server_seq = ack_pkt(SRC_PORT, our_seq_r1, last1)
        our_seq = our_seq_r1

        # ── Round 2 ──────────────────────────────────────────────────────────

        # Step 2a: send "ping2", receive echo, ACK it
        echo2a, our_seq = send_and_recv(SRC_PORT, our_seq, server_seq, b"ping2")
        server_seq = ack_pkt(SRC_PORT, our_seq, echo2a)

        # Step 2b: same pattern — send, ignore, collect 2 retransmits
        t2, retrans2 = recv_retransmits(SRC_PORT, count=3, timeout=15)

        data2b = (
            IP(src=SRC_IP, dst=DST_IP)
            / TCP(
                sport=SRC_PORT,
                dport=DST_PORT,
                seq=our_seq,
                ack=server_seq,
                flags="PA",
            )
            / Raw(load=b"drop2")
        )
        send(data2b, iface=TUN_IFACE, verbose=False)
        print("Sent drop2 — going silent, waiting for 2 retransmits (~3s total)")

        t2.join()
        self._assert_two_backoff_gaps(retrans2, "Round2")

        # Clean up
        last2 = retrans2[-1]
        final_ack = IP(src=SRC_IP, dst=DST_IP) / TCP(
            sport=SRC_PORT,
            dport=DST_PORT,
            seq=our_seq + len(b"drop2"),
            ack=last2[TCP].seq + len(last2[Raw].load),
            flags="A",
        )
        send(final_ack, iface=TUN_IFACE, verbose=False)
        print("Final ACK sent — done")


if __name__ == "__main__":
    unittest.main()
