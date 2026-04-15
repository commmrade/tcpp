import queue
import threading
import time
import unittest

from scapy.all import send, sniff
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

TUN_IFACE = "tun1"
DST_IP = "10.0.0.2"
SRC_IP = "10.0.0.1"
DST_PORT = 8090

SEQ_INIT = 1000

_send_queue = queue.Queue()


def _sender_loop():
    """Dedicated thread that sends all packets. Avoids send() inside sniff() callbacks."""
    while True:
        pkt = _send_queue.get()
        if pkt is None:
            return
        send(pkt, iface=TUN_IFACE, verbose=False)


def queued_send(pkt):
    _send_queue.put(pkt)


def make_ack(our_seq, client_port, ack_seq, window=65535):
    return IP(src=SRC_IP, dst=DST_IP) / TCP(
        sport=DST_PORT,
        dport=client_port,
        seq=our_seq,
        ack=ack_seq,
        flags="A",
        window=window,
    )


def do_handshake():
    def is_syn(pkt):
        return (
            pkt.haslayer(TCP)
            and pkt[TCP].flags & 0x02 != 0
            and pkt[TCP].flags & 0x10 == 0
            and pkt[TCP].dport == DST_PORT
        )

    results = []
    ready = threading.Event()

    def _sniff():
        ready.set()
        pkts = sniff(iface=TUN_IFACE, lfilter=is_syn, count=1, timeout=15)
        results.extend(pkts)

    t = threading.Thread(target=_sniff)
    t.start()
    ready.wait()
    time.sleep(0.05)
    t.join()

    assert len(results) == 1, "No SYN received"
    syn = results[0]

    client_seq = syn[TCP].seq
    client_port = syn[TCP].sport
    server_seq = SEQ_INIT

    queued_send(
        IP(src=SRC_IP, dst=DST_IP)
        / TCP(
            sport=DST_PORT,
            dport=client_port,
            seq=server_seq,
            ack=client_seq + 1,
            flags="SA",
            window=65535,
        )
    )

    def is_ack(pkt):
        return (
            pkt.haslayer(TCP)
            and pkt[TCP].flags & 0x10 != 0
            and not pkt.haslayer(Raw)
            and pkt[TCP].dport == DST_PORT
            and pkt[TCP].sport == client_port
        )

    ack_results = []
    ack_ready = threading.Event()

    def _sniff_ack():
        ack_ready.set()
        pkts = sniff(iface=TUN_IFACE, lfilter=is_ack, count=1, timeout=10)
        ack_results.extend(pkts)

    t2 = threading.Thread(target=_sniff_ack)
    t2.start()
    ack_ready.wait()
    time.sleep(0.05)
    t2.join()

    assert len(ack_results) == 1, "No ACK received after SYNACK"

    our_seq = server_seq + 1
    print(f"Handshake done: our_seq={our_seq}, client_port={client_port}")
    return our_seq, client_port


class TestTcpZeroWindowProbe(unittest.TestCase):
    def test_zwp_timing(self):
        NUM_PROBES = 3
        DELTA = 0.35

        sender = threading.Thread(target=_sender_loop, daemon=True)
        sender.start()

        try:
            our_seq, client_port = do_handshake()

            # ── Step 1: drain data segments, ACK each immediately ─────────────
            received_data = []
            drain_done = threading.Event()

            def is_sender_data(pkt):
                return (
                    pkt.haslayer(TCP)
                    and pkt.haslayer(Raw)
                    and pkt[IP].src == DST_IP
                    and pkt[TCP].sport == client_port
                    and pkt[TCP].dport == DST_PORT
                )

            def on_data(pkt):
                ack_seq = pkt[TCP].seq + len(pkt[Raw].load)
                queued_send(make_ack(our_seq, client_port, ack_seq, window=65535))
                print(
                    f"ACKed data: seq={pkt[TCP].seq}, len={len(pkt[Raw].load)}, ack={ack_seq}"
                )
                received_data.append(pkt)

            def drain_thread():
                drain_done.set()
                sniff(
                    iface=TUN_IFACE,
                    lfilter=is_sender_data,
                    prn=on_data,
                    count=3,
                    timeout=10,
                )

            t1 = threading.Thread(target=drain_thread)
            t1.start()
            drain_done.wait()
            time.sleep(0.05)
            t1.join()

            self.assertGreater(len(received_data), 0, "No data received from sender")

            last_seg = received_data[-1]
            client_seq_after = last_seg[TCP].seq + len(last_seg[Raw].load)

            # ── Step 2: send window=0 ─────────────────────────────────────────
            queued_send(make_ack(our_seq, client_port, client_seq_after, window=0))
            print("Sent window=0 — sender should start probing")

            # ── Step 3: collect ZWPs, ACK each with window=0 ─────────────────
            probe_results = []
            probe_ready = threading.Event()

            def is_zwp(pkt):
                return (
                    pkt.haslayer(TCP)
                    and pkt.haslayer(Raw)
                    and pkt[IP].src == DST_IP
                    and pkt[TCP].sport == client_port
                    and pkt[TCP].dport == DST_PORT
                    and len(pkt[Raw].load) == 1
                )

            def on_probe(pkt):
                queued_send(make_ack(our_seq, client_port, pkt[TCP].seq, window=0))
                probe_results.append(pkt)
                print(
                    f"Probe {len(probe_results) - 1}: seq={pkt[TCP].seq}, time={pkt.time:.3f}"
                )

            def probe_thread():
                probe_ready.set()
                sniff(
                    iface=TUN_IFACE,
                    lfilter=is_zwp,
                    prn=on_probe,
                    count=NUM_PROBES,
                    timeout=30,
                )

            t2 = threading.Thread(target=probe_thread)
            t2.start()
            probe_ready.wait()
            t2.join()

            self.assertEqual(
                len(probe_results),
                NUM_PROBES,
                f"Expected {NUM_PROBES} ZWPs, got {len(probe_results)}",
            )

            probe_seq = probe_results[0][TCP].seq
            for i, pkt in enumerate(probe_results):
                self.assertEqual(
                    pkt[TCP].seq,
                    probe_seq,
                    f"Probe {i} seq={pkt[TCP].seq} != {probe_seq}",
                )

            expected_gap = (
                2.0  # gap between probe 0 and probe 1 is already the second interval
            )
            for i in range(1, NUM_PROBES):
                gap = probe_results[i].time - probe_results[i - 1].time
                print(f"Gap {i}: {gap:.3f}s (expected ~{expected_gap:.1f}s)")
                self.assertAlmostEqual(
                    gap,
                    expected_gap,
                    delta=DELTA,
                    msg=f"Gap {i} was {gap:.3f}s, expected ~{expected_gap:.1f}s",
                )
                expected_gap *= 2

            # ── Step 4: reopen window ─────────────────────────────────────────
            last_probe = probe_results[-1]
            queued_send(
                make_ack(our_seq, client_port, last_probe[TCP].seq + 1, window=100)
            )
            print("Window reopened — waiting for one data segment")

            final_data = []
            final_ready = threading.Event()

            def is_post_zwp_data(pkt):
                return (
                    pkt.haslayer(TCP)
                    and pkt.haslayer(Raw)
                    and pkt[IP].src == DST_IP
                    and pkt[TCP].sport == client_port
                    and pkt[TCP].dport == DST_PORT
                )

            def sniff_final():
                final_ready.set()
                pkts = sniff(
                    iface=TUN_IFACE, lfilter=is_post_zwp_data, count=1, timeout=5
                )
                final_data.extend(pkts)

            t3 = threading.Thread(target=sniff_final)
            t3.start()
            final_ready.wait()
            time.sleep(0.05)
            t3.join()

            self.assertEqual(
                len(final_data), 1, "Did not receive post-ZWP data segment"
            )
            print(
                f"Post-ZWP data: seq={final_data[0][TCP].seq}, len={len(final_data[0][Raw].load)}"
            )
            print("Test passed")

        finally:
            _send_queue.put(None)
            sender.join()


if __name__ == "__main__":
    unittest.main()
