import queue
import random
import threading
import time
import unittest

from scapy.all import send, sniff
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

TUN_IFACE = "tun1"
SERVER_IP = "10.0.0.2"
CLIENT_IP = "10.0.0.1"
SERVER_PORT = 8090
CLIENT_PORT = random.randint(49152, 65535)

MSS = 536

_send_queue = queue.Queue()


def _sender_loop():
    while True:
        pkt = _send_queue.get()
        if pkt is None:
            return
        send(pkt, iface=TUN_IFACE, verbose=False)


def queued_send(pkt):
    _send_queue.put(pkt)


def make_seg(sport, dport, seq, ack, flags, window, payload=b""):
    pkt = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        flags=flags,
        window=window,
    )
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt


def do_handshake():
    isn = random.randint(0, 2**32 - 1)

    # Send SYN
    queued_send(make_seg(CLIENT_PORT, SERVER_PORT, isn, 0, "S", 65535))

    # Wait for SYNACK
    def is_synack(pkt):
        return (
            pkt.haslayer(TCP)
            and pkt[TCP].flags & 0x12 == 0x12
            and pkt[TCP].sport == SERVER_PORT
            and pkt[TCP].dport == CLIENT_PORT
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
    t.join()

    assert len(results) == 1, "No SYNACK received"
    synack = results[0]

    server_isn = synack[TCP].seq
    server_wnd = synack[TCP].window
    our_seq = isn + 1
    server_seq = server_isn + 1

    # Send ACK to complete handshake
    queued_send(make_seg(CLIENT_PORT, SERVER_PORT, our_seq, server_seq, "A", 65535))

    print(
        f"Handshake done: our_seq={our_seq}, server_seq={server_seq}, server_wnd={server_wnd}"
    )
    return our_seq, server_seq, server_wnd


class TestTcpZeroWindowProbe(unittest.TestCase):
    def test_zwp_server_responds(self):
        NUM_PROBES = 3
        DELTA = 0.35

        sender = threading.Thread(target=_sender_loop, daemon=True)
        sender.start()

        try:
            our_seq, server_seq, server_wnd = do_handshake()

            # ── Step 1: flood data to fill server's recv buffer ───────────────
            # Server reads 512 bytes then sleeps 10s, so buffer fills quickly.
            # Send server_wnd + extra to ensure window closes.
            total_to_send = server_wnd + MSS * 4
            nxt = our_seq
            offset = 0

            while offset < total_to_send:
                chunk = min(MSS, total_to_send - offset)
                queued_send(
                    make_seg(
                        CLIENT_PORT,
                        SERVER_PORT,
                        seq=nxt,
                        ack=server_seq,
                        flags="PA",
                        window=65535,
                        payload=b"A" * chunk,
                    )
                )
                nxt += chunk
                offset += chunk
                time.sleep(0.002)

            print(f"Sent {total_to_send} bytes, waiting for window=0")

            # ── Step 2: wait for server to advertise window=0 ────────────────
            zero_wnd_pkts = []
            zero_ready = threading.Event()

            def is_zero_wnd(pkt):
                return (
                    pkt.haslayer(TCP)
                    and pkt[TCP].sport == SERVER_PORT
                    and pkt[TCP].dport == CLIENT_PORT
                    and pkt[TCP].window == 0
                )

            def sniff_zero():
                zero_ready.set()
                pkts = sniff(iface=TUN_IFACE, lfilter=is_zero_wnd, count=1, timeout=15)
                zero_wnd_pkts.extend(pkts)

            tz = threading.Thread(target=sniff_zero)
            tz.start()
            zero_ready.wait()
            time.sleep(0.05)
            tz.join()

            self.assertEqual(len(zero_wnd_pkts), 1, "Server never advertised window=0")
            snd_una = zero_wnd_pkts[0][TCP].ack
            print(f"Got window=0. Server ACKed up to {snd_una}")

            # ── Step 3: send ZWP probes, verify server ACKs each ─────────────
            probe_acks = []
            probe_ready = threading.Event()

            def is_probe_ack(pkt):
                return (
                    pkt.haslayer(TCP)
                    and pkt[TCP].sport == SERVER_PORT
                    and pkt[TCP].dport == CLIENT_PORT
                    and pkt[TCP].flags & 0x10 != 0
                )

            def on_probe_ack(pkt):
                probe_acks.append(pkt)
                print(
                    f"Probe ACK {len(probe_acks) - 1}: window={pkt[TCP].window}, time={pkt.time:.3f}"
                )

            def sniff_probe_acks():
                probe_ready.set()
                sniff(
                    iface=TUN_IFACE,
                    lfilter=is_probe_ack,
                    prn=on_probe_ack,
                    count=NUM_PROBES,
                    timeout=30,
                )

            tp = threading.Thread(target=sniff_probe_acks)
            tp.start()
            probe_ready.wait()
            time.sleep(0.05)

            # Send probes with exponential backoff: wait 1s, 2s, 4s before each
            rto = 1.0
            probe_send_times = []
            for i in range(NUM_PROBES):
                time.sleep(rto)
                queued_send(
                    make_seg(
                        CLIENT_PORT,
                        SERVER_PORT,
                        seq=snd_una,
                        ack=server_seq,
                        flags="A",
                        window=65535,
                        payload=b"Z",
                    )
                )
                probe_send_times.append(time.time())
                print(f"Sent probe {i}: seq={snd_una}, rto={rto:.1f}s")
                rto *= 2

            tp.join()

            self.assertEqual(
                len(probe_acks),
                NUM_PROBES,
                f"Expected {NUM_PROBES} probe ACKs from server, got {len(probe_acks)}",
            )

            # Verify inter-probe-ACK gaps match our send cadence (~1s, ~2s, ~4s)
            expected_gap = 2.0
            for i in range(1, NUM_PROBES):
                gap = probe_acks[i].time - probe_acks[i - 1].time
                print(f"ACK gap {i}: {gap:.3f}s (expected ~{expected_gap:.1f}s)")
                self.assertAlmostEqual(
                    gap,
                    expected_gap,
                    delta=DELTA,
                    msg=f"ACK gap {i} was {gap:.3f}s, expected ~{expected_gap:.1f}s",
                )
                expected_gap *= 2

            print("Test passed")

        finally:
            _send_queue.put(None)
            sender.join()


if __name__ == "__main__":
    unittest.main()
