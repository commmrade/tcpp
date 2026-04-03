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

    queued_send(make_seg(CLIENT_PORT, SERVER_PORT, isn, 0, "S", 65535))

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
    mss = 536
    for opt_name, opt_val in synack[TCP].options:
        if opt_name == "MSS":
            mss = opt_val
            break

    our_seq = isn + 1
    server_seq = server_isn + 1

    queued_send(make_seg(CLIENT_PORT, SERVER_PORT, our_seq, server_seq, "A", 65535))

    print(
        f"Handshake done: our_seq={our_seq}, server_seq={server_seq}, "
        f"server_wnd={server_wnd}, mss={mss}"
    )
    return our_seq, server_seq, server_wnd, mss


class TestTcpZeroWindowProbe(unittest.TestCase):
    def test_zwp_server_responds(self):
        NUM_PROBES = 3
        DELTA = 0.35
        OUR_WINDOW = 65535

        sender = threading.Thread(target=_sender_loop, daemon=True)
        sender.start()

        try:
            our_seq, server_seq, server_wnd, mss = do_handshake()

            # ── Step 1: flood data respecting server's window ─────────────────
            snd_una = our_seq
            snd_nxt = our_seq
            snd_wnd = server_wnd

            flood_acks = queue.Queue()
            flood_done = threading.Event()

            def is_server_ack(pkt):
                return (
                    pkt.haslayer(TCP)
                    and pkt[TCP].sport == SERVER_PORT
                    and pkt[TCP].dport == CLIENT_PORT
                    and pkt[TCP].flags & 0x10 != 0
                )

            def collect_flood_acks():
                while not flood_done.is_set():
                    pkts = sniff(
                        iface=TUN_IFACE,
                        lfilter=is_server_ack,
                        count=1,
                        timeout=0.5,
                    )
                    for pkt in pkts:
                        flood_acks.put(pkt)

            ack_thread = threading.Thread(target=collect_flood_acks, daemon=True)
            ack_thread.start()

            zero_wnd_seen = False

            while not zero_wnd_seen:
                while not flood_acks.empty():
                    ack_pkt = flood_acks.get_nowait()
                    acked = ack_pkt[TCP].ack
                    new_wnd = ack_pkt[TCP].window
                    if acked > snd_una:
                        snd_una = acked
                    snd_wnd = new_wnd
                    print(f"Flood ACK: snd_una={snd_una}, snd_wnd={snd_wnd}")
                    if snd_wnd == 0:
                        zero_wnd_seen = True
                        break

                if zero_wnd_seen:
                    break

                while snd_nxt < snd_una + snd_wnd:
                    available = (snd_una + snd_wnd) - snd_nxt
                    chunk = min(mss, available)
                    if chunk <= 0:
                        break
                    queued_send(
                        make_seg(
                            CLIENT_PORT,
                            SERVER_PORT,
                            seq=snd_nxt,
                            ack=server_seq,
                            flags="PA",
                            window=OUR_WINDOW,
                            payload=b"A" * chunk,
                        )
                    )
                    snd_nxt += chunk
                    time.sleep(0.002)

                time.sleep(0.01)

            flood_done.set()
            print(f"Window closed. snd_una={snd_una}, snd_nxt={snd_nxt}")

            # ── Step 2: ZWP probes (timed, verify backoff) ────────────────────
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
                    f"Probe ACK {len(probe_acks) - 1}: window={pkt[TCP].window}, "
                    f"time={pkt.time:.3f}"
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

            rto = 1.0
            for i in range(NUM_PROBES):
                time.sleep(rto)
                queued_send(
                    make_seg(
                        CLIENT_PORT,
                        SERVER_PORT,
                        seq=snd_una,
                        ack=server_seq,
                        flags="A",
                        window=OUR_WINDOW,
                        payload=b"Z",
                    )
                )
                print(f"Sent probe {i}: seq={snd_una}, rto={rto:.1f}s")
                rto *= 2

            tp.join()

            self.assertEqual(
                len(probe_acks),
                NUM_PROBES,
                f"Expected {NUM_PROBES} probe ACKs from server, got {len(probe_acks)}",
            )

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

            # ── Step 3: keep probing until window opens, then send data ───────
            # Server will eventually drain its buffer and advertise window > 0.
            # We must send a probe to elicit that update — it won't come unsolicited.
            print("Probing for window reopen...")

            reopened_wnd = 0
            probe_rto = rto  # continue backoff from where we left off
            max_recovery_probes = 10

            for i in range(max_recovery_probes):
                time.sleep(probe_rto)

                probe_ack_pkts = []
                rdy = threading.Event()

                def sniff_one_probe_ack():
                    rdy.set()
                    pkts = sniff(
                        iface=TUN_IFACE,
                        lfilter=is_probe_ack,
                        count=1,
                        timeout=probe_rto + 1.0,
                    )
                    probe_ack_pkts.extend(pkts)

                tr = threading.Thread(target=sniff_one_probe_ack)
                tr.start()
                rdy.wait()
                time.sleep(0.05)

                queued_send(
                    make_seg(
                        CLIENT_PORT,
                        SERVER_PORT,
                        seq=snd_una,
                        ack=server_seq,
                        flags="A",
                        window=OUR_WINDOW,
                        payload=b"Z",
                    )
                )
                print(f"Recovery probe {i}: seq={snd_una}, rto={probe_rto:.1f}s")

                tr.join()

                self.assertEqual(
                    len(probe_ack_pkts), 1, f"No ACK for recovery probe {i}"
                )
                ack_wnd = probe_ack_pkts[0][TCP].window
                print(f"Recovery probe ACK: window={ack_wnd}")

                if ack_wnd > 0:
                    reopened_wnd = ack_wnd
                    break

                probe_rto = min(probe_rto * 2, 60.0)

            self.assertGreater(
                reopened_wnd, 0, "Window never reopened after recovery probes"
            )
            print(f"Window reopened: {reopened_wnd} bytes")

            # ── Step 4: send a full MSS segment, verify ACK ───────────────────
            # snd_una is the probe seq; probe payload is 1 byte ("Z"), so
            # next seq is snd_una + 1.
            recovery_seq = snd_una
            send_len = min(mss, reopened_wnd)

            recovery_acks = []
            recovery_ready = threading.Event()

            def is_recovery_ack(pkt):
                return (
                    pkt.haslayer(TCP)
                    and pkt[TCP].sport == SERVER_PORT
                    and pkt[TCP].dport == CLIENT_PORT
                    and pkt[TCP].flags & 0x10 != 0
                    and pkt[TCP].ack == recovery_seq + send_len
                )

            def sniff_recovery_ack():
                recovery_ready.set()
                pkts = sniff(
                    iface=TUN_IFACE,
                    lfilter=is_recovery_ack,
                    count=1,
                    timeout=10,
                )
                recovery_acks.extend(pkts)

            tr = threading.Thread(target=sniff_recovery_ack)
            tr.start()
            recovery_ready.wait()
            time.sleep(0.05)

            queued_send(
                make_seg(
                    CLIENT_PORT,
                    SERVER_PORT,
                    seq=recovery_seq,
                    ack=server_seq,
                    flags="PA",
                    window=OUR_WINDOW,
                    payload=b"B" * send_len,
                )
            )
            print(f"Sent recovery segment: seq={recovery_seq}, len={send_len}")

            tr.join()

            self.assertEqual(
                len(recovery_acks),
                1,
                f"Recovery segment not ACKed (expected ack={recovery_seq + send_len})",
            )
            print(
                f"Recovery ACK: ack={recovery_acks[0][TCP].ack}, "
                f"window={recovery_acks[0][TCP].window}"
            )
            print("All tests passed")

        finally:
            _send_queue.put(None)
            sender.join()


if __name__ == "__main__":
    unittest.main()
