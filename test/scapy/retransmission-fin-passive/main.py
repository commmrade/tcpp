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

    our_seq = synack[TCP].ack  # server ack'd our SYN, so this is our next seq
    server_seq = synack[TCP].seq + 1  # we ack server's SYN

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


class TestTcpFinAckRetrans(unittest.TestCase):
    def test_fin(self):
        """Send FINACK, server ACKs it, then server sends FINACK — verify it arrives."""
        our_seq, server_seq = do_handshake(SRC_PORT)

        def is_ack(pkt):
            return (
                pkt.haslayer(TCP)
                and pkt[TCP].flags & 0x10 == 0x10  # ACK
                and pkt[TCP].flags & 0x01 == 0x00  # not FIN
                and pkt[TCP].sport == DST_PORT
                and pkt[TCP].dport == SRC_PORT
            )

        def is_finack(pkt):
            return (
                pkt.haslayer(TCP)
                and pkt[TCP].flags & 0x11 == 0x11  # FIN + ACK
                and pkt[TCP].sport == DST_PORT
                and pkt[TCP].dport == SRC_PORT
            )

        # Start sniffers for ACK and server's FINACK before sending our FINACK
        ack_results = []
        finack_results = []
        ack_ready = threading.Event()
        finack_ready = threading.Event()

        def sniff_ack():
            ack_ready.set()
            pkts = sniff(iface=TUN_IFACE, lfilter=is_ack, count=1, timeout=10)
            ack_results.extend(pkts)

        def sniff_finack():
            finack_ready.set()
            pkts = sniff(iface=TUN_IFACE, lfilter=is_finack, count=1, timeout=10)
            finack_results.extend(pkts)

        t_ack = threading.Thread(target=sniff_ack)
        t_finack = threading.Thread(target=sniff_finack)
        t_ack.start()
        t_finack.start()
        ack_ready.wait()
        finack_ready.wait()
        time.sleep(0.05)

        # Send our FINACK
        finack = IP(src=SRC_IP, dst=DST_IP) / TCP(
            sport=SRC_PORT,
            dport=DST_PORT,
            seq=our_seq,
            ack=server_seq,
            flags="FA",
        )
        send(finack, iface=TUN_IFACE, verbose=False)
        print("Sent FINACK")

        t_ack.join()
        t_finack.join()

        # Verify server sent ACK for our FINACK
        self.assertEqual(len(ack_results), 1, "Did not receive ACK for our FINACK")
        print(
            f"Server ACK received: seq={ack_results[0][TCP].seq}, ack={ack_results[0][TCP].ack}"
        )

        # Verify server sent its own FINACK
        self.assertEqual(len(finack_results), 1, "Did not receive server FINACK")
        server_finack = finack_results[0]
        print(
            f"Server FINACK received: seq={server_finack[TCP].seq}, ack={server_finack[TCP].ack}"
        )

        # ACK the server's FINACK to cleanly close
        final_ack = IP(src=SRC_IP, dst=DST_IP) / TCP(
            sport=SRC_PORT,
            dport=DST_PORT,
            seq=server_finack[TCP].ack,
            ack=server_finack[TCP].seq + 1,
            flags="A",
        )
        send(final_ack, iface=TUN_IFACE, verbose=False)
        print("Final ACK sent — connection closed")

    def test_fin_exponential_backoff(self):
        """Send FINACK, ignore server's FINACK, verify exponential backoff retransmits."""
        NEW_SRC_PORT = SRC_PORT + 1
        NUM_RETRANSMITS = 4  # original + 4 retransmits = 5 packets total
        DELTA = 0.3

        our_seq, server_seq = do_handshake(NEW_SRC_PORT)

        def is_server_finack(pkt):
            return (
                pkt.haslayer(TCP)
                and pkt[TCP].flags & 0x11 == 0x11  # FIN + ACK
                and pkt[TCP].sport == DST_PORT
                and pkt[TCP].dport == NEW_SRC_PORT
            )

        results = []
        sniffer_ready = threading.Event()

        def sniff_all():
            sniffer_ready.set()
            pkts = sniff(
                iface=TUN_IFACE,
                lfilter=is_server_finack,
                count=NUM_RETRANSMITS + 1,
                timeout=30,
            )
            results.extend(pkts)

        t = threading.Thread(target=sniff_all)
        t.start()
        sniffer_ready.wait()
        time.sleep(0.05)

        # Send our FINACK to trigger the server to start closing
        finack = IP(src=SRC_IP, dst=DST_IP) / TCP(
            sport=NEW_SRC_PORT,
            dport=DST_PORT,
            seq=our_seq,
            ack=server_seq,
            flags="FA",
        )
        send(finack, iface=TUN_IFACE, verbose=False)
        print("Sent FINACK — waiting for server FINACK retransmits...")

        t.join()

        self.assertEqual(
            len(results),
            NUM_RETRANSMITS + 1,
            f"Expected {NUM_RETRANSMITS + 1} FINACKs, got {len(results)}",
        )

        # Verify exponential backoff gaps: 1s, 2s, 4s, 8s
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

        # ACK the last FINACK to cleanly close
        server_finack = results[-1]
        final_ack = IP(src=SRC_IP, dst=DST_IP) / TCP(
            sport=NEW_SRC_PORT,
            dport=DST_PORT,
            seq=server_finack[TCP].ack,
            ack=server_finack[TCP].seq + 1,
            flags="A",
        )
        send(final_ack, iface=TUN_IFACE, verbose=False)
        print("Final ACK sent — connection closed")


if __name__ == "__main__":
    unittest.main()
