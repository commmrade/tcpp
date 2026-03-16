import threading
import time
import unittest

from scapy.all import IP, TCP, send, sniff

TUN_IFACE = "tun1"
DST_IP = "10.0.0.2"
SRC_IP = "10.0.0.1"
DST_PORT = 8090
SPORT = 54675
seq_num = 1000

result_packet = None


def do_sniff(filter_fn, timeout=5):
    return sniff(
        iface=TUN_IFACE, lfilter=filter_fn, count=1, timeout=timeout, promisc=False
    )


def sniff_for(filter_fn, timeout=5):
    result = []

    def _sniff():
        r = do_sniff(filter_fn, timeout)
        result.extend(r)

    t = threading.Thread(target=_sniff)
    t.start()
    time.sleep(0.5)
    return t, result


def filter_synack(pkt):
    return (
        IP in pkt
        and TCP in pkt
        and pkt[IP].src == DST_IP
        and pkt[TCP].dport == SPORT
        and (pkt[TCP].flags & 0x12) == 0x12  # SYN+ACK
    )


def filter_finack(pkt):
    return (
        IP in pkt
        and TCP in pkt
        and pkt[IP].src == DST_IP
        and pkt[TCP].dport == SPORT
        and (pkt[TCP].flags & 0x11) == 0x11  # FIN+ACK
    )


class TestTcpConnEstab(unittest.TestCase):
    def test_conn(self):
        seq = seq_num

        # ── 3-way handshake ──────────────────────────────────────────

        # 1. SYN
        t, synack_result = sniff_for(filter_synack)
        syn_pkt = IP(dst=DST_IP, src=SRC_IP) / TCP(
            dport=DST_PORT, sport=SPORT, flags="S", seq=seq
        )
        send(syn_pkt, verbose=False)
        print(f"SYN sent to {DST_IP}:{DST_PORT}")
        t.join()

        self.assertTrue(synack_result, "No SYN-ACK received")
        synack = synack_result[0]
        self.assertEqual(synack[TCP].ack, seq + 1)
        self.assertIn("S", synack[TCP].flags)
        self.assertIn("A", synack[TCP].flags)
        print("SYN-ACK received!")

        # 2. ACK
        server_seq = synack[TCP].seq
        seq += 1
        ack_pkt = IP(src=SRC_IP, dst=DST_IP) / TCP(
            dport=DST_PORT, sport=SPORT, flags="A", seq=seq, ack=server_seq + 1
        )
        send(ack_pkt, verbose=False)
        print("ACK sent — handshake complete!")

        # ── 4-way teardown ───────────────────────────────────────────
        # We initiate active close
        #
        #   Client            Server
        #     -- FIN+ACK -->
        #     <-- ACK ------
        #     <-- FIN+ACK --
        #     -- ACK ------>

        server_ack = server_seq + 1  # server's current ack (our next seq)

        # 3. FIN+ACK  (we initiate close)
        t, finack_result = sniff_for(filter_finack)
        fin_pkt = IP(src=SRC_IP, dst=DST_IP) / TCP(
            dport=DST_PORT, sport=SPORT, flags="FA", seq=seq, ack=server_ack
        )
        send(fin_pkt, verbose=False)
        print("FIN+ACK sent (active close)")
        seq += 1  # FIN consumes one seq
        t.join()

        self.assertTrue(finack_result, "No FIN+ACK from server received")
        server_fin = finack_result[0]
        self.assertIn("F", server_fin[TCP].flags)
        self.assertIn("A", server_fin[TCP].flags)
        print("Server FIN+ACK received!")

        # 4. Final ACK
        final_ack_pkt = IP(src=SRC_IP, dst=DST_IP) / TCP(
            dport=DST_PORT, sport=SPORT, flags="A", seq=seq, ack=server_fin[TCP].seq + 1
        )
        send(final_ack_pkt, verbose=False)
        print("Final ACK sent — connection closed!")


if __name__ == "__main__":
    unittest.main()
