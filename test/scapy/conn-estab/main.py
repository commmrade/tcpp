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


def filter_synack(pkt):
    return (
        IP in pkt
        and TCP in pkt
        and pkt[IP].src == DST_IP
        and pkt[TCP].dport == SPORT
        and (pkt[TCP].flags & 0x12) == 0x12
    )


def do_sniff():
    global result_packet
    result_packet = sniff(
        iface=TUN_IFACE,
        lfilter=filter_synack,
        count=1,
        timeout=5,
        promisc=False,
    )


class TestTcpConnEstab(unittest.TestCase):
    def test_conn(self):
        # Start sniff thread FIRST
        t = threading.Thread(target=do_sniff)
        t.start()

        # Small delay to let sniff start up
        time.sleep(0.5)

        # NOW send SYN
        syn_pkt = IP(dst=DST_IP, src=SRC_IP) / TCP(
            dport=DST_PORT, sport=SPORT, flags="S", seq=seq_num
        )
        send(syn_pkt, verbose=False)
        print(f"SYN sent to {DST_IP}:{DST_PORT}")

        print("Waiting for SYN-ACK...")
        t.join()

        if not result_packet:
            print("No SYN-ACK received.")
            exit(1)

        ack_num = result_packet[0][TCP].seq + 1
        seq_nxt = seq_num + 1

        self.assertEqual(result_packet[0][TCP].ack, seq_num + 1)
        self.assertTrue("S" in result_packet[0][TCP].flags)
        self.assertTrue("A" in result_packet[0][TCP].flags)

        ack_pkt = IP(src=SRC_IP, dst=DST_IP) / TCP(
            dport=DST_PORT, sport=SPORT, flags="A", seq=seq_nxt, ack=ack_num
        )
        send(ack_pkt, verbose=False)
        print("ACK sent, handshake complete!")


if __name__ == "__main__":
    unittest.main()
