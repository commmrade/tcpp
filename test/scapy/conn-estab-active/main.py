import threading
import time
import unittest

from scapy.all import IP, TCP, send, sniff

TUN_IFACE = "tun1"
MY_IP = "10.0.0.1"  # us (server)
CLIENT_IP = "10.0.0.2"  # their TCP
MY_PORT = 8090
server_seq = 5000

captured = {}


def wait_for(filter_fn, timeout=5):
    result = []

    def _sniff():
        r = sniff(
            iface=TUN_IFACE, lfilter=filter_fn, count=1, timeout=timeout, promisc=False
        )
        result.extend(r)

    t = threading.Thread(target=_sniff)
    t.start()
    time.sleep(0.5)
    return t, result


class TestTcpServerSide(unittest.TestCase):
    def test_passive_open(self):
        seq = server_seq

        # ── Wait for SYN ─────────────────────────────────────────────
        def filter_syn(pkt):
            return (
                IP in pkt
                and TCP in pkt
                and pkt[IP].src == CLIENT_IP
                and pkt[TCP].dport == MY_PORT
                and (pkt[TCP].flags & 0x02) == 0x02  # SYN
                and (pkt[TCP].flags & 0x10) == 0x00  # not ACK
            )

        print("Waiting for SYN...")
        t, syn_result = wait_for(filter_syn, timeout=10)
        t.join()
        self.assertTrue(syn_result, "No SYN received")

        syn = syn_result[0]
        client_port = syn[TCP].sport
        client_seq = syn[TCP].seq
        print(f"SYN received from port {client_port}, seq={client_seq}")

        # ── Send SYN-ACK ─────────────────────────────────────────────
        def filter_ack(pkt):
            return (
                IP in pkt
                and TCP in pkt
                and pkt[IP].src == CLIENT_IP
                and pkt[TCP].dport == MY_PORT
                and pkt[TCP].sport == client_port
                and (pkt[TCP].flags & 0x10) == 0x10  # ACK
                and (pkt[TCP].flags & 0x02) == 0x00  # not SYN
            )

        t, ack_result = wait_for(filter_ack, timeout=5)

        synack_pkt = IP(src=MY_IP, dst=CLIENT_IP) / TCP(
            sport=MY_PORT, dport=client_port, flags="SA", seq=seq, ack=client_seq + 1
        )
        send(synack_pkt, verbose=False)
        print(f"SYN-ACK sent, seq={seq}, ack={client_seq + 1}")

        t.join()
        self.assertTrue(ack_result, "No ACK received")

        ack = ack_result[0]
        self.assertEqual(ack[TCP].ack, seq + 1)
        print("ACK received — handshake complete!")
        seq += 1


if __name__ == "__main__":
    unittest.main()
