# Entire code is written by Hardik Arora Comp CSS Batch1 CSS roll no: 12



from scapy.all import *
from time import sleep
import os

class Sniff:
    i = 1

    @staticmethod
    def sniffer(pkt):
        if pkt.haslayer(IP):
            print("[" + str(Sniff.i) + "]\tSource IP: %s  TO  Dest IP: %s  |  Source MAC: %s  TO  Dest MAC: %s  |  Proto: %s  |  PORT: %s\n" % (pkt[IP].src, pkt[IP].dst,pkt[Ether].src,pkt[Ether].dst,pkt[IP].proto, pkt[IP].dport))
            Sniff.i += 1


if __name__ == '__main__':
    os.system('clear')

#*********** Future Code for selecting filters ***********************
    # filter = raw_input("Select a protocol you want (optional): ").lower()
    # if filter:
    #     pkt = sniff(filter=filter, prn = Sniff.sniffer)
    # else:
    #     pkt = sniff(prn = Sniff.sniffer)
#**********************************************************************

    print "########Press ctrl + c to stop collecting packets!!!!!!!\n"
    for i in range(3, 0, -1):
        print "Packet Listening will start in ", i, " seconds....."
        sleep(1)

    print "\n\n" + "*" * 50 + "\n\n"
    pkt = sniff(filter = 'tcp', count=500, prn=Sniff.sniffer) # sniffs packets untill keyboard interrupt is given
    if pkt:
        # Asking user if he/she wishes to see any packet in detail
        fil = raw_input("\n\n" + "*" * 50 + "\n\n"+"Do you want to filter the result and get details y/n: ").lower()

        if fil == 'y':
            while True:
                print "\n" + "*"*50 + "\n"
                number = input("Enter the Sr.no. of the packet you want the details from above(-1 for exit): ")
                if number == -1:
                    break
                else:
                    print "\n" + "*"*50 + "\n"
                    pkt[number-1].show() # displaying details of requested packet
                    if pkt[number-1][IP].dport == 80 or pkt[number-1][IP].dport == 443:
                        print "Payload: " + str(bytes(packet[TCP].payload))




