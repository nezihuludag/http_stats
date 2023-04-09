import sys
import re
from scapy.all import *


#GET hostname information from TCP payload
def get_hostname_from_payload(payload):
    http_header_regex = r"(?P<name>.*?): (?P<value>.*?)\r\n"
    start = payload.index(b"GET ") +4
    end = payload.index(b" HTTP/1.1")
    #url_path = payload[start:end].decode("utf8")
    http_header_raw = payload[:payload.index(b"\r\n\r\n") + 2 ]
    http_header_parsed = dict(re.findall(http_header_regex, http_header_raw.decode("utf8")))
    hostname = http_header_parsed["Host"]
    return hostname


def parse_pcap(pcap_path):
    # definitions of variables
    http_flows = {}
    http_bytes = 0
    hostnames = []

    # Read pcap file
    pcap_flow = rdpcap(pcap_path)

    # loop to check each packets
    for packets in pcap_flow:
        # check whether the packet is HTTP traffic
        if packets.haslayer('TCP') and packets.haslayer('Raw') and packets[TCP].dport == 80:
            # collect source and destination IPs and ports
            src_ip = packets[IP].src
            dst_ip = packets[IP].dst
            src_port = packets[TCP].sport
            dst_port = packets[TCP].dport
            # control to not make duplicated calculation
            if (src_ip, dst_ip, src_port, dst_port) not in http_flows:
                # if so , assign value as 0
                http_flows[(src_ip, dst_ip, src_port, dst_port)] = 0

            # update the flows
            http_flows[(src_ip, dst_ip, src_port, dst_port)] += len(packets[Raw])

            #debugging
            #print((src_ip, dst_ip, src_port, dst_port))
            #print(http_flows)
            #print(http_flows[(src_ip, dst_ip, src_port, dst_port)])

            # update http bytes
            http_bytes += len(packets[Raw])


    # Get Sessions from pcap_flows to find hostnames
    sessions = pcap_flow.sessions()

    # Find Hosts from HTTP sessions and append to array
    for session in sessions:
        for packet in sessions[session]:
            try:
                if packet[TCP].dport == 80:
                    payload = bytes(packet[TCP].payload)
                    hostname = get_hostname_from_payload(payload)
                    hostnames.append(str(hostname))
            except Exception as e:
                pass

    # Calculate Top visited Hostname from array
    top_visited_hostname = max(set(hostnames), key=hostnames.count)
    count = hostnames.count(top_visited_hostname)

    #Print Requested Values
    print('\n'f'HTTP traffic flows: {len(http_flows)}'+ '\n')
    print(f'HTTP Traffic Bytes: {http_bytes}'+ '\n')
    print(f"Top HTTP Hostname is: {top_visited_hostname},   which appears {count} times in traffic capture."+ '\n')

def main(arguments):
    if len(arguments) == 2:
        #if arguments[1] == "--pcap" :
        parse_pcap(arguments[1])


if __name__ == "__main__":
    main(sys.argv)