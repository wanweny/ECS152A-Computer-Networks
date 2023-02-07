import ipaddress
from shutil import register_archive_format
import dpkt
import socket
from datetime import datetime


# https://dpkt.readthedocs.io/en/latest/_modules/examples/print_packets.html
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

f = open('project1_part2.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)
ip_dic = {}
res_dic = {}
time_dic = []
iptime_dic={}
endpoint_dic = {}
http_count = 0
https_count = 0
dns_count = 0
ftp_count = 0
ssh_count = 0
dhcp_count = 0
telnet_count = 0 
smtp_count = 0
pop3_count = 0
ntp_count = 0
icmp_count = 0
igmp_count = 0


for ts, buf in pcap:
    time_dic.append(ts)
    # link layer
    eth = dpkt.ethernet.Ethernet(buf)
    if not isinstance(eth.data, dpkt.ip.IP):
        continue

    # network layer
    ip = eth.data
    
    if isinstance(ip.data, dpkt.icmp.ICMP):
        icmp_count+=1
        continue
    if isinstance(ip.data, dpkt.igmp.IGMP):
        igmp_count+=1
        continue
    
    
    start_ip = ipaddress.IPv4Address('10.42.0.2')
    end_ip = ipaddress.IPv4Address('10.42.0.255')
    if int(ipaddress.IPv4Address(ip.src)) in range(int(start_ip), int(end_ip)):
        if inet_to_str(ip.src) not in ip_dic:
            ip_dic[inet_to_str(ip.src)] = 1
        else:
            ip_dic[inet_to_str(ip.src)] += 1
        if inet_to_str(ip.src) not in iptime_dic:
            iptime_dic[inet_to_str(ip.src)] = [ts]
        else:
            iptime_dic[inet_to_str(ip.src)].append(ts)

        if inet_to_str(ip.dst) not in endpoint_dic:
            endpoint_dic[inet_to_str(ip.dst)] = [ipaddress.IPv4Address(ip.src)]
        else:
            if not ipaddress.IPv4Address(ip.src) in endpoint_dic[inet_to_str(ip.dst)]:
                endpoint_dic[inet_to_str(ip.dst)].append(ipaddress.IPv4Address(ip.src))
            else:
                continue

    elif int(ipaddress.IPv4Address(ip.dst)) in range(int(start_ip), int(end_ip)):
        if inet_to_str(ip.dst) not in res_dic:
            res_dic[inet_to_str(ip.dst)] = 1
        else:
            res_dic[inet_to_str(ip.dst)] += 1
    else:
        continue
    # transport layer
    tcp = ip.data

    # application layer content
    appData = tcp.data



    # req or res
    if len(appData) > 0 :
        # check for HTTP packets
        if tcp.dport == 80 or tcp.sport == 80:
            http_count += 1
        # check for HTTPS packets
        elif tcp.dport == 443 or tcp.sport == 443:
            https_count += 1
        # DNS
        elif tcp.dport == 53 or tcp.sport == 53:
            dns_count += 1
        # FTP 
        elif tcp.dport == 20 or tcp.dport == 21 or tcp.sport == 20 or tcp.sport == 21:
            ftp_count += 1
        # SSH  
        elif tcp.dport == 22 or tcp.sport == 22:
            ssh_count += 1
        # DHCP 
        elif tcp.dport == 67 or tcp.dport == 68 or tcp.sport == 67 or tcp.sport == 68:
            dhcp_count += 1
        # TELNET 
        elif tcp.dport == 23 or tcp.sport == 23:
            telnet_count += 1
        # SMTP
        elif tcp.dport == 25 or tcp.sport == 25:
            smtp_count += 1 
        # POP3
        elif tcp.dport == 110 or tcp.sport == 110:
            pop3_count += 1
        # NTP
        elif tcp.dport == 123 or tcp.sport == 110:
            ntp_count += 1
        else: 
            continue
    else:
        # should we count empty packets?
        if tcp.dport == 80 or tcp.sport == 80:
            http_count += 1
        
        elif tcp.dport == 443 or tcp.sport == 443:
            https_count += 1
        else:
            continue
print("question1 number of device", len(ip_dic))
ip_max = max(ip_dic,key = ip_dic.get)
print("question 2 device ", ip_max, " that send most packets",  ip_dic[ip_max])
ip_max2 = max(res_dic,key = res_dic.get)
print("question 3 device ", ip_max2, " that receive most packets",  res_dic[ip_max2])
print("question 4 dst ip address with more than one device sends out a network packet to it: ")
for key in endpoint_dic:
    if len(endpoint_dic[key])>=2:
        print(key)
print("question 5")
print("HTTP packets = ", http_count)
print("HTTPS packets = ", https_count)
print("DNS packets = ", dns_count)
print("FTP packets = ", ftp_count) 
print("SSH packets = ", ssh_count)
print("DHCP packets = ", dhcp_count)
print("TELNET packets = ", telnet_count)
print("SMTP packets = ", smtp_count)
print("POP3 packets = ", pop3_count)
print("NTP packets = ", ntp_count)
print("ICMP packets = ", icmp_count)
print("IGMP packets = ", igmp_count)


# print("start time: ",min(time_dic))
# print("end time: ", max(time_dic))
print("question 6 duration: ", round((max(time_dic)-min(time_dic))/60), "min")
print("question 7")
for key in iptime_dic:
    print("ip address: ",key, "start time: ",datetime.fromtimestamp(min(iptime_dic[key]))
    , " end time: ", datetime.fromtimestamp(max(iptime_dic[key])))
