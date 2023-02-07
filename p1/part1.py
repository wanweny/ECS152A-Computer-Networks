from ipaddress import ip_address
import dpkt
import socket

# https://dpkt.readthedocs.io/en/latest/_modules/examples/print_packets.html
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# open pcap file
filename = input("Enter file name: ")
f = open(filename, 'rb')
cur_ip = "168.150.22.248"
if filename == "tmz.pcap":
    cur_ip = "168.150.20.229"
pcap = dpkt.pcap.Reader(f)

total_count = 0
tcp_count = 0 
udp_count = 0
http_sent = 0 
https_sent = 0 
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
ip_dic={}

# go through pcap file
for ts, buf in pcap:
    # link layer
    eth = dpkt.ethernet.Ethernet(buf)

    # make sure it is IP packet
    if not isinstance(eth.data, dpkt.ip.IP):
        total_count += 1
        continue

    # network layer
    total_count += 1

    ip = eth.data
    if inet_to_str(ip.dst) not in ip_dic:
        ip_dic[inet_to_str(ip.dst)] = 1
    else:
        ip_dic[inet_to_str(ip.dst)] += 1



    # check for TCP and UDP packets
    if isinstance(ip.data, dpkt.tcp.TCP):
        tcp_count += 1
    elif isinstance(ip.data, dpkt.udp.UDP):
        udp_count += 1
    else:
        continue

    # transport layer
    tcp = ip.data

    # application layer content
    appData = tcp.data

# #2 only packets sent, #3 both
    # req or res
    if tcp.dport == 80 and inet_to_str(ip.src) == cur_ip:
        http_sent += 1
    # check for HTTPS packets SENT!!!
    elif tcp.dport == 443 and inet_to_str(ip.src) == cur_ip:
        https_sent += 1
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

print(filename)
print("question1: ")
print("TCP packets = ", tcp_count)
print("UDP packets = ", udp_count)
print("question2: ")
print("HTTP packets SENT ", http_sent)
print("HTTPS packets SENT ", https_sent)
print("question3: ")
print("Percent of HTTP packets: ", str(http_count/total_count*100) + '%')
print("Percent of HTTPS packets: ", str(https_count/total_count*100) + '%')
print("Percent of DNS packets: ", str(dns_count/total_count*100) + '%')
print("Percent of FTP packets: ", str(ftp_count/total_count*100) + '%')
print("Percent of SSH packets: ", str(ssh_count/total_count*100) + '%')
print("Percent of DHCP packets: ", str(dhcp_count/total_count*100) + '%')
print("Percent of TELNET packets: ", str(telnet_count/total_count*100) + '%')
print("Percent of SMTP packets: ", str(smtp_count/total_count*100) + '%')
print("Percent of POP3 packets: ", str(pop3_count/total_count*100) + '%')
print("Percent of NTP packets: ", str(ntp_count/total_count*100) + '%')
# print("DNS packets = ", dns_count)
# print("FTP packets = ", ftp_count) 
# print("SSH packets = ", ssh_count)
# print("DHCP packets = ", dhcp_count)
# print("TELNET packets = ", telnet_count)
# print("SMTP packets = ", smtp_count)
# print("POP3 packets = ", pop3_count)
# print("NTP packets = ", ntp_count)
print("question4: ")
print("Unique des ip address = ", len(ip_dic))
print("question5: ")
print("top 10 ip address: ")
for i in range(11):
    ip_max = max(ip_dic,key = ip_dic.get)
    print("ip_address ",i," :", ip_max ," number: ", ip_dic[ip_max])
    del ip_dic[ip_max]



f.close