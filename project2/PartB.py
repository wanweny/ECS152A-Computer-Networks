import socket
from argparse import ArgumentParser
import binascii
import random
import time
from datetime import datetime
random.seed(1220)

def parse_args():
    # parse the command line arguments
    args = ArgumentParser()
    args.add_argument('--url', default="tmz.com", type=str)
    return args.parse_args()

# Use url from command line and return a DNS query message
def createQuery(url): 
    qname = "" # tmz
    lenQNameInt = 0
    tld = "" # com
    lenTldInt = 0
    tldFlag = 0 # 0 before '.' 1 after '.'
    for i in url:
        if i == ".":
            tldFlag = 1
            continue

        if tldFlag == 0:
            qname += str(hex(ord(i)))[2:]
            lenQNameInt += 1
        else: 
            tld += str(hex(ord(i)))[2:]
            lenTldInt += 1

    if lenQNameInt < 10:
        lenQName = '0' + str(hex(lenQNameInt))[2:]
    else: 
        lenQName = str(hex(lenQNameInt))[2:]
    if lenTldInt < 10:
        lentld = '0' + str(hex(lenTldInt))[2:]
    else: 
        lentld = str(hex(lenTldInt))[2:]

    message = "BB AA 00 00 00 01 00 00 00 00 00 00 " + lenQName + qname + lentld + tld + " 00 " + " 00 01 00 01"

    message = message.replace(" ", "").replace("\n", "")
    return binascii.unhexlify(message)

# Send DNS requests to servers
def start_udp_client(server_host, server_port, message):

    # create a client socket with the following specifications
    #   AF_INET -> IPv4 socket
    #   SOCK_DGRAM -> UDP protocol
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:

        # send message to server at address (server_host, server_port)
        client_socket.sendto(message, (server_host, server_port))
        message, addr = client_socket.recvfrom(2048)
        
        return binascii.hexlify(message).decode("utf-8")

# Helper function used to unpack responses
def getList(hex):
    octets = [hex[i:i+2] for i in range(0, len(hex), 2)]
    return octets

# Given a DNS response returns an IP Address to TLD or AUTH servers
def getServerIP(response):
    lenQNameInt = int(response[12], base=16)
    lenTldInt = int(response[12+lenQNameInt+1], base=16)
    StartofAnswer = 12+lenQNameInt+1+lenTldInt +1 + 5
    
    auth_num = int(response[9], base=16)
    index = StartofAnswer
    i=0
    while(i < auth_num):
        # print("start of ",i,"th record:",root_response[index])
        end_index = index +11 + int(response[index+11], base=16)
        # print("record ", i, " lenth: ",int(root_response[index+11], base=16))
        # print("end of ",i,"th record:",root_response[end_index])
        index = end_index+1
        i+=1

    ip_list=[]

    i=0
    add_num = int(response[11], base=16)
    #  get ip address from response from server response
    while(i < add_num):
        addr_lenth_index = index +11 
        if  int(response[addr_lenth_index], base=16) == 4:
            a = int(response[addr_lenth_index+1], base=16)
            b = int(response[addr_lenth_index+2], base=16)
            c = int(response[addr_lenth_index+3], base=16)
            d = int(response[addr_lenth_index+4], base=16)
            tldIP = str(a) + '.' + str(b) + '.' + str(c) + '.' + str(d) 
            ip_list.append(tldIP)
        index =  addr_lenth_index+int(response[addr_lenth_index], base=16)+1
        i+=1
    return random.choice(ip_list)

# Send request to ROOT, TLD, and AUTH servers, returns repsonse from AUTH server
def getAuthRes(message):
    # ------ DNS -> ROOT -------
    # ROOT DNS IPs
    ipArr = ["198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241", "192.112.36.4,", "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33"]

    root_server_host = random.choice(ipArr)
    print("Root server IP address: ",root_server_host)
    server_port = 53
    
    # RTT from local DNS to ROOT
    time_sent_root = time.time() 
    root_response = start_udp_client(root_server_host, server_port,message)
    time_recv_root = time.time()
    print("RRT_ROOT: ", time_recv_root - time_sent_root)

    root_response = getList(root_response)

    add_num = int(root_response[11], base=16)
    if add_num <1:
        print("NO TLD RECIEVED"), len(root_response)
    else:
        tldIP=getServerIP(root_response)
    print("TLD server IP address: ", tldIP)

    # ----- DNS -> TLD ------
    # RTT from local DNS to TLD
    time_sent_tld = time.time() 
    tld_response = start_udp_client(tldIP, server_port,message)
    time_recv_tld = time.time() 
    print("RRT_TLD: ", time_recv_tld - time_sent_tld)

    tld_response = getList(tld_response)
    auth_ip = getServerIP(tld_response)
    print("Authoritative server IP address",auth_ip)

    # ----- DNS -> AUTH ------
    # RTT from local DNS to AUTH
    time_sent_auth = time.time() 
    auth_response = start_udp_client(auth_ip, server_port,message)
    time_recv_auth = time.time()
    print("RRT_AUTH: ", time_recv_auth - time_sent_auth)
    # print("Number of Answers:", int(auth_response[7], base=16))
    # print("Number of authority records:", int(auth_response[9], base=16))
    # print("Number of additional records:", int(auth_response[11], base=16))
    
    return auth_response

def getAnswerIp(res):
    response = getList(res)
    # print(response)
    # print("Number of Answers:", int(response[7], base=16))
    # print("Number of authority records:", int(response[9], base=16))
    # print("Number of additional records:", int(response[11], base=16))
    lenQNameInt = int(response[12], base=16)
    lenTldInt = int(response[12+lenQNameInt+1], base=16)
    StartofAnswer = 12+lenQNameInt+1+lenTldInt +1 + 5

    ip_list=[]
    i=0
    numAns = int(response[7], base=16)
    # get ip address from response from server response
    while(i < numAns):
        ans = StartofAnswer +11
        if  int(response[ans], base=16) == 4:
            a = int(response[ans+1], base=16)
            b = int(response[ans+2], base=16)
            c = int(response[ans+3], base=16)
            d = int(response[ans+4], base=16)
            ansIP = str(a) + '.' + str(b) + '.' + str(c) + '.' + str(d) 
            ip_list.append(ansIP)
        StartofAnswer =  ans+int(response[ans], base=16)+1
        i+=1
    # Randomly take an ip addresss
    ipAddress = random.choice(ip_list) 
    return ipAddress

if __name__ == '__main__':
    args = parse_args()
    print("Domain: ", args.url)
    dns_query = createQuery(args.url)
    response = getAuthRes(dns_query) #DNS Response with IP of url
    ipAdd =  getAnswerIp(response)
    print("HTTP Server IP address:", ipAdd)
