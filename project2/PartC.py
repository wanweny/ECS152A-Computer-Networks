import socket
from argparse import ArgumentParser
import binascii
import random
import time
from datetime import datetime
random.seed(1220)
cache = {}

def parse_args():
    # parse the command line arguments
    args = ArgumentParser()
    args.add_argument('--host', default='localhost')
    args.add_argument('--port', default=20000, type=int)
    return args.parse_args()

# get ip from a response
def getIP(auth_response):
    auth_response=getList(auth_response)
    
    lenQNameInt = int(auth_response[12], base=16)
    lenTldInt = int(auth_response[12+lenQNameInt+1], base=16)
    StartofAnswer = 12+lenQNameInt+1+lenTldInt +1 + 5
    record_list=[]
    i=0
    numAns = int(auth_response[7], base=16)
    #  get ip address from response from server
    while(i < numAns):
        ipAndttl = [] #  format: [ipaddress,ttl]
        ans = StartofAnswer +11
        if  int(auth_response[ans], base=16) == 4:
            a = int(auth_response[ans+1], base=16)
            b = int(auth_response[ans+2], base=16)
            c = int(auth_response[ans+3], base=16)
            d = int(auth_response[ans+4], base=16)
            ansIP = str(a) + '.' + str(b) + '.' + str(c) + '.' + str(d) 
            ipAndttl.append(ansIP)
            
            ipAndttl.append(int(auth_response[ans-3]+auth_response[ans-2], base=16))
        StartofAnswer = ans+int(auth_response[ans], base=16)+1
        record_list.append(ipAndttl)
        i+=1
    ipAddr = random.choice(record_list)
    print("HTTP Server IP address:",ipAddr[0])
    return ipAddr

# return domain name of a request
def getHostname(message):
    
    message =getList(binascii.hexlify(message).decode("utf-8"))
    qname = []
    lenQNameInt = int(message[12], base=16)
    lenTldInt= int(message[12+lenQNameInt+1], base=16)
    for i in range(lenQNameInt):
        qname.append(bytearray.fromhex(message[13+i]).decode())
    qname.append(".")
    for i in range(lenTldInt):
        qname.append(bytearray.fromhex(message[12+lenQNameInt+2+i]).decode())
    return "".join(qname)

# Creates a server, recieves requests from client, and sends back response to client
def start_udp_server(host, port):
    # create a server socket with the following specifications
    #   AF_INET -> IPv4 socket
    #   SOCK_DGRAM -> UDP protocol
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:

        # bind the socket to a OS port
        server_socket.bind((host, port))

        # start receiving udp packets in an infinite loop
        while True:
            # data, addr = recvfrom(n)
            #   n -> buffer size, i.e., number of max bytes to receive
            #   data -> the message received from the client
            #   addr -> the address of the client

            message, addr = server_socket.recvfrom(1024)
            time_recv_from_client = time.time()

            print("Domain:",getHostname(message))
            hostname =getHostname(message)
            in_cache=0
            # determine if host name in cache
            if hostname in cache:
                ts = time.time()
                diff = int(ts)-cache[hostname][2]
                if diff < cache[hostname][1]:
                    in_cache = 1
            if in_cache == 1:
                print("IN CACHE")
                response = cache[hostname]
                getIP(response[0])
            else:
                print("NOT IN CACHE")
                response = getAuthIp(message) # DNS Response with format[response,ttl]
                ts = time.time()
                #store[response,ttl,ts] into cache
                cache[hostname] = [response[0],response[1],int(ts)]
            
            # send response back to client
            time_send_to_client = time.time()
            server_socket.sendto(binascii.unhexlify(response[0]), addr)
            
            print("Total time to resolve host name: ", time_send_to_client - time_recv_from_client)

# # Send DNS requests to servers
def start_udp_client(server_host, server_port, message):

    # create a client socket with the following specifications
    #   AF_INET -> IPv4 socket
    #   SOCK_DGRAM -> UDP protocol
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:

        # send message to server at address (server_host, server_port)
        
        # ----- message from client -----
        # message = "BB AA 00 00 00 01 00 00 00 00 00 00 03 74 6D 7A 03 63 6f 6d 00 00 01 00 01"  
        # message = message.replace(" ", "").replace("\n", "")
        # client_socket.sendto(binascii.unhexlify(message), (server_host, server_port))
        client_socket.sendto(message, (server_host, server_port))
        # print("DNS request sent")
        message, addr = client_socket.recvfrom(2048)
        
        return binascii.hexlify(message).decode("utf-8")

# Helper function used to unpack responses
def getList(hex):
    octets = [hex[i:i+2] for i in range(0, len(hex), 2)]
    return octets

# Given a DNS response returns an IP Address to TLD or AUTH servers
def getServerIP(res):
    lenQNameInt = int(res[12], base=16)
    lenTldInt = int(res[12+lenQNameInt+1], base=16)
    StartofAnswer = 12+lenQNameInt+1+lenTldInt +1 + 5
    
    auth_num = int(res[9], base=16)
    index = StartofAnswer
    i=0
    while(i < auth_num):
        end_index = index +11 + int(res[index+11], base=16)
        index = end_index+1
        i+=1

    record_list=[]

    i=0
    add_num = int(res[11], base=16)

    while(i < add_num):
        addr_lenth_index = index +11 
        if  int(res[addr_lenth_index], base=16) == 4:
            a = int(res[addr_lenth_index+1], base=16)
            b = int(res[addr_lenth_index+2], base=16)
            c = int(res[addr_lenth_index+3], base=16)
            d = int(res[addr_lenth_index+4], base=16)
            ipAd = str(a) + '.' + str(b) + '.' + str(c) + '.' + str(d) 
            record_list.append(ipAd)
        index =  addr_lenth_index+int(res[addr_lenth_index], base=16)+1
        i+=1
    return random.choice(record_list)

# Send request to ROOT, TLD, and AUTH servers, returns AUTH response and TTL
def getAuthIp(message):
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
    
    #get random final ip address
    ttl = int(auth_response[-16:-12], base=16)
    result= auth_response
    getIP(auth_response)

    print("TTL: ", ttl, " seconds")

    return [result,ttl]

if __name__ == '__main__':
    args = parse_args()
    start_udp_server(args.host, args.port)
    
