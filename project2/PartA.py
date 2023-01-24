import socket
from argparse import ArgumentParser
import binascii
import time
import random
random.seed(1220)

def parse_args():
    # parse the command line arguments
    args = ArgumentParser()
    args.add_argument('--server-host', default='168.62.214.68')
    args.add_argument('--server-port', default=53, type=int)
    args.add_argument('--url', default="tmz.com", type=str)
    return args.parse_args()

# build DNS query, send query, recieve response, function returns DNS response
def start_udp_client(server_host, server_port, url):
    # create a client socket with the following specifications
    #   AF_INET -> IPv4 socket
    #   SOCK_DGRAM -> UDP protocol
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:

        # send message to server at address (server_host, server_port)

        qname = "" # ex: tmz
        lenQNameInt = 0
        tld = "" # ex: com
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

  
        message = "BB AA 01 00 00 01 00 00 00 00 00 00 " + lenQName + qname + lentld + tld + " 00 " + " 00 01 00 01"

        message = message.replace(" ", "").replace("\n", "")
        client_socket.sendto(binascii.unhexlify(message), (server_host, server_port))
        ts_sent = time.time()
        # print("DNS Query Sent")
        message, addr = client_socket.recvfrom(2048)
        ts_re = time.time()
        print("RTT_DNS: ", ts_re - ts_sent)
        return binascii.hexlify(message).decode("utf-8")

# Initiate a TCP connection to the IP address at port 80, and send a HTTP GET request, returns a HTTP response
# reference: https://www.geeks3d.com/hacklab/20190110/python-3-simple-http-request-with-the-socket-module/
def sendHTTP(ipAdd, domain):
    target_host = ipAdd 
    
    target_port = 80  # create a socket object 
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    
    # connect the client 
    client.connect((target_host,target_port))  
    
    # send some data 
    request = "GET / HTTP/1.1\r\nHost:%s\r\n\r\n" % domain
    client.send(request.encode())  
    ts_sent = time.time()
    # receive some data 
    response = client.recv(4096)  
    ts_re = time.time()
    print("RTT_HTTP: ", ts_re - ts_sent)

    http_response = repr(response)
    http_response_len = len(http_response)
    
    return http_response

# Helper function used to unpack responses
def getList(hex):
    octets = [hex[i:i+2] for i in range(0, len(hex), 2)]
    return octets

if __name__ == '__main__':
    args = parse_args()
    print("Domain:",args.url)
    # send DNS request
    response = start_udp_client(args.server_host, args.server_port, args.url)
    response = getList(response)

    # print("Number of Answers:", int(response[7], base=16))
    # print("Number of authority records:", int(response[9], base=16))
    # print("Number of additional records:", int(response[11], base=16))
    lenQNameInt = int(response[12], base=16)
    lenTldInt = int(response[12+lenQNameInt+1], base=16)
    StartofAnswer = 12+lenQNameInt+1+lenTldInt +1 + 5

    ip_list=[]
    i=0
    numAns = int(response[7], base=16)
    # get ip addresses from response from server response
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
    ipAddr = random.choice(ip_list)
    print("HTTP Server IP address:", ipAddr)

    # send HTTP request 
    content = str(sendHTTP(ipAddr, args.url))
    with open(args.url+'.html', 'w') as f:
        f.write(content)
