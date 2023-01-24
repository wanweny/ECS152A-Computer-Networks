import socket
from argparse import ArgumentParser
import binascii
from concurrent.futures import ThreadPoolExecutor
from time import sleep

def parse_args():
    # parse the command line arguments
    args = ArgumentParser()
    args.add_argument('--ip', default='localhost')
    args.add_argument('--port', default=35000, type=int)
    return args.parse_args()

# welcoming socket
def welcomigSocket(ip, port):
    # create a server socket with the following specifications
    #   AF_INET -> IPv4 socket
    #   SOCK_DGRAM -> UDP protocol
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:

        # bind the socket to a OS port
        server_socket.bind((ip, port))
        
        num_clients = 0
        # create a processing pool for threads with max number of threads as 5
        with ThreadPoolExecutor(max_workers=5) as executor:
            # start receiving udp packets in an infinite loop
            while True:
                # RECIEVED SYN packets from client
                message, addr = server_socket.recvfrom(1024)
                print("received SYN message")
                # decode the message
                packet = unpack(message)           

                # if it is a SYN request
                if packet[4] == "1":
                    
                    ack_message = createAckMessage(num_clients,packet[0])
                    print("ack_message",ack_message)
                    port = (addr,int(packet[0]))
                    print("packet[0]: ", addr)

                    # Create new connection socket
                    ip = "localhost"
                    port = 30001 + num_clients
                    print("connection socket port number: ", port)
                    connection_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    # bind the socket to a OS port
                    connection_socket.bind((ip, port))

                    # SEND SYN/ACK message 
                    server_socket.sendto(ack_message.encode(), addr)
                    print("sent SYN/ACK message")
                    
                    # the thread will start in the connection_socket function
                    executor.submit(connection_socket_fn, connection_socket, num_clients)   
                    num_clients += 1

# connections socket
def connection_socket_fn(connection_socket, socket_num):

        # RECIEVE ACK from client
        message, addr = connection_socket.recvfrom(1024)
        message = unpack(message)
        if message[3] == "1":
            print("ACK recieved")
            while True:
                # recieve data message
                message, addr = connection_socket.recvfrom(1024)
                message = unpack(message)
                
                # FIN message
                if message[5] == "1":
                    print("received FIN")
                    break
                # DATA message
                if message[3] == "0" and message[4] == "0" and message[5]=="0":
                    sleep(1)
                    print("received",message[2] )
                    reply = createDataMessage(socket_num,message[0],"pong" )
                    connection_socket.sendto(reply.encode(),addr)
        else:
            print("not receiving ACK")

        # END 
        print("end the connection" )
        ack_message = createFinAckMessage(socket_num,message[0])
        connection_socket.sendto(ack_message.encode(),addr)
        connection_socket.close()


def addZero(str, num_bits):
    binary_num = str[2:]
    pad = num_bits - len(binary_num)
    zeros = ''
    for _ in range(pad):
        zeros += '0'
    return zeros + binary_num       

def unpack(message):
    message = message.decode('ascii')
    scr_port = message[:16]
    des_port = message[16:32]
    ack = message[100]
    syn = message[101]
    fin = message[102]
    data =message[103:]
    return int(scr_port,2), int(des_port,2), data,ack,syn,fin

def createAckMessage(socket_num,clientPort):
    connection_socket_port = 30001+socket_num
    src_port = addZero(bin(connection_socket_port), 16) # 16 bits
    dest_port = addZero(bin(int(clientPort)), 16) # 16 bits
    seq_num = '00000000000000000000000000000000' # 32 bits
    ack_num = '00000000000000000000000000000000' # 32 bits
    data_offset = '0011' # 4 bits
    ack = '1' # 1 bit
    syn = '1' # 1 bit
    fin = '0' # 1 bit
    data = '' #64bits
    message = src_port + dest_port + seq_num + ack_num + data_offset + ack + syn + fin + data
    return  message           

def createFinAckMessage(socket_num,clientPort):
    connection_socket_port = 30001+socket_num
    src_port = addZero(bin(connection_socket_port), 16) # 16 bits
    dest_port = addZero(bin(int(clientPort)), 16) # 16 bits
    seq_num = '00000000000000000000000000000000' # 32 bits
    ack_num = '00000000000000000000000000000000' # 32 bits
    data_offset = '0011' # 4 bits
    ack = '1' # 1 bit
    syn = '0' # 1 bit
    fin = '0' # 1 bit
    data = '' #64bits
    message = src_port + dest_port + seq_num + ack_num + data_offset + ack + syn + fin + data
    return  message   

def createDataMessage(socket_num,clientPort,data):
    connection_socket_port = 30001+socket_num
    src_port = addZero(bin(connection_socket_port), 16) # 16 bits
    dest_port = addZero(bin(clientPort), 16) # 16 bits
    seq_num = '00000000000000000000000000000000' # 32 bits
    ack_num = '00000000000000000000000000000000' # 32 bits
    data_offset = '0011' # 4 bits
    ack = '0' # 1 bit
    syn = '0' # 1 bit
    fin = '0' # 1 bit
    msg=""
    for char in data:
        msg+= str(bin(ord(char)))[2:]
    message = src_port + dest_port + seq_num + ack_num + data_offset + ack + syn + fin + data
    return  message       


if __name__ == '__main__':
    args = parse_args()
    welcomigSocket(args.ip,args.port)