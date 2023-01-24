import socket
from argparse import ArgumentParser
import binascii
from concurrent.futures import ThreadPoolExecutor
from time import sleep
import random

def parse_args():
    # parse the command line arguments
    args = ArgumentParser()
    args.add_argument('--ip', default='localhost')
    args.add_argument('--port', default=35000, type=int)
    args.add_argument('--packet-loss-percentage', default=10, type=int)
    args.add_argument('--round-trip-jitter', default=0.5, type=float)
    args.add_argument('--output',default="output.txt")
    return args.parse_args()

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
                message, addr = server_socket.recvfrom(2048)
                print("server receive syn msg")
                # decode the message
                packet = unpack(message)
                
                # if it is a SYN request
                if packet[4] == "1":

                    socket_num = num_clients
                    ack_message = createAckMessage(socket_num,packet[0])
                    port = (addr,int(packet[0]))

                    # Create new connection socket
                    ip = "localhost"
                    port = 30001 + socket_num
                    print("connection socket port number: ",port)
                    connection_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    # bind the socket to a OS port
                    connection_socket.bind((ip, port))

                    # SEND SYN/ACK message 
                    server_socket.sendto(ack_message.encode(), addr)
                    print("server sent syn/ack")
                    
                    # the thread will start in the connection_socket function
                    executor.submit(connection_socket_fn, connection_socket, num_clients)   
                    num_clients += 1

# connections socket
def connection_socket_fn(connection_socket, socket_num):
        
        msg_list=[]

        # RECIEVE ACK from client
        message, addr = connection_socket.recvfrom(1024)
        message = unpack(message)
        if message[3] == "1":
            print("ACK recieved")
            while True:
                print("-----------------------------------")
                # recieve data message
                message, addr = connection_socket.recvfrom(1024)
                message = unpack(message)
                print("received packet seq num: ", message[6])
               
                rand = random.randrange(101)
                ack_num = 0

                # FIN message
                if message[5] == "1":
                    print("received fin")
                    break

                # DATA message
                if message[3] == "0" and message[4] == "0" and message[5]=="0":
                    
                    # randomly drop packets
                    if rand > packet_loss_percentage:
                        # if first packet
                        if len(msg_list) == 0:
                            msg_list.append(message)
                        # if packet sequence number after last packet recieved
                        elif message[6] == msg_list[-1][6] + 1000:
                            msg_list.append(message)

                        ack_num = msg_list[-1][6]

                        jitter  = random.randint(0, 101)/100
                        # round trip jitter
                        if jitter > round_trip_jitter:
                            sleep(jitter)

                        # SEND ACK 
                        reply = createAckNumMessage(socket_num,message[0],ack_num )
                        connection_socket.sendto(reply.encode(),addr)
                        print("ACK sent: ", ack_num)
                    else:
                        print("packet is lost")
        else:
            print("not receiving ack")

        # save recieved data
        name = str(addr[1]) + output
        with open(name, 'w') as fp:
            for msg in msg_list:
                # write each item on a new line
                fp.write("%s" % msg[2])

        # END
        print("end the connection" )
        ack_message = createFinAckMessage(socket_num,message[0])
        connection_socket.sendto(ack_message.encode(),addr)
        connection_socket.close()

# add leading zeros
def addZero(str, num_bits):
    binary_num = str[2:]
    pad = num_bits - len(binary_num)
    zeros = ''
    for _ in range(pad):
        zeros += '0'
    return zeros + binary_num       

# unpack encoded messages
def unpack(message):
    message = message.decode('ascii')
    scr_port = message[:16]
    des_port = message[16:32]
    seq_num = message[32:64]
    ack_num = message[64:96]
    ack = message[100]
    syn = message[101]
    fin = message[102]
    data =message[103:]
    return int(scr_port,2), int(des_port,2), data,ack,syn,fin,int(seq_num,2), int(ack_num,2) 

# create ACK packet
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

# create final ACK packet
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

# create packet containing ACK number
def createAckNumMessage(socket_num,clientPort,ack):
    connection_socket_port = 30001+socket_num
    src_port = addZero(bin(connection_socket_port), 16) # 16 bits
    dest_port = addZero(bin(clientPort), 16) # 16 bits
    seq_num = '00000000000000000000000000000000' # 32 bits
    ack_num = addZero(bin(ack), 32) # 32 bits
    data_offset = '0011' # 4 bits
    ack = '0' # 1 bit
    syn = '0' # 1 bit
    fin = '0' # 1 bit

    message = src_port + dest_port + seq_num + ack_num + data_offset + ack + syn + fin 
    return  message       


if __name__ == '__main__':
    args = parse_args()
    global packet_loss_percentage
    global round_trip_jitter
    packet_loss_percentage = args.packet_loss_percentage
    round_trip_jitter = args.round_trip_jitter

    global output
    output = args.output

    # start welcoming socket
    welcomigSocket(args.ip,args.port)