import socket
from argparse import ArgumentParser
from time import sleep
import signal
import time
log = []

def parse_args():
    # parse the command line arguments
    args = ArgumentParser()
    args.add_argument('--server-ip', default='localhost')
    args.add_argument('--server-port', default=35000, type=int)
    return args.parse_args()

def addLog(Source,Destination,SYN,ACK,FIN,Message_Length,ts):
    if SYN == "1" and ACK == "1":
        Message_Type = "SYN/ACK"
    elif SYN == "0" and ACK == "0" and FIN == "0":
        Message_Type = "DATA"
    elif SYN == "1":
        Message_Type = "SYN"
    elif ACK == "1":
        Message_Type = "ACK"
    elif FIN == "1":
        Message_Type = "FIN"
    
    log.append([str(Source),Destination,Message_Type,Message_Length,ts])

connection_socket_port = 0
send_fin = False

def finHandler(signum, frame):
    global send_fin 
    print("Finhandler executed, ", send_fin)
    
    send_fin = True
    print("Fin: ",send_fin)

def getList(hex):
    octets = [hex[i:i+1] for i in range(0, len(hex), 1)]
    return octets

def connectWelcoming(serverIP,serverPort):
    # create a udp socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        # bind the socket to a OS port

        udp_socket.bind(("localhost",0 ))
        socket_port = udp_socket.getsockname()[1]
        print("client socket bind to port",socket_port)
        # write message
        src_port = addZero(bin(socket_port), 16) # 16 bits
        dest_port = addZero(bin(serverPort), 16) # 16 bits
        seq_num = addZero(str(0), 32)  # 32 bits
        ack_num = '00000000000000000000000000000000' # 32 bits
        data_offset = '0011' # 4 bits
        ack = '0' # 1 bit
        syn = '1' # 1 bit
        fin = '0' # 1 bit
        data = '' # 64 bits
        message = src_port + dest_port + seq_num + ack_num + data_offset + ack + syn + fin + data

        udp_socket.sendto(message.encode(), (serverIP, serverPort))
        ts = time.time()
        addLog(socket_port,serverPort,syn,ack,fin,len(message)-103,ts)
        # receive the acknowledgement
        acknowledgement, _ = udp_socket.recvfrom(1024)
        print("client receive syn/ack msg: ")
        acknowledgement = unpack(acknowledgement)
        ts = time.time()
        addLog(acknowledgement[0],acknowledgement[1],acknowledgement[4],acknowledgement[3],acknowledgement[5],acknowledgement[6],ts)
        if acknowledgement[3] == "1" and acknowledgement[4] == "1":
            global connection_socket_port
            connection_socket_port = acknowledgement[0]
            connectConnection(serverIP,acknowledgement[0],1)
                

def connectConnection(serverIP, serverPort,seq):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection_socket:
        connection_socket.bind(("localhost",0 ))
        socket_port = connection_socket.getsockname()[1]
        print("connection socket bind to port",socket_port)
        src_port = addZero(bin(socket_port), 16) # 16 bits
        dest_port = addZero(bin(serverPort), 16) # 16 bits
        seq_num = addZero(str(seq), 32)  # 32 bits
        ack_num = '00000000000000000000000000000000' # 32 bits
        data_offset = '0011' # 4 bits
        ack = '1' # 1 bit
        syn = '0' # 1 bit
        fin = '0' # 1 bit
        data = '' # 64 bits
        message = src_port + dest_port + seq_num + ack_num + data_offset + ack + syn + fin + data
        connection_socket.sendto(message.encode(), (serverIP, serverPort))
        message = unpack(message.encode())
        ts = time.time()
        addLog(message[0],message[1],message[4],message[3],message[5],message[6],ts)
        print("client sent last ack "  )
        #first ping
        reply = createDataMessage(0,socket_port,"ping" )
        print("client sent first ping" )
        print("socket sent to:", serverIP,serverPort)
        connection_socket.sendto(reply.encode(),(serverIP, serverPort))
        print("reply")
        reply = unpack(reply.encode())
        print("sent",reply[2])
        ts = time.time()
        addLog(reply[0],reply[1],reply[4],reply[3],reply[5],reply[6],ts)
        signal.signal(signal.SIGINT, finHandler)
        while send_fin == False: 
           
                sleep(1)
                message, addr = connection_socket.recvfrom(1024)
                message = unpack(message)
                ts = time.time()
                addLog(message[0],message[1],message[4],message[3],message[5],message[6],ts)
                print("received",message[2])
                reply = createDataMessage(0,socket_port,"ping" )
                connection_socket.sendto(reply.encode(),(addr[0], message[0]))
                reply = unpack(reply.encode())
                print("sent",reply[2])
                ts = time.time()
                addLog(reply[0],reply[1],reply[4],reply[3],reply[5],reply[6],ts)
           
        
        finmsg = createFinMessage(0,socket_port)
        print("sent fin msg")
        connection_socket.sendto(finmsg.encode(),(addr[0], message[0]))
        reply = unpack(finmsg.encode())
        ts = time.time()
        addLog(reply[0],reply[1],reply[4],reply[3],reply[5],reply[6],ts)

        message, addr = connection_socket.recvfrom(1024)
        message, addr = connection_socket.recvfrom(1024)
        print("receive ack," )
        message = unpack(message)
        ts = time.time()
        addLog(message[0],message[1],message[4],message[3],message[5],message[6],ts)
        
        name = str(socket_port)+".txt"
        with open(name, 'w') as fp:
            fp.write("%s\n" % "Source,Destination,Message_Type,Message_Length,Time_stamp")
            for item in log:
                # write each item on a new line
                fp.write("%s\n" % item)
            print('Done')
        exit(1)


def createDataMessage(socket_num,clientPort,data):
    src_port = addZero(bin(clientPort), 16) # 16 bits
    dest_port = addZero(bin(connection_socket_port), 16) # 16 bits
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

def createFinMessage(socket_num,clientPort):
    src_port = addZero(bin(int(clientPort)), 16) # 16 bits
    dest_port = addZero(bin(connection_socket_port), 16) # 16 bitsbin
    seq_num = '00000000000000000000000000000000' # 32 bits
    ack_num = '00000000000000000000000000000000' # 32 bits
    data_offset = '0011' # 4 bits
    ack = '0' # 1 bit
    syn = '0' # 1 bit
    fin = '1' # 1 bit
    data='' #64bits
    message = src_port + dest_port + seq_num + ack_num + data_offset + ack + syn + fin + data
    return  message  

def unpack(message):
    message = message.decode()
    length = len(message)-103
    scr_port = message[:16]
    des_port = message[16:32]
    data = message[103:]
    ack = message[100]
    syn = message[101]
    fin = message[102]
    return int(scr_port,2), int(des_port,2), data,ack,syn,fin,length

def addZero(str, num_bits):
    binary_num = str[2:]
    pad = num_bits - len(binary_num)
    zeros = ''
    for _ in range(pad):
        zeros += '0'
    return zeros + binary_num

if __name__ == '__main__':
    args = parse_args()

    # for i in range(0,11):
    #     connect(args.serverIP, args.serverPort, i)
    connectWelcoming(args.server_ip, args.server_port)
    


    