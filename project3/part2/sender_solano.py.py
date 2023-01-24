import socket
from argparse import ArgumentParser
from time import sleep
import time

import signal
import random

log = []
PKT_SIZE = 897

def parse_args():
    # parse the command line arguments
    args = ArgumentParser()
    args.add_argument('--dest-ip', default='localhost')
    args.add_argument('--dest-port', default=35000, type=int)
    args.add_argument('--input',default="alice29.txt")
    return args.parse_args()

# add info to log 
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
    
    log.append([str(Source),Destination,Message_Type,Message_Length,str(ts)])

connection_socket_port = 0
send_fin = False
sequence_number = 0

# signal handlet for termination
def finHandler(signum, frame):
    global send_fin 
    print("Finhandler executed, ", send_fin)
    
    send_fin = True
    print("Fin: ",send_fin)

# Client socket
def connectWelcoming(serverIP,serverPort):
    # create a udp socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        # bind the socket to a OS port
        udp_socket.bind(("localhost",0 ))
        socket_port = udp_socket.getsockname()[1]
        print("client socket bind to port",socket_port)

        # 3 way handshake SEND SYN to server welcoming socket
        message = createSynMessage(socket_port, serverPort)    
        print("client sent first syn msg:", message)
        udp_socket.sendto(message.encode(), (serverIP, serverPort))
        message = unpack(message.encode())
        ts = time.time()
        addLog(message[0],message[1],message[4],message[3],message[5],message[6],ts)
        
        # 3 way handshake RECIEVE SYN/ACK
        acknowledgement, _ = udp_socket.recvfrom(1024)
        print("client receive syn/ack msg: ", acknowledgement)
        acknowledgement = unpack(acknowledgement)
        ts = time.time()
        addLog(acknowledgement[0],acknowledgement[1],acknowledgement[4],acknowledgement[3],acknowledgement[5],acknowledgement[6],ts)
        
        # check it is a SYN/ACK packet
        if acknowledgement[3] == "1" and acknowledgement[4] == "1":
            # connection socket port of server
            global connection_socket_port
            connection_socket_port = acknowledgement[0]
            # create new data socket on client side
            connectConnection(serverIP,acknowledgement[0])        

# Client data socket
def connectConnection(serverIP, serverPort):
    # create data socket for client
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection_socket:
        global total_sent
        global total_lost
        total_lost=0
        total_sent = 0 

        # bind client data socket to random port
        connection_socket.bind(("localhost",0 ))
        socket_port = connection_socket.getsockname()[1]
        print("connection socket bind to port",socket_port)

        # 3 way handshake SEND ACK to server connection socket
        message = createAckMessage(socket_port, serverPort)
        connection_socket.sendto(message.encode(), (serverIP, serverPort))
        message = unpack(message.encode())
        ts = time.time()
        addLog(message[0],message[1],message[4],message[3],message[5],message[6],ts)
        print("client sent last ack "  )
            
        signal.signal(signal.SIGINT, finHandler)
        
        global Time_out 
        Time_out = 2
        global Estimate_RTT
        Estimate_RTT = 0
        global Dev_RTT
        Dev_RTT = 0

        packets = parseText()
        packet_num = 0
        rand = random.randint(0,2147483648)
        for packet in packets:
            # continue to send packets
            if send_fin == False:
                print("checktest-------------------------")
                connection_socket.settimeout(2)
                # update sequence number
                seq =(packet_num+1)*(PKT_SIZE+103) + rand

                # SEND data message    
                datamsg = createDataMessage(socket_port,str(packet),seq)
                connection_socket.sendto(datamsg.encode(),(serverIP, serverPort))
                sent_ts = time.time()
                total_sent += 1
                log1 = unpack(datamsg.encode())
                ts = time.time()
                addLog(log1[0],log1[1],log1[4],log1[3],log1[5],log1[6],ts)


                print("packet_num",packet_num)

                enter_timeout = False
                while True:
                    try:
                        # RECIECVE ACK from server
                        message, addr = connection_socket.recvfrom(1024)
                        receive_ts = time.time()
                        print("receive packet")
                        message = unpack(message)
                        ts = time.time()
                        addLog(message[0],message[1],message[4],message[3],message[5],message[6],ts)
                        
                        # FIN message
                        if message[5] == "1":
                            print("received fin")
                            break
                        # DATA message
                        elif message[3] == "0" and message[4] == "0" and message[4] == "0":
                            
                            if enter_timeout == False:
                                sample_rtt = receive_ts-sent_ts
                                Estimate_RTT = (1-0.125)*Estimate_RTT + 0.125*(sample_rtt)
                                Dev_RTT = (1-0.25)*Dev_RTT + 0.25*abs(sample_rtt-Estimate_RTT)
                                Time_out  = Estimate_RTT + 4*Dev_RTT
                            
                            # check ACK
                            if message[8] == seq:
                                print('ACK received: ', message[8])
                                break
                            else:
                                print("ACK not correct ------", message[8])
                                print("    expected:", seq)
                    # Timeout resend packet            
                    except socket.timeout:
                        total_lost += 1
                        Time_out = Time_out*2
                        print("Time_out:",Time_out)
                        enter_timeout = True

                        print(f"Timeout occured for #{packet_num}, resending")
                        # RESEND packet
                        connection_socket.sendto(datamsg.encode(),(serverIP, serverPort))
                        total_sent+=1
                        log1 = unpack(datamsg.encode())
                        ts = time.time()
                        addLog(log1[0],log1[1],log1[4],log1[3],log1[5],log1[6],ts)
                packet_num += 1  
            # FIN is recieved    
            else:
                # send FIN message
                fin_sent = 0
                finmsg = createFinMessage(socket_port)
                print("sent fin msg when send_fin is TURE",finmsg)
                connection_socket.sendto(finmsg.encode(),(serverIP, serverPort))
                reply = unpack(finmsg.encode())
                ts = time.time()
                addLog(reply[0],reply[1],reply[4],reply[3],reply[5],reply[6],ts)
                fin_sent += 1
            
                # recieve ACK
                while True: 
                    try:
                        # recieve ACK from server to end connection
                        message, addr = connection_socket.recvfrom(1024)
                        print("receive ack,",message )
                        message = unpack(message)
                        ts = time.time()
                        addLog(message[0],message[1],message[4],message[3],message[5],message[6],ts)

                        if message[3] == '1':
                            # END 
                            name = str(socket_port)+".txt"
                            with open(name, 'w') as fp:
                                fp.write("%s\n" % "Source,Destination,Message_Type,Message_Length,Time_Stamp")
                                for item in log:
                                    # write each item on a new line
                                    fp.write("%s\n" % item)
                                print('Done')
                            connection_socket.close()    
                            exit(0)   
                    # Timeout, resend FIN message        
                    except socket.timeout:
                        # FIN message sent less than 3 times
                        if fin_sent < 3:  
                            # SEND FIN message
                            finmsg = createFinMessage(socket_port)
                            print("sent fin msg after timeout of receiving fin ack",finmsg)
                            connection_socket.sendto(finmsg.encode(),(addr[0], message[0]))
                            reply = unpack(finmsg.encode())
                            ts = time.time()
                            addLog(reply[0],reply[1],reply[4],reply[3],reply[5],reply[6],ts)   
                            fin_sent += 1
                        else:
                            # END
                            name = str(socket_port)+".txt"
                            with open(name, 'w') as fp:
                                fp.write("%s\n" % "Source,Destination,Message_Type,Message_Length,Time_Stamp")
                                for item in log:
                                    # write each item on a new line
                                    fp.write("%s\n" % item)
                                print('Done')
                            connection_socket.close()
                            exit(0)
            
        # EOF, SEND last message with sequence number = 0
        end_msg = createDataMessage(socket_port,"",0)
        connection_socket.sendto(end_msg.encode(),(serverIP, serverPort))
        log1 = unpack(datamsg.encode())
        ts = time.time()
        addLog(log1[0],log1[1],log1[4],log1[3],log1[5],log1[6],ts) 
        print("EOF message sent")
        
        # send FIN message
        fin_sent = 0
        finmsg = createFinMessage(socket_port)
        print("sent fin msg after last packet sent")
        connection_socket.sendto(finmsg.encode(),(addr[0], message[0]))
        reply = unpack(finmsg.encode())
        ts = time.time()
        addLog(reply[0],reply[1],reply[4],reply[3],reply[5],reply[6],ts)
        fin_sent += 1
        message, addr = connection_socket.recvfrom(1024)
        
        # recieve ACK
        while True: 
            try:
                # recieve ACK from server to end connection
                message, addr = connection_socket.recvfrom(1024)
                print("receive ack to end connection")
                message = unpack(message)
                ts = time.time()
                addLog(message[0],message[1],message[4],message[3],message[5],message[6],ts)
                
                if message[3] == '1':
                    # END 
                    name = str(socket_port)+".txt"
                    with open(name, 'w') as fp:
                        fp.write("%s\n" % "Source,Destination,Message_Type,Message_Length,Time_Stamp")
                        for item in log:
                            # write each item on a new line
                            fp.write("%s\n" % item)
                        print('Done')
                    break   
                   
            # Timeout, resend FIN message        
            except socket.timeout:
                # FIN message sent less than 3 times
                if fin_sent < 3:  
                    # SEND FIN message
                    finmsg = createFinMessage(socket_port)
                    print("sent fin msg after last packet timeout",finmsg)
                    connection_socket.sendto(finmsg.encode(),(addr[0], message[0]))
                    reply = unpack(finmsg.encode())
                    ts = time.time()
                    addLog(reply[0],reply[1],reply[4],reply[3],reply[5],reply[6],ts)   
                    fin_sent += 1
                else:
                    # END
                    name = str(socket_port)+".txt"
                    with open(name, 'w') as fp:
                        fp.write("%s\n" % "Source,Destination,Message_Type,Message_Length,Time_Stamp")
                        for item in log:
                            # write each item on a new line
                            fp.write("%s\n" % item)
                        print('Done')
                    break
        connection_socket.close()
   
# create SYN packet
def createSynMessage(clientPort, severPort):
    src_port = addZero(bin(clientPort), 16) # 16 bits
    dest_port = addZero(bin(severPort), 16) # 16 bits
    seq_num = '00000000000000000000000000000000' # 32 bits
    ack_num = '00000000000000000000000000000000' # 32 bits
    data_offset = '0011' # 4 bits
    ack = '0' # 1 bit
    syn = '1' # 1 bit
    fin = '0' # 1 bit
    data = '' # 64 bits
    message = src_port + dest_port + seq_num + ack_num + data_offset + ack + syn + fin + data        
    return  message          

# create ACK packet
def createAckMessage(clientPort, serverPort):
    src_port = addZero(bin(clientPort), 16) # 16 bits
    dest_port = addZero(bin(serverPort), 16) # 16 bits
    seq_num = '00000000000000000000000000000000' # 32 bits
    ack_num = '00000000000000000000000000000000' # 32 bits
    data_offset = '0011' # 4 bits
    ack = '1' # 1 bit
    syn = '0' # 1 bit
    fin = '0' # 1 bit
    data = '' # 64 bits
    message = src_port + dest_port + seq_num + ack_num + data_offset + ack + syn + fin + data
    return  message

# create DATA packet
def createDataMessage(clientPort, data, seq_num):
    src_port = addZero(bin(clientPort), 16) # 16 bits
    dest_port = addZero(bin(connection_socket_port), 16) # 16 bits
    seq_num = addZero(bin(seq_num),32) # 32 bits
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

# create FIN packet
def createFinMessage(clientPort):
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

# unpack encoded messages
def unpack(message):
    message = message.decode()
    length = len(message)-103
    scr_port = message[:16]
    des_port = message[16:32]
    seq_num = message[32:64]

    ack_num = message[64:96]
    data = message[103:]
    ack = message[100]
    syn = message[101]
    fin = message[102]
    return int(scr_port,2), int(des_port,2), data, ack, syn, fin, length, int(seq_num,2), int(ack_num,2)

# add leading zeros
def addZero(str, num_bits):
    binary_num = str[2:]
    pad = num_bits - len(binary_num)
    zeros = ''
    for _ in range(pad):
        zeros += '0'
    return zeros + binary_num

# put file contents into sections of PKT_SIZE
def parseText():
    packets = []
    packet_num = 0
    sequence_num = 0
    while sequence_num < len(filecontent):
        if sequence_num + PKT_SIZE < len(filecontent):
            packets.append(filecontent[sequence_num:sequence_num+PKT_SIZE] )
            sequence_num += PKT_SIZE
            packet_num += 1
        else:
            packets.append(filecontent[sequence_num:])
            sequence_num = len(filecontent)
            packet_num += 1
    return packets

if __name__ == '__main__':
    args = parse_args()
    
    with open(args.input, "r") as file:
        global filecontent
        filecontent = file.read()
    
    sent_ts = time.time()
    # start client socket
    connectWelcoming(args.dest_ip, args.dest_port)
    finish_ts = time.time()

    total_time = finish_ts-sent_ts
    print("Time taken to transfer ", args.input, ": ", total_time)

    num = len(filecontent) // 897
    remain = len(filecontent) % 897
    bandwidth = num*(1000)+remain+103  /total_time

    print("Total bandwith achieved: ", bandwidth)
    print("Packet loss observed: ", total_lost/total_sent)


    


    