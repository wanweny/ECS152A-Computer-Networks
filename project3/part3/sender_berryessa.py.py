import socket
from argparse import ArgumentParser
from time import sleep
import time

import signal
import matplotlib.pyplot as plt
import random

log = []
PKT_SIZE = 881

def parse_args():
    # parse the command line arguments
    args = ArgumentParser()
    args.add_argument('--dest-ip', default='localhost')
    args.add_argument('--dest-port', default=36000, type=int)
    args.add_argument('--tcp_version', default='reno') # tahoe or reno
    args.add_argument('--input', default="alice29.txt")
    return args.parse_args()

# add info to log 
def addLog(Source,Destination,SYN,ACK,FIN,Message_Length,state,cwnd,ts):
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
    
    log.append([str(Source),Destination,Message_Type,Message_Length,state,str(cwnd),ts])

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
def connectWelcoming(serverIP, serverPort, tcpType):
    # create a udp socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        # bind the socket to a OS port
        udp_socket.bind(("localhost",0 ))
        socket_port = udp_socket.getsockname()[1]
        print("client socket bind to port",socket_port)

        # 3 way handshake SEND SYN to server welcoming socket
        message = createSynMessage(socket_port, serverPort)    
        print("client sent first SYN msg to server welcoming socket")
        udp_socket.sendto(message.encode(), (serverIP, serverPort))
        message = unpack(message.encode())
        ts = time.time()
        addLog(message[0],message[1],message[4],message[3],message[5],message[6],"N/A",1,ts)

        # 3 way handshake RECIEVE SYN/ACK
        acknowledgement, _ = udp_socket.recvfrom(1024)
        print("client receive SYN/ACK msg")
        acknowledgement = unpack(acknowledgement)
        ts = time.time()
        addLog(acknowledgement[0],acknowledgement[1],acknowledgement[4],acknowledgement[3],acknowledgement[5],acknowledgement[6],"N/A",1,ts = time.time())
        
        # check it is a SYN/ACK packet
        if acknowledgement[3] == "1" and acknowledgement[4] == "1":
            # connection socket port of server
            global connection_socket_port
            connection_socket_port = acknowledgement[0]
            # create new data socket on client side
            connectConnection(serverIP, acknowledgement[0], tcpType)        

# Client data socket
def connectConnection(serverIP, serverPort, tcpType):
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
        addLog(message[0],message[1],message[4],message[3],message[5],message[6],"N/A",1,ts)
        print("client sent last ack "  )
            
        signal.signal(signal.SIGINT, finHandler)
        
        global Time_out 
        Time_out = 2 # initially = 1
        global Estimate_RTT
        Estimate_RTT = 0
        global Dev_RTT
        Dev_RTT = 0
        transmission_round = []
        congestion_window = []
        packets = parseText()
        acks_list = [0] # ACK numbers recieved
        sent_index = [-1] # packet index that were sent, packet_num
        
        slow_start_threshold = 16
        cwnd = 1 # initial cwnd = 1
        dup_acks = 0
        dup_ack_num = -1
        previous_wind_start = -1
        slow_start = True
        congestion_avoidence = False
        packet_num = 0
        rand = 0
        transmission_round_index = 0
        while packet_num < len(packets): 
            # continue to send packets
            if send_fin == False:
                connection_socket.settimeout(2)
                print("--------------START OF WINDOW -------------------")
                print("congestion window: ", cwnd)
                # send packets in windows of cwnd packets
                window = []
                transmission_round_index+=1
                transmission_round.append(transmission_round_index)
                congestion_window.append(cwnd)
                for first in range(0, cwnd):
                    if first == 0:
                        # set packet_num to the start of last window + 1
                        # packet_num = previous_wind_start + 1
                        # previous_wind_start += 1
                        packet_num = acks_list[-1] // 1000
                    else:
                        # packet_num = previous_wind_start + first 
                        packet_num = acks_list[-1] // 1000 + first 

                    window.append(packet_num)

                    # if EOF
                    if packet_num >= len(packets):
                        break

                    # if lost packet has not been recieved, do not send this window
                    if first == 0:
                        this_seq = (packet_num+1)*(PKT_SIZE+119)
                        if dup_ack_num != -1:
                            if this_seq > dup_ack_num + (PKT_SIZE+119):
                                previous_wind_start -= 1
                                break

                    # do not resend packets already sent    
                    if packet_num in sent_index:
                        continue
                    
                    packet = packets[packet_num]
                    # update sequence number
                    seq = (packet_num+1)*(PKT_SIZE+119) + rand

                    # SEND data message    
                    datamsg = createDataMessage(socket_port,str(packet),seq,cwnd)
                    connection_socket.sendto(datamsg.encode(),(serverIP, serverPort))
                    # keep track of packets already sent
                    sent_index.append(packet_num)
                    sent_ts = time.time()
                    total_sent += 1
                    log1 = unpack(datamsg.encode())
                    state = ""
                    if slow_start :
                        state = "slowstart"
                    elif congestion_avoidence:
                        state = "congestion_avoidence "
                    ts = time.time()
                    addLog(log1[0],log1[1],log1[4],log1[3],log1[5],log1[6],state,cwnd,ts)
                    print("packet sent packet_num: ",packet_num)
                    print("       seq_num: ", seq)
                
                print(window)

                enter_timeout = False
                while True:
                    try:
                        # RECIECVE ACK from server
                        message, addr = connection_socket.recvfrom(1024)
                        receive_ts = time.time()
                        message = unpack(message)
                        if slow_start :
                            state = "slowstart"
                        elif congestion_avoidence:
                            state = "congestion_avoidence"
                        print("state: ",state)
                        ts = time.time()
                        addLog(message[0],message[1],message[4],message[3],message[5],message[6],state,1,ts)

                        # FIN message
                        if message[5] == "1":
                            print("received fin")
                            break
                        # DATA message
                        elif message[3] == "0" and message[4] == "0" and message[4] == "0":
                            # calculate timeout
                            if enter_timeout == False:
                                sample_rtt = receive_ts-sent_ts
                                Estimate_RTT = (1-0.125)*Estimate_RTT + 0.125*(sample_rtt)
                                Dev_RTT = (1-0.25)*Dev_RTT + 0.25*abs(sample_rtt-Estimate_RTT)
                                Time_out  = Estimate_RTT + 4*Dev_RTT
                            
                            # append ACK to acks_list
                            acks_list.append(message[8])
                            print('ACK received: ', message[8])
                            # check duplicate ACK
                            if message[8] == acks_list[-2]:
                                # this ACK duplicates with last ACK received
                                print("DUPLICTAE ACK")
                                dup_acks += 1
                                total_lost += 1
                                # resend if 3 duplicate ACKs
                                if dup_acks >= 2:
                                    print("3 DUPLICTAE ACKs")
                                    dup_ack_num = message[8]
                                    if tcpType == 'tahoe':
                                        # TAHOE: Fast Retransmit phase, reset cwnd to intial size
                                        print("!!! Fast Retransmit phase")
                                        cwnd = 1
                                        slow_start = True
                                        congestion_avoidence = False
                                    else:
                                        # RENO: Fast Recovery phase
                                        cwnd = cwnd // 2
                                        if cwnd == 0:
                                            cwnd = 1
                                        slow_start = True
                                        congestion_avoidence = False

                                    if index >=len(packet):
                                        break
                                    # get the index of packet to send
                                    index = dup_ack_num // 1000 
                                    packet = packets[index]
                                    # update sequence number
                                    seq = (index+1)*(PKT_SIZE+119) + rand
                                    # RESEND packet of this ack_num
                                    print("RESEND packet_num: ", index)
                                    print("       seq_num: ", seq)
                                    datamsg = createDataMessage(socket_port,str(packet),seq,1)
                                    connection_socket.sendto(datamsg.encode(),(serverIP, serverPort))
                                    dup_acks = 0
                                    dup_ack_num = -1
                                    total_sent+=1
                                    log1 = unpack(datamsg.encode())
                                    state = ""
                                    if slow_start :
                                        state = "slowstart"
                                    elif congestion_avoidence:
                                        state = "congestion_avoidence "
                                    ts = time.time()
                                    addLog(log1[0],log1[1],log1[4],log1[3],log1[5],log1[6],state,cwnd,ts)
                                    continue
                                else:
                                    # break if not hit 3 dupilcates
                                    break
                            #     
                            elif acks_list[-1] < (sent_index[-1]+1)*(PKT_SIZE+119):
                                # get the index of packet to send
                                index = acks_list[-1] // 1000 
                                packet = packets[index]
                                # update sequence number
                                seq = (index+1)*(PKT_SIZE+119)+ rand
                                # RESEND packet of this ack_num
                                print("RESEND packet_num: ", index)
                                print("       seq_num: ", seq)
                                datamsg = createDataMessage(socket_port,str(packet),seq,1)
                                connection_socket.sendto(datamsg.encode(),(serverIP, serverPort))
                                dup_acks = 0
                                dup_ack_num = -1
                                total_sent+=1
                                log1 = unpack(datamsg.encode())
                                state = ""
                                if slow_start :
                                    state = "slowstart"
                                elif congestion_avoidence:
                                    state = "congestion_avoidence "
                                ts = time.time()
                                addLog(log1[0],log1[1],log1[4],log1[3],log1[5],log1[6],state,cwnd,ts)
                                continue

                            # no duplicate ACK    
                            else:  
                                if cwnd >= slow_start_threshold: 
                                    # AIMD phase
                                    print("!!! AIMD phase")
                                    slow_start_threshold = cwnd // 2
                                    cwnd += 1  
                                    congestion_avoidence = True
                                    slow_start =False
                                else:   
                                    # SLOW START phase
                                    print("!!! SLOW START phase")
                                    # double cwnd after each rtt if no dupliacte ACK
                                    cwnd *= 2  
                                    congestion_avoidence = False
                                    slow_start = True
                                    print("cwnd doubled")
                                break           
                    except socket.timeout:
                        print("--- TIMEOUT---", Time_out)
                        # TAHOE and RENO: Fast Retransmit phase, reset cwnd to intial size
                        print("!!! Fast Retransmit phase")
                        cwnd = 1    

                        enter_timeout = True
                        total_lost += 1
                        Time_out = Time_out*2
                        break
            # FIN is recieved    
            else:
                # send FIN message
                fin_sent = 0
                finmsg = createFinMessage(socket_port)
                print("sent fin msg when send_fin is TURE",finmsg)
                connection_socket.sendto(finmsg.encode(),(serverIP, serverPort))
                reply = unpack(finmsg.encode())
                if slow_start :
                        state = "slowstart"
                elif congestion_avoidence:
                    state = "congestion_avoidence"
                ts = time.time()
                addLog(reply[0],reply[1],reply[4],reply[3],reply[5],reply[6],state,cwnd,ts)
                fin_sent += 1
                # recieve ACK
                while True: 
                    try:
                        # recieve ACK from server to end connection
                        message, addr = connection_socket.recvfrom(1024)
                        print("receive ack,",message )
                        message = unpack(message)
                        if slow_start :
                                state = "slowstart"
                        elif congestion_avoidence:
                            state = "congestion_avoidence"
                        ts = time.time()
                        addLog(message[0],message[1],message[4],message[3],message[5],message[6],state,1,ts)

                        if message[3] == '1':
                            # END 
                            name = str(socket_port)+".txt"
                            with open(name, 'w') as fp:
                                fp.write("%s\n" % "Source,Destination,Message_Type,Message_Length,State,CWND,TimeStamp")
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
                            if slow_start :
                                    state = "slowstart"
                            elif congestion_avoidence:
                                state = "congestion_avoidence"
                            ts = time.time()
                            addLog(reply[0],reply[1],reply[4],reply[3],reply[5],reply[6],state,cwnd,ts)   
                            fin_sent += 1
                        else:
                            # END
                            name = str(socket_port)+".txt"
                            with open(name, 'w') as fp:
                                fp.write("%s\n" % "Source,Destination,Message_Type,Message_Length,State,CWND,TimeStamp")
                                for item in log:
                                    # write each item on a new line
                                    fp.write("%s\n" % item)
                                print('Done')
                            connection_socket.close()
                            exit(0)          
            
        # EOF, SEND last message with sequence number = 0
        end_msg = createDataMessage(socket_port,"",0,1)
        connection_socket.sendto(end_msg.encode(),(serverIP, serverPort))
        log1 = unpack(datamsg.encode())
        state = ""
        if slow_start :
            state = "slowstart"
        elif congestion_avoidence:
            state = "congestion_avoidence "
        ts = time.time()
        addLog(log1[0],log1[1],log1[4],log1[3],log1[5],log1[6],state,cwnd,ts)
        print("EOF message sent")
        
        # send FIN message
        fin_sent = 0
        finmsg = createFinMessage(socket_port)
        print("sent fin msg after last packet sent",finmsg)
        connection_socket.sendto(finmsg.encode(),(addr[0], message[0]))
        reply = unpack(finmsg.encode())
        if slow_start :
                state = "slowstart"
        elif congestion_avoidence:
            state = "congestion_avoidence"
        ts = time.time()
        addLog(reply[0],reply[1],reply[4],reply[3],reply[5],reply[6],state,cwnd,ts)
        fin_sent += 1
        message, addr = connection_socket.recvfrom(1024)
        
        # recieve ACK
        while True: 
            try:
                # recieve ACK from server to end connection
                message, addr = connection_socket.recvfrom(1024)
                print("receive ack,",message )
                message = unpack(message)
                if slow_start :
                        state = "slowstart"
                elif congestion_avoidence:
                    state = "congestion_avoidence"
                ts = time.time()
                addLog(message[0],message[1],message[4],message[3],message[5],message[6],state,1,ts)
                
                if message[3] == '1':
                    # END 
                    name = str(socket_port)+".txt"
                    with open(name, 'w') as fp:
                        fp.write("%s\n" % "Source,Destination,Message_Type,Message_Length,State,CWND,TimeStamp")
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
                    if slow_start :
                            state = "slowstart"
                    elif congestion_avoidence:
                        state = "congestion_avoidence"
                    ts = time.time()
                    addLog(reply[0],reply[1],reply[4],reply[3],reply[5],reply[6],state,cwnd,ts)   
                    fin_sent += 1
                else:
                    # END
                    name = str(socket_port)+".txt"
                    with open(name, 'w') as fp:
                        fp.write("%s\n" % "Source,Destination,Message_Type,Message_Length,State,CWND,TimeStamp")
                        for item in log:
                            # write each item on a new line
                            fp.write("%s\n" % item)
                        print('Done')
                    break

        plt.plot(transmission_round, congestion_window)
        plt.xlabel('transmission_round')

        plt.ylabel('congestion_window')
        plt.savefig(str(socket_port) + '_graph.png')
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
    recv_wind = '0000000000000000' # 16 bits
    data = '' # 64 bits
    message = src_port + dest_port + seq_num + ack_num + data_offset + ack + syn + fin + recv_wind + data        
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
    recv_wind = '0000000000000000' # 16 bits
    data = '' # 64 bits
    message = src_port + dest_port + seq_num + ack_num + data_offset + ack + syn + fin + recv_wind + data
    return  message

# create DATA packet
def createDataMessage(clientPort, data, seq_num, cwnd):
    src_port = addZero(bin(clientPort), 16) # 16 bits
    dest_port = addZero(bin(connection_socket_port), 16) # 16 bits
    seq_num = addZero(bin(seq_num),32) # 32 bits
    ack_num = '00000000000000000000000000000000' # 32 bits
    data_offset = '0011' # 4 bits
    ack = '0' # 1 bit
    syn = '0' # 1 bit
    fin = '0' # 1 bit
    recv_wind = addZero(bin(cwnd), 16) # 16 bits
    msg=""

    for char in data:
        msg+= str(bin(ord(char)))[2:]
        
    message = src_port + dest_port + seq_num + ack_num + data_offset + ack + syn + fin + recv_wind + data
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
    data= '' 
    recv_wind = '0000000000000000' # 16 bits
    message = src_port + dest_port + seq_num + ack_num + data_offset + ack + syn + fin + recv_wind + data
    return  message  

# unpack encoded messages
def unpack(message):
    # HEADER SIZE : 119
    message = message.decode()
    length = len(message)-119
    scr_port = message[:16]
    des_port = message[16:32]
    seq_num = message[32:64]
    ack_num = message[64:96]
    
    ack = message[100]
    syn = message[101]
    fin = message[102]
    recv_wnd = message[103:119]

    data = message[119:]
    return int(scr_port,2), int(des_port,2), data, ack, syn, fin, length, int(seq_num,2), int(ack_num,2), int(recv_wnd,2)

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
    connectWelcoming(args.dest_ip, args.dest_port, args.tcp_version)
    finish_ts = time.time()

    total_time = finish_ts-sent_ts
    print("Time taken to transfer ", args.input, ": ", total_time)

    num = len(filecontent) // 897
    remain = len(filecontent) % 897
    bandwidth = num*(1000)+remain+119  /total_time

    print("Total bandwith achieved: ", bandwidth)
    print("Packet loss observed: ", total_lost/total_sent)


    


    