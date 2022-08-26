import dpkt, socket, collections
#dsender = '130.245.145.12'
#dreciever = '128.208.2.198'
#filename = 'assignment2.pcap'

def main(filename):
    flows = {}
    firstpacket = True
    for ts, pkt in dpkt.pcap.Reader(open(filename, 'rb')):
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type==dpkt.ethernet.ETH_TYPE_IP:   #check if IP packet
            ip = eth.data
            if ip.p==dpkt.ip.IP_PROTO_TCP:   #check if TCP packet
                tcp = ip.data
                
                if firstpacket: #identify sender, receiver IPs, and intial RWND for first packet
                    sender = ip.src
                    receiver = ip.dst
                    rwnd = tcp.win
                    firstpacket = False

                if ip.src==sender:
                    identifier = (tcp.sport, socket.inet_ntoa(ip.src), tcp.dport, socket.inet_ntoa(ip.dst))
                    if identifier in flows:
                        flow = flows[identifier]
                        seq = tcp.seq
                        if flow[2] != seq: #if the current sequence is different from the previous sequence
                            flow[2] = seq 
                            if flow[0] == 0: #checks if first or second transaction
                                flow[3] = (tcp.seq, tcp.ack, rwnd, tcp.win)
                                flow[0] = 1
                            elif flow[1] == 0:
                                flow[4] = (tcp.seq, tcp.ack, rwnd, tcp.win)
                                flow[1] = 1
                        flow[5] += len(tcp)
                        flow[9] += [tcp.seq]

                        if flow[10] != 0:
                            if ts - flow[11] < 0.8*flow[10]:
                                flow[12] += 1
                            else:   #next RTT interval
                                flow[13] += [flows[identifier][12]]
                                flow[12] = 0
                                flow[11] = ts
                                                          
                    else: #adds new flow to flows{} if identifier is not dictionary
                        flows[identifier] = [0, 0, tcp.seq, (), (), len(tcp), ts, ts, [], [], 0, 0, 0, []]
                else: #"sender" is reciever
                    identifier = (tcp.dport, socket.inet_ntoa(ip.dst), tcp.sport, socket.inet_ntoa(ip.src))
                    flow = flows[identifier]
                    flow[7] = ts #continuously stores reciever ts, final ts should be last transaction from receiver
                    flow[8] += [tcp.ack]
                    if tcp.flags==18: #indicates SYN/ACK packet(dpkt.tcp.TH_SYN is 2, dpkt.tcp.TH_ACK is 16), store initial RTT 
                        flow[10] = ts - flow[6]
                        flow[11] = ts
            else:
                continue
        else:
            continue
        
    print("# of TCP flows: " + str(len(flows)))
    print("-----------------------------------------------------------------")
    for identifier, flow in flows.items():
        print("Unique Identifier: " + str(identifier))
        for i, info in enumerate(flow[3:5], 1):
            print("TRANSACTION " + str(i))
            print("\tSeq #: " + str(info[0]))
            print("\tAck #: " + str(info[1]))
            print("\tInitial RWND: " + str(info[2]))
            print("\tScaling factor: " + str(info[3]))
        print("Throughput: " + str((flow[5]/(flow[7]-flow[6]))) + " bytes/sec") #throughput defined by total flow bytes/time passed from SYN->FIN
        if len(flow[13]) > 2:
            print("CWNDS: " + str(flow[13][:3]))
        else:
            print("CWNDS: " + str(flow[13]))
        
        ackcounter = collections.Counter(flow[8])
        tripleack = 0
        for count in ackcounter.values(): #more than 3 duplicate acks
            if count > 2:
                tripleack += 1
        print("Fast retransmissions: " + str(tripleack))
        seqcounter = collections.Counter(flow[9])
        timeouts = 0
        for count in seqcounter.values():   #more than 2 duplicate seqs
            if count > 1:
                timeouts += 1
        print("Timeout retransmissions: " + str(timeouts-tripleack))
        print("-----------------------------------------------------------------")
        
filename = input("enter filename: ")
main(filename)
