analysis_pcap_tcp
cyongc

myparser.py

Program will ask for user to input pcap file name. Ensure any additional test files aside from sample.pcap is included in main folder. Error raised when non-pcap file is inputted

Libraries used: dpkt, socket, collections
INPUT - .pcap file
OUTPUT - # of TCP flows, for each TCP flow: unique identifiers (src port, src IP, dest port, dest IP), first two transaction's seq #, ack #, and RWND size, sender throughput, CWND sizes, # of retransmissions occurred due to triple duplicate ack, # of retransmissions occurred due to timeouts


flows[identifier][i] dictionary index definitions
i	Usage
0	Transaction 1 tracker
1	Transaction 2 tracker
2	Sequence # tracker
3	Transaction 1 info (sequence #, ack #, rwnd, scaling factor)
4	Transaction 2 info
5	Total flow bytes sent by sender
6	First SYN timestamp
7	last receiver packet timestamp (assume FIN)
8	list of acks from receiver->sender
9	list of seqs from sender->receiver
10	initial estimated RTT
11	last RTT timestamp
12	packet count
13	CWND list