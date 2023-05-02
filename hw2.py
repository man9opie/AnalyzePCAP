import dpkt
import socket



count = 0
class Flows:
    def __init__(self):
        self.flows = []
        self.count_flow = 0
    def addflow(self,syn):##syn is a flow list
        self.flows.append(syn)
        self.count_flow +=1
        ##print(1)
    def addpacket_to_list(self,packet):
        for flow_list in self.flows:
            if (flow_list.sip == packet.sip and flow_list.sp == packet.sp and flow_list.dip == packet.dip and flow_list.dp == packet.dp) or \
            (flow_list.dip == packet.sip and flow_list.dp == packet.sp and flow_list.sip == packet.dip and flow_list.sp == packet.dp):
                flow_list.addpacket(packet)
                
    def numflow(self):
        return self.count_flow
    def flowlist(self,num):
        return self.flows[num]
    def print(self):
        c = 0
        for flow_list in self.flows:
            c+=1
            flow_list.print(c)
            
    
class Flow_list:
    def __init__(self,sip,sp,dip,dp,tcp):
        self.sip = sip
        self.sp = sp
        self.dip = dip
        self.dp = dp
        self.tcp = tcp
        self.flows = []
        self.count_packet = 0
        self.time = 0
        self.first_ts = 0
        self.found = True
        self.total_byte = 0
        self.count = 0
        self.limit = 0
        self.counter = [0,0,0]
        self.cwnd = []
        self.count_out =0
        self.num_triple_dup_ack = 0
        self.num_timeout = 0
        self.num_other = 0
    def addpacket(self, packet):
        if not packet in self.flows:
            self.flows.append(packet)
            self.count_packet+=1
            self.time = packet.ts
            if packet.sp == self.sp:
                self.total_byte += len(packet.tcp)
            if self.found:
                
                self.first_ts = packet.ts
                self.found = False
                return
            
            
    def timeout(self):
        receive = None
        i = -1
        found = False
        for packet in self.flows:
            i+=1
            if receive == None:
                receive = packet
                
                continue
            if receive.tcp.seq == self.flows[i].tcp.seq and receive.tcp.ack == self.flows[i].tcp.ack and found == True:
                continue
            if found == True and receive.tcp.seq != packet.tcp.seq and receive.tcp.ack != packet.tcp.ack:
                receive = packet
                found = False
                continue
            if  (packet.tcp.flags & dpkt.tcp.TH_ACK) and found == False and i+3 < len(self.flows):
                if receive.tcp.seq == self.flows[i+1].tcp.seq and receive.tcp.ack == self.flows[i+1].tcp.ack:
                    if receive.tcp.seq == self.flows[i+2].tcp.seq and receive.tcp.ack == self.flows[i+2].tcp.ack:
                        if receive.tcp.seq == self.flows[i+3].tcp.seq and receive.tcp.ack == self.flows[i+3].tcp.ack:
                            
                            self.num_triple_dup_ack+=1
                            found = True
                if receive.ts - self.flows[i-1].ts>0.01:
                    found = True
                    self.num_timeout+=1
                else:
                    self.num_other +=1
            receive = packet  
    def numpacket(self):
        return self.count_packet
    def findpacket(self,num):
        return flows[num]
    def print(self,num):
        ##print(self.cwnd[0])
        print("-------------------------------------------------------------------------------------------------")
        print("Flow "+str(num)+": ")
        print("Source Port: "+str(self.sp)+", Source IP: "+str(self.sip) + ", Destination Port: "+str(self.dp)+", Destination IP: "+str(self.dip))
        seq = self.flows[2].tcp.seq
        ack = self.flows[2].tcp.ack
        win = self.flows[2].tcp.win
        ip = self.flows[2].sip
        for packet in self.flows:
            if packet.sip == self.sip:
                self.counter[0] += 1
            if packet.tcp.seq == ack:
                seq2 = packet.tcp.seq
                ack2 = packet.tcp.ack
                win2 = packet.tcp.win
                self.count+=1
                break

        for packet in self.flows:
            if packet.tcp.seq == ack2:
                seq3 = packet.tcp.seq
                ack3 = packet.tcp.ack
                win3 = packet.tcp.win
                
                break
        
        for packet in self.flows:
            if packet.sip == self.sip:
                self.counter[1] += 1
            if packet.tcp.seq == ack3:
                seq4 = packet.tcp.seq
                ack4 = packet.tcp.ack
                win4 = packet.tcp.win
                if self.count == 1:
                    self.count+=1
                    continue
                break

        for packet in self.flows:
            if packet.tcp.seq == ack4:
                seq5 = packet.tcp.seq
                ack5 = packet.tcp.ack
                win5 = packet.tcp.win
                break
        count = 0
        for packet in self.flows:
            self.counter[2] += 1
            if packet.tcp.seq == ack5:
                seq6 = packet.tcp.seq
                ack6 = packet.tcp.ack
                win6 = packet.tcp.win
                if count < 2:
                    count+=1
                    continue
                break
        self.counter[0]-=1
        self.counter[1]-=2
        self.counter[2]-=3
        print("First Transaction:")
        print("SEND Sequence Number: " + str(seq) + ", ACK: "+str(ack)+", Receive Window Size: "+str(win))
        ##print(ip)
        print("RECV Sequence Number: " + str(seq2) + ", ACK: "+str(ack2)+", Receive Window Size: "+str(win2))
        ##print(ip2)
        print("Second Transaction:")
        print("SEND Sequence Number: " + str(seq3) + ", ACK: "+str(ack3)+", Receive Window Size: "+str(win3))
        print("RECV Sequence Number: " + str(seq4) + ", ACK: "+str(ack4)+", Receive Window Size: "+str(win4))
        
        time = self.time - self.first_ts
        
        t = self.total_byte/time
        t = "{:.3f}".format(t)
        time = "{:.3f}".format(time)
        print("Duration: "+str(time) + "   Total Byte: "+str(self.total_byte))
        print("Throughput: " + str(t)+" byte/sec")
        if self.counter[2] > 0:
            print("Congestion window size: " + str(self.counter[0])+", "+str(self.counter[1])+", "+str(self.counter[2]))
        elif self.counter[1] > 0:
            print("Congestion window size: " + str(self.counter[0])+", "+str(self.counter[1]))
        else:
            print("Congestion window size: " + str(self.counter[0]))
        self.timeout()
        print("Retransmission: " + str(self.num_triple_dup_ack+self.num_timeout)) 
class Packet:
    def __init__(self,sip,sp,dip,dp,tcp,ts):
        self.sip = sip
        self.sp = sp
        self.dip = dip
        self.dp = dp
        self.tcp = tcp
        self.ts = ts
        
        
    

flows = Flows()

def analysis_pcap_tcp(pcap):
    count = 0
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        src_port = tcp.sport
        dst_port = tcp.dport
        if isinstance(tcp, dpkt.tcp.TCP):
            if tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK:
                flow_list = Flow_list(src_ip,src_port,dst_ip,dst_port,tcp)
                flow_packet = Packet(src_ip,src_port,dst_ip,dst_port,tcp,ts)
                flows.addflow(flow_list) ## append a 
                flows.addpacket_to_list(flow_packet)
            else: 
                flow_packet = Packet(src_ip,src_port,dst_ip,dst_port,tcp,ts)
                flows.addpacket_to_list(flow_packet)

                

               


def main():

    file_name = r"C:\Users\a1069\Desktop\hw2\assignment2.pcap"
    file_name = input("Enter your file name: ")
    with open(file_name, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        analysis_pcap_tcp(pcap)
    
    
    flows.print()

if __name__ == "__main__":
    main()