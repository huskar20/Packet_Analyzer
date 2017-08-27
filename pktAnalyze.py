#***********************************************************************
'''
PACKET TRACE ANALYZER
CREATED BY HUSEYIN KARAARSLAN FOR CS4558 - LAB2
2016	
'''
#************************************************************************
import dpkt, sys, socket, time, collections
import operator

start_time=time.time()
print ">>>>>>>>>>>>>>>>> Created By Huseyin Karaarslan <<<<<<<<<<<<<<<<"
print "Script Started"
f = open('trace2.pcap','rb')
b = f.read(dpkt.pcap.FileHdr.__hdr_len__)
fh = dpkt.pcap.LEFileHdr(b)

f_for_pcap = open('trace2.pcap','rb')
pcap = dpkt.pcap.Reader(f_for_pcap)

ip4_count=0
non_ip4=0
byte_dict = {}  
cdf_bytes = {}
cdf_src =[]
print "Snaplen: ", fh.snaplen
##print "Major version:", fh.v_major 
print "Minor version: ", fh.v_minor
print "DLT: ", fh.linktype
f.close()
check_first_ts = False
pck_counter = 0
protocol_list = []
ip_src_list =[]
ip_dst_list = []
packet_size_dist={}
size_lst =[]
src_lst =[]

for ts, data in pcap:
  pck_counter= pck_counter+1
  if check_first_ts == False:
  	 print "First Timestamp: ", + ts
  	 first_packet_ts =ts
  	 check_first_ts = True
  e = dpkt.ethernet.Ethernet(data)
  ip = e.data
  protocol_list.append(ip.p)
  #packet_size_dist.append(ip.len)
  if ip.len not in packet_size_dist:
    packet_size_dist[ip.len]=1
  else:
    packet_size_dist[ip.len] += 1
    
  if socket.inet_ntoa(ip.src) not in byte_dict:
    byte_dict[socket.inet_ntoa(ip.src)] = ip.len
  else:
    byte_dict[socket.inet_ntoa(ip.src)] += ip.len

  if (ip.v == 4):
      ip4_count = ip4_count + 1
      ip_src_list.append(socket.inet_ntoa(ip.src))
      ip_dst_list.append(socket.inet_ntoa(ip.dst))
  else:  
  	  non_ip4 = non_ip4 + 1

#*********************TEST CODE AREA*************************************
'''
  if ((pck_counter%10000) == 0):
'''
#************************************************************************
f_for_pcap.close()
sf = open("size_dist.dat","w")
for x  in packet_size_dist:
	strng = str(x) + ";" + str(packet_size_dist[x]) +"\n"
	sf.write(strng)
sf.close()       	  
last_packet_ts=ts
sorted_byteDict = sorted(byte_dict.items(), key=operator.itemgetter(1), reverse=True)	

for ip, b in sorted_byteDict:
    try:
        cdf_bytes[b] += 1

    except:
        cdf_bytes[b] = 1

sorted_cdfByte =sorted(cdf_bytes.items(), key=operator.itemgetter(0), reverse=False)
for b, size in sorted_cdfByte:
	size_lst.append(b)
	src_lst.append(size)

sf = open("CDF.dat","w")
for x in range(0, len(src_lst)) :
	val = float(size_lst[x])/len(sorted_byteDict)
	strng = str(size_lst[x]) + ";" + str(src_lst[x])  + ";" + str(val) +"\n"
	sf.write(strng)
sf.close()    
print "File write process is finally finished :)"
print "#IP4: ", + ip4_count
print "#Non-IP4: ", + non_ip4
print "Average Packet Rate: " + "%", + ((pck_counter/(last_packet_ts-first_packet_ts))*100)
print "Packet Protocol Distribution is: "+ str(collections.Counter(protocol_list))
print str(len(set(ip_src_list))) + " unique ip source addresses."
print str(collections.Counter(ip_src_list).most_common(1)) + " sent the most packets"
print str(len(set(ip_dst_list))) + " unique ip destination addresses."
print str(collections.Counter(byte_dict).most_common(1)) + " sent the most bytes" 
print str(ip4_count) + " Data checked and file written in ", + time.time()-start_time 
sys.exit(-1)
