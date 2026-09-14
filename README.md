# ping 
This repo contains a simple ping binary implemented in C used to learn about sockets and IP

```bash
gcc ping.c -o ping 
sudo setcap cap_net_raw+ep ping 
./ping x.x.x.x
```

## stages
1. SOCKET SETUP
   - socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
   - Fail loudly and explain if errno == EPERM (missing CAP_NET_RAW)

2. PACKET CONSTRUCTION
   - Build struct icmphdr (or hand-roll: type, code, checksum, id, seq)
   - type = ICMP_ECHO (8), code = 0
   - Embed a payload containing: your own PID (as identifier) and a
     struct timeval / timespec (send timestamp) — you need this back
     to compute RTT, since the kernel doesn't do it for you

3. CHECKSUM
   - Implement RFC 1071 one's-complement checksum yourself
   - Checksum field must be zero during computation, then set
   - Function signature: uint16_t icmp_checksum(void *data, size_t len)
   - Test it against a known-good packet capture before trusting it

4. SEND
   - sendto() the constructed packet to the target IP
   - No manual IP header needed on send (kernel fills it for RAW+ICMP
     unless you set IP_HDRINCL — don't set it, out of scope here)

5. RECEIVE + PARSE
   - recvfrom() — you WILL receive the IP header prepended, even
     though you didn't send one
   - Read the IP header's IHL field (low 4 bits of first byte) to
     compute IP header length in bytes: IHL * 4
   - Skip that many bytes to reach the ICMP payload

6. MATCHING
   - Your raw socket receives ALL ICMP traffic to this host, not just
     your replies (other processes' pings, unrelated ICMP errors, etc.)
   - Discard any reply whose identifier != your PID or whose type !=
     ICMP_ECHOREPLY (0)

7. RTT
   - On accepted reply, timestamp now minus timestamp embedded in
     the (echoed-back) payload = RTT

8. SEQUENCE
   - Loop: increment sequence number each send, print "seq=N time=X ms"
   - Handle timeout: if no matching reply within e.g. 1s, print
     "Request timeout for icmp_seq N" and move on

