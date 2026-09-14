#include <asm-generic/errno-base.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <signal.h>


// this is in the GNU C library but is rewritten here to remove dependency
struct icmphdr
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    union 
    {
        struct 
        {
            uint16_t id;
            uint16_t sequence;
        } echo;
        uint32_t gateway;
        struct 
        {
            uint16_t __unused;
            uint16_t mtu;
        } frag;
    } un;
};

// modified from https://en.wikipedia.org/wiki/Internet_checksum#Algorithm
uint16_t checksum(int count, const void* addr)
{
    /* Compute internet checksum for "count" bytes 
    *   beginning at location "addr".
    */
    uint32_t sum = 0;
    const uint16_t *ptr = (const uint16_t *) addr;

    while(count > 1) 
    {
        sum += *ptr++;
        count-=2;
    }

    // add leftover byte
    if(count > 0)
    {
        sum += * (const uint8_t *)ptr;
    }

    // turn 32-bit sum into 16 bits 
    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

volatile __sig_atomic_t RUNNING = 1;

void handle_sigint(int sig) 
{
    RUNNING = 0;
}



int main(int argc, char* argv[])
{
    // setup signal handler for graceful shutdown
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if(sigaction(SIGINT, &sa, NULL) == -1)
    {
        printf("Error: couldn't set up signal handler\n");
        return -1;
    }

    // 1.
    int sfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sfd == -1)
    {
        if(errno == EPERM)
        {
            printf("errno == EPERM: system missing CAP_NET_RAW which allows programs to use raw sockets without root privileges\n");
            close(sfd);
            return -1;
        }
        else 
        {
            printf("Error: %s\n", strerror(errno));
            close(sfd);
            return -1;
        }
    }

    // set timeout
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    if(setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        printf("Error: setting socket timeout failed\n");
        close(sfd);
        return -1;
    }

    //3. test checksum
    uint8_t checksum_test[] = {0xA8, 0x4D, 0x00, 0x00};
    uint16_t csum = checksum(2, &checksum_test);
    // x86 uses little endianness, low byte at low address
    checksum_test[3] = (uint8_t)((csum & 0xff00) >> 8);
    checksum_test[2] = (uint8_t)(csum & 0x00ff);

    // sum of the 1's complement of all bytes should be zero. If it isn't, theres endianness issues.
    uint16_t checksum_valid = checksum(4, checksum_test);
    if(checksum_valid != 0)
    {
        printf("checksum failed test. checksum result was: %u\n", checksum_valid);
        printf("checksum value calculated by formula was: %u\n", csum);
        close(sfd);
        return -1;
    }

    struct timespec next;
    uint16_t seq = 0;
    double cumulative_ms = 0;
    while(RUNNING)
    {
        // add a payload containing timespec
        struct timespec now;
        timespec_get(&now, TIME_UTC);
        
        struct timespec sleep;
        sleep.tv_sec = next.tv_sec - now.tv_sec;
        sleep.tv_nsec = next.tv_nsec - now.tv_nsec;
        if(next.tv_sec > now.tv_sec || (next.tv_sec == now.tv_sec && next.tv_nsec >= now.tv_nsec))
        {
            if(sleep.tv_nsec < 0)
            {
                sleep.tv_sec--;
                sleep.tv_nsec+=1e9;
            }
            nanosleep(&sleep, NULL);
        }

        seq++;

        // 2. Packet construction (could alternatively do this as a buffer of bytes instead of struct: uint8_t packet[])
        struct icmphdr echo;
        memset(&echo, 0, sizeof(echo));
        echo.type = 8; // type == echo request
        echo.code = 0;
        echo.un.echo.id = getpid();
        echo.un.echo.sequence = seq;

        timespec_get(&now, TIME_UTC);
        memcpy(&next, &now, sizeof(now));
        next.tv_sec+=1; // will ping by the next 5 seconds;


        // create packet of bytes
        size_t packet_len = sizeof(now) + sizeof(echo);
        char *packet = malloc(packet_len);
        memcpy(packet, &echo, sizeof(echo));
        memcpy(packet + sizeof(echo), &now, sizeof(now));

        echo.checksum = checksum(packet_len, packet);
        memcpy(packet, &echo, sizeof(echo));

        // 4. SEND
        // get ip from first CLA 
        if(argc < 2)
        {
            printf("Error: binary requires a destination address as the first argument\n");
            close(sfd);
            return -1;
        }
        char* dest = argv[1];


        //convert addr into 4 byte unsigned integer
        struct sockaddr_in saddr;
        memset(&saddr, 0, sizeof(saddr));
        saddr.sin_family = AF_INET;
        int ret = inet_pton(AF_INET, argv[1], &saddr.sin_addr);
        if(ret <= 0) 
        {
            printf("Error: failed to parse address string, should match x.x.x.x\n");
            close(sfd);
            return -1;
        }

        size_t bytes_sent = sendto(sfd, packet, packet_len, 0, (struct sockaddr*)&saddr, sizeof(saddr));
        if(bytes_sent < packet_len)
        {
            printf("Error: only sent %ld/%ld bytes\n", bytes_sent, packet_len);
            close(sfd);
            return -1;
        }

        // 5. RECEIVE + PARSE
        char buf[256];
        socklen_t saddrlen = sizeof(saddr);
        char* recvd_packet = malloc(packet_len); // should be same length as sent packet (constant anyway)
        struct icmphdr recvd_header;
        int timeout = 0;
        while(1)
        {
            // check if we have been waiting more than a second
            timespec_get(&now, TIME_UTC);
            

            size_t bytes_recvd = recvfrom(sfd, buf, 256, 0, (struct sockaddr*)&saddr, &saddrlen);

            if(bytes_recvd == -1)
            {
                printf("Request timeout for icmp_seq %ud\n", seq);
                timeout = 1;
                break;
            }

            // get size of IP header 
            int IHL_bytes = (buf[0] & 0x0f)*4;
            // printf("Received packet with IP header of size %d\n", IHL_bytes);
            // extract ICMP packet
            if(bytes_recvd <= IHL_bytes)
            {
                continue;
            }
            memcpy(recvd_packet, buf+IHL_bytes, packet_len);

            // 6. Matching
            // Need to match this ICMP packet to the one we sent
            // extract the header
            memcpy(&recvd_header, recvd_packet, sizeof(recvd_header));
            if(recvd_header.type != 0 // echo reply
                || recvd_header.code != echo.code)  
            {
                // printf("Received header but didn't match code\n");
                continue; // wasn't our reply packet, on to the next;
            }
            else if(recvd_header.un.echo.id != getpid())
            {
                // printf("Received header but echo id didn't match pid\n");
                continue;
            }
            else if(recvd_header.un.echo.sequence != seq)
            {
                // printf("Received header but for wrong sequence\n");
            }
            else 
            {
                break;
            }
        }
        if(timeout)
        {
            continue;
        }

        // 7. RTT 
        // find current timestamp and find difference between one sent 
        struct timespec recvd_stamp;
        memcpy(&recvd_stamp, recvd_packet + sizeof(recvd_header), sizeof(recvd_stamp));
        timespec_get(&now, TIME_UTC);

        // find difference
        time_t d_sec = now.tv_sec - recvd_stamp.tv_sec;
        time_t d_nanos = now.tv_nsec - recvd_stamp.tv_nsec;

        time_t rtt = d_sec * 1e9 + d_nanos;
        printf("seq = %u time = %f ms\n", seq, 1e-6*rtt);
        cumulative_ms+=1e-6*rtt;
    }

    // print averages
    double avg_ms = cumulative_ms/seq;
    printf("Average RTT: %lf\n", avg_ms);

    close(sfd);

}

