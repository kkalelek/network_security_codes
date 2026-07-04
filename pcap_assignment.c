#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>

/* Ethernet Header */
struct ethheader {
    u_char  ether_dhost[6];
    u_char  ether_shost[6];
    u_short ether_type;
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4,
                       iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3,
                       iph_offset:13;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr     iph_sourceip;
    struct in_addr     iph_destip;
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int   tcp_seq;
    u_int   tcp_ack;
    u_char  tcp_offx2;

#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)

    u_char  tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};


/* MAC 주소 출력 함수 */
void print_mac(const u_char *mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}


/* 패킷 처리 함수 */
void got_packet(u_char *args,
                const struct pcap_pkthdr *header,
                const u_char *packet)
{
    (void)args;

    /* 최소 Ethernet Header 길이 확인 */
    if (header->caplen < sizeof(struct ethheader)) {
        return;
    }

    /* =========================
       1. Ethernet Header
       ========================= */
    const struct ethheader *eth =
        (const struct ethheader *)packet;

    /* IPv4가 아니면 무시 */
    if (ntohs(eth->ether_type) != 0x0800) {
        return;
    }

    printf("\n========================================\n");

    printf("[Ethernet Header]\n");

    printf("Source MAC      : ");
    print_mac(eth->ether_shost);
    printf("\n");

    printf("Destination MAC : ");
    print_mac(eth->ether_dhost);
    printf("\n");


    /* =========================
       2. IP Header
       ========================= */
    const struct ipheader *ip =
        (const struct ipheader *)
        (packet + sizeof(struct ethheader));

    /* IP Header Length 계산 */
    int ip_header_len = ip->iph_ihl * 4;

    /* 잘못된 IP Header 방지 */
    if (ip_header_len < 20) {
        return;
    }

    /* TCP가 아니면 무시 */
    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }

    printf("\n[IP Header]\n");

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET,
              &ip->iph_sourceip,
              src_ip,
              sizeof(src_ip));

    inet_ntop(AF_INET,
              &ip->iph_destip,
              dst_ip,
              sizeof(dst_ip));

    printf("Source IP       : %s\n", src_ip);
    printf("Destination IP  : %s\n", dst_ip);


    /* =========================
       3. TCP Header
       ========================= */
    const struct tcpheader *tcp =
        (const struct tcpheader *)
        (packet
         + sizeof(struct ethheader)
         + ip_header_len);

    /* TCP Header Length 계산 */
    int tcp_header_len = TH_OFF(tcp) * 4;

    /* 잘못된 TCP Header 방지 */
    if (tcp_header_len < 20) {
        return;
    }

    printf("\n[TCP Header]\n");

    printf("Source Port      : %u\n",
           ntohs(tcp->tcp_sport));

    printf("Destination Port : %u\n",
           ntohs(tcp->tcp_dport));


    /* =========================
       4. HTTP Message
       ========================= */

    int total_ip_len = ntohs(ip->iph_len);

    int payload_len =
        total_ip_len
        - ip_header_len
        - tcp_header_len;

    const u_char *payload =
        packet
        + sizeof(struct ethheader)
        + ip_header_len
        + tcp_header_len;

    printf("\n[HTTP Message]\n");

    if (payload_len > 0) {

        for (int i = 0; i < payload_len; i++) {

            unsigned char c = payload[i];

            if (isprint(c) ||
                c == '\n' ||
                c == '\r' ||
                c == '\t') {

                putchar(c);
            }
            else {
                putchar('.');
            }
        }

        printf("\n");
    }
    else {
        printf("No Application Data\n");
    }

    printf("========================================\n");
}


int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    struct bpf_program fp;

    /* TCP 패킷만 캡처 */
    char filter_exp[] = "tcp";

    bpf_u_int32 net = 0;


    /* Step 1:
       enp0s3 인터페이스에서
       실시간 패킷 캡처 시작 */
    handle = pcap_open_live(
        "ens33",
        BUFSIZ,
        1,
        1000,
        errbuf
    );

    if (handle == NULL) {
        fprintf(stderr,
                "pcap_open_live failed: %s\n",
                errbuf);
        return 1;
    }


    /* Step 2:
       TCP 필터 컴파일 */
    if (pcap_compile(
            handle,
            &fp,
            filter_exp,
            0,
            net) == -1) {

        fprintf(stderr,
                "pcap_compile failed: %s\n",
                pcap_geterr(handle));

        pcap_close(handle);
        return 1;
    }


    /* TCP 필터 적용 */
    if (pcap_setfilter(handle, &fp) != 0) {

        pcap_perror(handle, "Error");

        pcap_freecode(&fp);
        pcap_close(handle);

        return 1;
    }


    printf("TCP Packet Sniffing Start...\n");
    printf("Press Ctrl+C to stop.\n");


    /* Step 3:
       패킷 지속 캡처 */
    pcap_loop(
        handle,
        -1,
        got_packet,
        NULL
    );


    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}
