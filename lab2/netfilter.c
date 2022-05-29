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

/* 用于描述我们的Netfilter挂钩
 * nf_hook_ops数据结构在linux/netfilter.h中定义
 * 我们定义两个nf_hook_ops结构体，一个传入的hook 和 一个传出的hook 
struct nf_hook_ops
{
  struct list_head list; //钩子链表
  nf_hookfn *hook;       //钩子处理函数
  struct module *owner;  //模块所有者
  int pf;                //钩子协议族
  int hooknum;           //钩子的位置值（PREROUTING、POSTOUTING、INPUT、FORWARD、OUTPUT五个位置）
  int priority;          //钩子的的优先级
}
 */
static struct nf_hook_ops post_hook;            

static unsigned int watch_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	if(!skb){ 
		return NF_ACCEPT; 
	}
  struct iphdr *ip = NULL;
  struct tcphdr *tcp = NULL;
  char *tcp_data = NULL;   // tcp data
  int tcp_payload_len = 0;
  ip = (struct iphdr *)skb_network_header(skb);
  tcp = (struct tcphdr *)skb_transport_header(skb);
  if (ip->protocol != IPPROTO_TCP || (tcp->dest != htons(443) && tcp->dest != htons(80))) {
      return NF_ACCEPT;
  }
  tcp_payload_len = ntohs(ip->tot_len) - (ip->ihl<<2) - (tcp->doff<<2);
  tcp_data = (char*)kmalloc(sizeof(char) * tcp_payload_len + 1, GFP_KERNEL);
  if (skb_copy_bits(skb, (ip->ihl<<2) + (tcp->doff<<2), tcp_data, tcp_payload_len) < 0) {
      return NF_ACCEPT;
  }
  tcp_data[tcp_payload_len] = '\0';
  printk("data: %s", tcp_data);
  // 丢弃url存在.exe关键字的tcp报文, 经过HTTPS加密的url无法过滤
  if (strstr(tcp_data, ".exe") != NULL) {
    printk("成功丢弃存在后缀名为.exe的url");
    return NF_DROP;
  }
	return NF_ACCEPT;
}

/*
内核模块中的两个函数init_module() ：表示起始 和 cleanup_module() ：表示结束 
*/ 
int init_module()
{
	/*hook函数指针指向watc_out*/ 
  post_hook.hook     = watch_out;
  /*协议簇为ipv4*/  
  post_hook.pf       = PF_INET;
  /*优先级最高*/
  post_hook.priority = NF_IP_PRI_FIRST;
  post_hook.hooknum  = NF_INET_POST_ROUTING;

   /*将post_hook注册，注册实际上就是在一个nf_hook_ops链表中再插入一个nf_hook_ops结构*/ 
  nf_register_net_hook(&init_net ,&post_hook);
  return 0;
}

void cleanup_module()
{
	/*将post_hook取消注册，取消注册实际上就是在一个nf_hook_ops链表中删除一个nf_hook_ops结构*/ 
  nf_unregister_net_hook(&init_net ,&post_hook);
}

MODULE_LICENSE("GPL");