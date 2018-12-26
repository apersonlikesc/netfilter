#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <asm/atomic.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/moduleparam.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_bridge.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zhang");

//static int pktcnt = 0;

#define NIPQUAD(addr) \
  ((unsigned char *)&addr)[0], \
  ((unsigned char *)&addr)[1], \
  ((unsigned char *)&addr)[2], \
  ((unsigned char *)&addr)[3]


//我们自己定义的hook回调函数 过滤函数
static unsigned int myhook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	__be32 sip,dip;
	//__u16 ack;
   	const struct iphdr *iph = ip_hdr(skb);
	//atomic_inc(&pktcnt);
	sip = iph->saddr;
        dip = iph->daddr;

	if(iph->protocol == IPPROTO_TCP)
	{
		char *data = NULL;
		struct tcphdr *tcph = NULL;
//ack(jialehuichucuo)
		//ack=tcph->ack;
		tcph = (struct tcphdr *)((char *)skb->data + (int)(iph->ihl * 4));
//shuju
		data = (char *)((int)tcph + (int)(tcph->doff * 4));
	 	printk("Got Packet tcp for source address: %u.%u.%u.%u destination address: %u.%u.%u.%u data:%s\n", NIPQUAD(sip),NIPQUAD(dip),data);
	}
	else if(iph->protocol == IPPROTO_UDP){
		printk("GOT udp\n");
		//return NF_DROP;
	}else if(iph->protocol == IPPROTO_ICMP){
		printk("find icmp\n");
		return NF_ACCEPT;
	}

   return NF_QUEUE;
}

//set hook info
	static struct nf_hook_ops nfho = 
	{
		.list =  {NULL,NULL},
		.hook=myhook_func, //回调函数是myhook_func
		.pf=PF_INET,       //协议类型
		.hooknum=NF_BR_POST_ROUTING,//挂载点
		.priority=NF_IP_PRI_FIRST,//优先级
	};

	static int __init myhook_init(void)
	{
	    return nf_register_hook(&nfho);
	}

	static void __exit myhook_fini(void)
	{
	    nf_unregister_hook(&nfho);
	}
	//初始化函数调用
	module_init(myhook_init);
	//卸载函数中调用
	module_exit(myhook_fini);
