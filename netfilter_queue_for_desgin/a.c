#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>  
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>




static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    	u_int32_t id = 0;
    	struct nfqnl_msg_packet_hdr *ph;
//
   	ph = nfq_get_msg_packet_hdr(nfa);
  	if (ph) {
  		id = ntohl(ph->packet_id);
 	   }

 	printf("packet id: %u\n", id);
	printf("packet received (id=%u hw=0x%04x hook=%u)\n",id, ntohs(ph->hw_protocol), 		ph->hook);
    	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int    fd;
	int rv;
	char buf[4096];
	h = nfq_open();
//yi chang kong zhi
	
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}



    	printf("binding this socket to queue '0'\n");
        qh = nfq_create_queue(h,  0, &cb, NULL);


        if (!qh) {
                fprintf(stderr, "error during nfq_create_queue()\n");
                exit(1);
        }

        printf("setting copy_packet mode\n");


        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
                fprintf(stderr, "can't set packet_copy mode\n");
                exit(1);
        }


    	fd = nfq_fd(h);

	printf("Waiting for packets...\n");

	//
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		printf("packet got!\n");
		nfq_handle_packet(h, buf, rv);
	}

	printf("unbinding from queue 0\n");
    	nfq_destroy_queue(qh);
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
	printf("nfq_close START\n");
    	nfq_close(h);
    	return 0;
}
