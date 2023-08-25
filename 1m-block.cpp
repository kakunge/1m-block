#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <string.h>
#include <signal.h>
#include <iostream>
#include <fstream>
#include <unordered_set>

void filterOn() {
	system("sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0");
	system("sudo iptables -A INPUT -j NFQUEUE --queue-num 0");

	printf("netfilter on\n");
}

void filterOff() {
	system("sudo iptables -F");

	printf("\nnetfilter off\n");
}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

void signalHandler(int n) {
	filterOff();

	exit(0);
}

std::unordered_set<std::string> filterURLs;

static u_int32_t get_payload (struct nfq_data *tb) {
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);

	if (ntohs(ph->hw_protocol) != 0x0800)
		return id;

	if (ret >= 0) {
		printf("payload_len=%d\n", ret);
		dump(data, ret);
		printf("\n");
	}

	unsigned char ip[20];
	for (int i = 0; i < 20; i++) {
		ip[i] = data[i];
	}

	if (ip[9] != 0x06)
		return id;

	unsigned char tcp[20];
	for (int i = 0; i < 20; i++) {
		tcp[i] = data[i+20];
	}

	unsigned char tcpOffset = ((tcp[12] >> 4) * 4) - 20;

	unsigned char http[ret-20-20-tcpOffset];
	for (int i = 0; i < ret-20-20-tcpOffset; i++) {
		http[i] = data[i+20+20+tcpOffset];
	}

	std::string strHttp(reinterpret_cast<char*>(http));

	std::string target = "Host: ";
    size_t sidx = strHttp.find("Host: ");
    
    if (sidx != std::string::npos) {
        sidx += 6;
        size_t eidx = strHttp.find("\r\n", sidx);
        if (eidx != std::string::npos) {
            std::string host = strHttp.substr(sidx, eidx - sidx);

			std::unordered_set<std::string>::const_iterator iter = filterURLs.find(host);

			if (iter != filterURLs.end()) {
				return 0;
			}
        }
    }
	
	fputc('\n', stdout);

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
	u_int32_t id = get_payload(nfa);

	if (!id)
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

	printf("entering callback\n");
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void usage() {
	printf("syntax: 1m-block <site list file>\n");
	printf("sample: 1m-block top-1m.txt\n");
}

int main(int argc, char **argv) {
	if (argc != 2) {
		usage();
		return -1;
	}

	std::ifstream filterFile(argv[1]);

	if (!filterFile.is_open()) {
		printf("can't open file\n");

		return -1;
	}

	std::string filterURL;

	while (std::getline(filterFile, filterURL)) {
		int idx = filterURL.find(',');

		if (idx != std::string::npos) {
			int key = std::stoi(filterURL.substr(0, idx));
			std::string value = filterURL.substr(idx + 1);

			filterURLs.insert(value);
		}
	}

	filterFile.close();
	
	filterOn();

	signal(SIGINT, signalHandler);

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
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

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

