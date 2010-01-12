#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <strings.h>
#include <netinet/in.h>

#include "capture.h"
#include "edonkey.h"
#include "bittorrent.h"

int capture(char *interface, char bittorrent, char edonkey) {
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_handle;
	int pcap_return;
	char capture_options = 0;

	if (bittorrent) {
		capture_options |= CAPTURE_BITTORRENT;
	}

	if (edonkey) {
		capture_options |= CAPTURE_EDONKEY;
	}

	if ((pcap_handle = pcap_open_live(interface, BUFSIZ, 0, 1000, pcap_errbuf)) == NULL) {
		warnx("could not open device '%s' - %s", interface, pcap_errbuf);
		return EXIT_FAILURE;
	}

	pcap_return = pcap_loop(pcap_handle, 0, capture_packet, (u_char *) &capture_options);

	if (pcap_return == -1) {
		warnx("pcap returns packet capture failure - %s", pcap_geterr(pcap_handle));
	} 

	pcap_close(pcap_handle);

	if (pcap_return == -1) {
		return EXIT_FAILURE;
	} else {
		return EXIT_SUCCESS;
	}
}

void capture_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
	unsigned char capture_options = *user, ip_version, ip_size, ip_protocol, src_addr[4], dst_addr[4], source;
	unsigned short ethernet_protocol, src_port, dst_port, ptr = 0, ip_length, udp_length, tcp_length, payload_length = 0;
	struct decoded_hash *result = NULL, *itr;

	/* Do we have enough data to even have a start to an IP packet? */
	/* Ether frame is 14 bytes (2 * 6 char + 1 x short) */
	if (h->caplen < 15) {
		return;
	}

	/* Skip ethernet addresses. */
	ptr = 12;

	/* Extract ethernet payload type. */
	bcopy(&bytes[ptr], &ethernet_protocol, sizeof(unsigned short));
	ethernet_protocol = ntohs(ethernet_protocol);
	ptr += sizeof(unsigned short);

	/* If the payload is not IP then quit now. */
	if (ethernet_protocol != 0x0800) {
		return;
	}

	/* Extract the IP version. */
	ip_version = bytes[ptr] >> 4;
        ip_size = (bytes[ptr] & 0x0f) << 2;
	ptr += sizeof(unsigned char);

	/* Check to see if we're IPv4. */
	if (ip_version != 4) {
		return;
	}

	/* Do we now have a full IP header to decode? */
	if (h->caplen < (ptr + ip_size)) {
		return;
	}

	/* Skip TOS bits */
	ptr += 1;

	/* Extract total length. */
	bcopy(&bytes[ptr], &ip_length, sizeof(unsigned short));
	ip_length = ntohs(ip_length);
	ptr += sizeof(unsigned short);

	/* Skip ID, flags, ttl. */
	ptr += 5;

	/* Extract protocol number. 0x06 = tcp, 0x11 = udp */
	ip_protocol = bytes[ptr];
	ptr += sizeof(unsigned char);

	/* Abort early if we don't have tcp or udp. */
	if (ip_protocol != 0x06 && ip_protocol != 0x11) {
		return;
	}

	/* Skip checksum. */
	ptr += 2;
	
	/* Extract source and destination IP address, this will move if it's IPv6.*/
	bcopy(&bytes[ptr], &src_addr, sizeof(unsigned char) * 4); 
	ptr += sizeof(unsigned char) * 4;
	bcopy(&bytes[ptr], &dst_addr, sizeof(unsigned char) * 4);
	ptr += sizeof(unsigned char) * 4;

	/* Check to see if we have the ports. */
	if (h->caplen < (ptr + (2 * sizeof(unsigned short)))) {
		return;
	}

	/* In both TCP and UDP the first four bytes are src and dst ports in shorts. */
	bcopy(&bytes[ptr], &src_port, sizeof(unsigned short));
	ptr += sizeof(unsigned short);
	src_port = ntohs(src_port);

	bcopy(&bytes[ptr], &dst_port, sizeof(unsigned short));
	ptr += sizeof(unsigned short);
	dst_port = ntohs(dst_port);
	
	/* Get ports from either tcp or udp. */
	if (ip_protocol == 0x06) {
		/* TCP Packet, sanity check. */
		if (h->caplen < ptr + 9) {
			return;
		}

		/* Skip sequence numbers. */
		ptr += 8;

		/* Get tcp header length. */
		tcp_length = (bytes[ptr] & 0xf0) >> 2;
		ptr += sizeof(unsigned char);

		/* Skip the rest of the TCP header. */
		ptr += (tcp_length - 13);

		/* ptr should now be at payload. */
		payload_length = (h->caplen - 14 - ip_size - tcp_length);
	} else if (ip_protocol == 0x11) {
		/* UDP Packet, sanity check. */
		if (h->caplen < ptr + 4) {
			return;
		}

		/* Extract UDP length. */
		bcopy(&bytes[ptr], &udp_length, sizeof(unsigned short));
		ptr += sizeof(unsigned short);
		udp_length = ntohs(udp_length);

		/* Skip checksum. */
		ptr += sizeof(unsigned short);

		/* ptr should now be at payload. */
		payload_length = ip_length - ip_size - 8;
	}

	/* Sanity check */
	if (h->caplen < ptr) {
		return;
	}

	/* Analyse it if it's a bittorrent packet.*/
	if (capture_options & CAPTURE_BITTORRENT) {
		result = bittorrent_decode(&bytes[ptr], payload_length);	

		if (result) {
			source = 'b';
		}
	}

	/* Analyse it if it's a edonkey packet and bittorrent didn't match anything. */
	if (!result && capture_options & CAPTURE_EDONKEY) {
		result = edonkey_decode(&bytes[ptr], payload_length, ip_protocol);

		if (result) {
			source = 'e';
		}
	}	

	/* If we still have no result, abort! */	
	if (!result) {
		return;
	}

	/* Loop through results. */
	for (itr = result; itr; itr = itr->next) {
		printf("%ld,%i.%i.%i.%i,%i,%i.%i.%i.%i,%i,%i,%c,%s,%i.%i.%i.%i,%i\n", h->ts.tv_sec, src_addr[0], src_addr[1], src_addr[2], src_addr[3], src_port, dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3], dst_port, ip_protocol, source, itr->hash, itr->address[0], itr->address[1], itr->address[2], itr->address[3], itr->port);
	}
}
