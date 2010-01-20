/*
 * Hashgrab - Utility to capture eDonkey and BitTorrent crytographic hashes from BPF.
 * 
 * Copyright (C) 2010 University of Lancaster
 * 
 * This program is free software: you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License, or 
 * (at your option) any later version. This program is distributed in the 
 * hope that it will be useful, but WITHOUT ANY WARRANTY; without 
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR 
 * A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details. You should have received a copy of the GNU General 
 * Public License along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <strings.h>
#include <netinet/in.h>
#include <ctype.h>

#include "capture.h"
#include "network.h"
#include "edonkey.h"
#include "bittorrent.h"

pcap_dumper_t *pcap_dumper = NULL;
pcap_t *pcap_handle = NULL;

int capture(char *interface, unsigned char capture_options, char *file, char *filter) {
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	int pcap_return;
	struct bpf_program fp;

	if ((pcap_handle = pcap_open_live(interface, BUFSIZ, 0, 1000, pcap_errbuf)) == NULL) {
		warnx("could not open device '%s' - %s", interface, pcap_errbuf);
		return EXIT_FAILURE;
	}

	/* If we've been given a BPF filter we need to compile it and set it. */
	if (filter) {
		if (pcap_compile(pcap_handle, &fp, filter, 0, 0) == -1) {
			warnx("could not parse filter \"%s\": %s", filter, pcap_geterr(pcap_handle));
			return EXIT_FAILURE;
		}

		if (pcap_setfilter(pcap_handle, &fp) == -1) {
			warnx("could not set filter \"%s\": %s", filter, pcap_geterr(pcap_handle));
			return EXIT_FAILURE;
		}
	}

	if (file) {
		if ((pcap_dumper = pcap_dump_open(pcap_handle, file)) == NULL) {
			warnx("could not open dump file '%s' - %s", file, pcap_errbuf);
			return EXIT_FAILURE;
		}
	}

	pcap_return = pcap_loop(pcap_handle, 0, capture_packet, (u_char *) &capture_options);

	if (pcap_return == -1) {
		warnx("pcap returns packet capture failure - %s", pcap_geterr(pcap_handle));
	} 

	if (pcap_dumper) {
		pcap_dump_close(pcap_dumper);
	}

	pcap_close(pcap_handle);

	if (pcap_return == -1) {
		return EXIT_FAILURE;
	} else {
		return EXIT_SUCCESS;
	}
}

void capture_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
	unsigned char capture_options = *user, ip_version, ip_size, ip_protocol, src_addr[4], dst_addr[4], source, dump;
	char *filename;
	char text_output[512];
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
	if ((capture_options & CAPTURE_BITTORRENT)) {
		dump = 0;

		result = bittorrent_decode(&bytes[ptr], payload_length, ip_protocol, &dump);

		if (dump && pcap_dumper) {
			pcap_dump((u_char *) pcap_dumper, h, bytes);
			pcap_dump_flush(pcap_dumper);
		}	

		if (result) {
			source = 'b';
		}
	}

	/* Analyse it if it's a edonkey packet and bittorrent didn't match anything. */
	if (!result && (capture_options & CAPTURE_EDONKEY)) {
		dump = 0;

		result = edonkey_decode(&bytes[ptr], payload_length, ip_protocol, &dump);

		if (dump && pcap_dumper) {
			pcap_dump((u_char *) pcap_dumper, h, bytes);
			pcap_dump_flush(pcap_dumper);
		}

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
		if (itr->filename) {
			filename = itr->filename;
		} else {
			filename = "unknown";
		}

		snprintf(text_output, 512, "%ld,%i.%i.%i.%i,%i,%i.%i.%i.%i,%i,%i,%c,%c,%s,%s", (unsigned long) h->ts.tv_sec, src_addr[0], src_addr[1], src_addr[2], src_addr[3], src_port, dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3], dst_port, ip_protocol, source, itr->exchange_type, itr->hash, filename);

		if (capture_options & CAPTURE_CONSOLE) {
			printf("%s\n", text_output);
		}

		if (capture_options & CAPTURE_NETWORK) {
			network_send(text_output);
		}
	}

	DESTROY_DECODED_HASH(result, itr);
}

void sanitize_filename(char *filename, unsigned short length) {
	unsigned short i;

	for (i = 0; i < length; i++) {
		if (!isprint(filename[i])) {
			filename[i] = '-';
		}
	}
}
