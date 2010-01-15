#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <limits.h>
#include <signal.h>
#include <pcap.h>

#include "main.h"
#include "capture.h"
#include "network.h"

int main (int argc, char *argv[]) {
	unsigned char capture_options = 0;
	unsigned short network_port = 10000;
	long temp_port;
	int rv;
	char *network_host = NULL;
	char opt, daemon = 0;
	char *interface = NULL, *file = NULL;

	(void) signal(SIGINT, handle_signal);

	while ((opt = getopt(argc, argv, "i:debcf:nh:p:")) != -1) {
		switch(opt) {
			case 'i':
				interface = strdup(optarg);
				break;

			case 'f':
				file = strdup(optarg);

			case 'd':
				daemon = 1;
				break;

			case 'e':
				capture_options |= CAPTURE_EDONKEY;
				break;

			case 'b':
				capture_options |= CAPTURE_BITTORRENT;
				break;

			case 'c':
				capture_options |= CAPTURE_CONSOLE;
				break;

			case 'n':
				capture_options |= CAPTURE_NETWORK;
				break;

			case 'h':
				if (network_host) {
					free(network_host);
				}

				network_host = strdup(optarg);
				break;

			case 'p':
				temp_port = strtol(optarg, NULL, 10);

				if (temp_port < 0 || temp_port > 65535) {
					warnx("invalid port number specified");
					return hashgrab_usage();
				}

				network_port = temp_port;
				break;

			default:
				return hashgrab_usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (!network_host) {
		network_host = strdup("localhost");
	}

	if (!interface) {
		warnx("no capture interface defined");
		return hashgrab_usage();
	}

	if ((capture_options & (CAPTURE_EDONKEY | CAPTURE_BITTORRENT)) == 0) {
		warnx("configured to check neither edonkey or bittorent");
		return hashgrab_usage();
	}

	if ((capture_options & CAPTURE_NETWORK) && (network_setup(network_host, network_port) != 0)) {
		warnx("could not set up network sending");
		return hashgrab_usage();
	}

	/* Execute the main body of the code. */
	rv = capture(interface, capture_options, file);

	/* Close down what we need to. */
	if (capture_options & CAPTURE_NETWORK) {
		/* Teardown the network side. */
		network_teardown();
	}

	return rv;
}

int hashgrab_usage(void) {
	warnx("program usage");
	warnx("-i <device>    - device to capture packets from");
	warnx("-d             - daemonise this program");
	warnx("-e             - grab edonkey/emule hashes");
	warnx("-b             - grab bittorrent hashes");
	warnx("-f <filename>  - file to capture packets to");
	warnx("-c             - print output to console");
	warnx("-n             - print output to network via udp");
	warnx("-h <hostname>  - hostname to send udp to (default => localhost)");
	warnx("-p <port>      - port to send udp to (default => 10000)");
	return EXIT_FAILURE;
}

void handle_signal(int signal) {
	pcap_breakloop(pcap_handle);	
}
