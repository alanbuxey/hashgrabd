/*
 * Hashgrabd - Utility to capture eDonkey and BitTorrent crytographic hashes from BPF.
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <limits.h>
#include <signal.h>
#include <pcap.h>
#include <sys/stat.h>

#include "main.h"
#include "capture.h"
#include "network.h"

int main (int argc, char *argv[]) {
	unsigned char capture_options = 0;
	unsigned short network_port = 10000;
	long temp_port;
	int rv;
	char *network_host = NULL, *filter = NULL;
	char opt, daemon = 0;
	char *interface = NULL, *file = NULL;

	(void) signal(SIGINT, handle_signal);

	while ((opt = getopt(argc, argv, "i:deFbcf:nh:p:v")) != -1) {
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

			case 'F':
				capture_options |= CAPTURE_EDONKEY_FILENAME;
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

			case 'v':
				warnx("%s (%s)", HASHGRABD_NAME, HASHGRABD_VERSION);
				return EXIT_SUCCESS;

			default:
				return hashgrab_usage();
		}
	}

	argc -= optind;
	argv += optind;

	/* If we have a filter we'll need to pass it through. */
	if (argc > 0) {
		filter = argv[0];
	}

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

	/* Very last thing we do after setup is daemonize. */
	if (daemon) {
		rv = daemonize();

		if (rv == EXIT_SUCCESS || rv == EXIT_FAILURE) {
			return rv;
		}
	}

	/* Execute the main body of the code. */
	rv = capture(interface, capture_options, file, filter);

	/* Close down what we need to. */
	if (capture_options & CAPTURE_NETWORK) {
		/* Teardown the network side. */
		network_teardown();
	}

	return rv;
}

int hashgrab_usage(void) {
	warnx("program usage");
	warnx("-v             - print current version");
	warnx("-i <device>    - device to capture packets from");
	warnx("-d             - daemonise this program");
	warnx("-e             - grab edonkey/emule hashes");
	warnx("-F             - grab edonkey filename");
	warnx("-b             - grab bittorrent hashes");
	warnx("-f <filename>  - file to capture packets to");
	warnx("-c             - print output to console");
	warnx("-n             - print output to network via udp");
	warnx("-h <hostname>  - hostname to send udp to (default => localhost)");
	warnx("-p <port>      - port to send udp to (default => 10000)");
	warnx("\"<filter>\"     - bpf filter to be applied to traffic");
	return EXIT_FAILURE;
}

void handle_signal(int signal) {
	pcap_breakloop(pcap_handle);	
}

int daemonize(void) {
	pid_t pid, sid;
	
	/* Fork to create other copy of processes. */
	pid = fork();

	if (pid < 0) {
		warnx("failed to fork process");
		return EXIT_FAILURE;
	} else if (pid > 0) {
		return EXIT_SUCCESS;
	}

	/* Remove all file access. */
	umask(0);

	/* Put daemon in new session. */
	sid = setsid();

	if (sid < 0) {
		warnx("failed to change session");
		return EXIT_FAILURE;
	}

	/* Move out of current directory to root incase directory needs to be moved or deleted. */
	if (chdir("/") < 0) {
		warnx("failed to change working directory");
		return EXIT_FAILURE;
	}

	/* Return a value that isn't EXIT_FAILURE or EXIT_SUCCESS */
	return 1 + EXIT_FAILURE + EXIT_SUCCESS;
}
