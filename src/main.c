#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include "main.h"
#include "capture.h"

int main (int argc, char *argv[]) {
	char opt, daemon = 0, edonkey = 0, bittorrent = 0;
	char *interface = NULL, *file = NULL;

	while ((opt = getopt(argc, argv, "i:debhf:")) != -1) {
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
				edonkey = 1;
				break;

			case 'b':
				bittorrent = 1;
				break;

			case 'h':
			default:
				return hashgrab_usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (!interface) {
		warnx("no capture interface defined");
		return hashgrab_usage();
	}

	if (!edonkey && !bittorrent) {
		warnx("configured to check neither edonkey or bittorent");
		return hashgrab_usage();
	}

	return capture(interface, bittorrent, edonkey, file);
}

int hashgrab_usage(void) {
	warnx("program usage");
	warnx("-h             - program usage details");
        warnx("-i <device>    - device to capture packets from");
	warnx("-d             - daemonise this program");
	warnx("-e             - grab edonkey hashes");
	warnx("-b             - grab bittorrent hashes");
	warnx("-f <filename>  - file to capture packets to");
	return EXIT_FAILURE;
}
