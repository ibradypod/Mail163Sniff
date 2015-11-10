#include "mail_sniff.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcre.h>
#include <string.h>


int main()
{

    char filter_exp[] = "tcp dst or src port 80";		/* filter expression [3] */

    /* global parameter */
    nids_params.device = "all";
    nids_params.filename = "test.cap";
    nids_params.pcap_filter = filter_exp;

    struct nids_chksum_ctl chksum;

    chksum.netaddr = 0;
    chksum.mask = 0;
    chksum.action = 1;
    nids_register_chksum_ctl(&chksum,1);

    if (!nids_init ()){
          fprintf (stderr, "%s\n", nids_errbuf);
          exit (1);
     }

    nids_register_tcp (tcp_protocol_callback);

    nids_run();

	printf("\nCapture complete.\n");

	return 0;
}

#if 0
int main(int argc, char **argv)
{

    char *dev = NULL;			/* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle;				/* packet capture handle */

    char filter_exp[] = "tcp dst or src port 80";		/* filter expression [3] */
    struct bpf_program fp;			/* compiled filter program (expression) */
    bpf_u_int32 mask;			/* subnet mask */
    bpf_u_int32 net;			/* ip */
    int num_packets = 10;			/* number of packets to capture */

    (void)argc;
    (void*)argv;

//	/* find a capture device  */
//	dev = pcap_lookupdev(errbuf);
//    dev = (char*)"wlan0";
//	if (dev == NULL) {
//		fprintf(stderr, "Couldn't find default device: %s\n",
//		    errbuf);
//		exit(EXIT_FAILURE);
//	}

//	/* get network number and mask associated with capture device */
//	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
//		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
//		    dev, errbuf);
//		net = 0;
//        mask = 0;
//        exit(EXIT_FAILURE);
//	}

//	/* print capture info */
//	printf("Device: %s\n", dev);
//	printf("Number of packets: %d\n", num_packets);
//	printf("Filter expression: %s\n", filter_exp);

//	/* open capture device */
//	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
//	if (handle == NULL) {
//		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
//		exit(EXIT_FAILURE);
//	}

//	/* make sure we're capturing on an Ethernet device [2] */
//	if (pcap_datalink(handle) != DLT_EN10MB) {
//		fprintf(stderr, "%s is not an Ethernet\n", dev);
//		exit(EXIT_FAILURE);
//	}

     // offline packet
     char file[] = "test.cap";
     handle = pcap_open_offline(file,errbuf);
     if(handle == NULL)
     {
        fprintf(stderr, "Couldn't open offline file : %s\n", errbuf);
        exit(EXIT_FAILURE);
     }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */
    pcap_loop(handle, -1, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");

    return 0;
}
#endif
