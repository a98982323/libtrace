/* ARP */
#include <stdio.h>
#include <inttypes.h>
#include <dlfcn.h>
#include "libpacketdump.h"
#include <sys/socket.h>
#ifndef WIN32
	#include <netinet/in_systm.h>
#endif
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <string.h>

/* 
 * Converts an ARP hardware address to a printable string.
 * Takes an ARP header structure and a pointer to the start
 * of the hardware address in the structure that we should
 * attempt to decode.
 */
char *format_hrd(struct arphdr *arp, char *hrd) {
	static char buffer[1024] = {0,};
	uint8_t *addr = (uint8_t *)hrd;
	int i;

	if (!hrd) {
		strncpy(buffer, "(Truncated)", sizeof(buffer));
		return buffer;
	}

	switch(ntohs(arp->ar_hrd)) {
		case ARPHRD_ETHER:
			trace_ether_ntoa(hrd, buffer);
			break;
		default:
			for (i=0;i<arp->ar_hln;i++) {
				snprintf(buffer,sizeof(buffer),"%s %02x",
						buffer,(unsigned char)hrd[i]);
			}
			break;
	}
	
	return buffer;
}

/* 
 * Converts an ARP protocol address to a printable string.
 * Takes an ARP header structure and a pointer to the start
 * of the protocol address in the structure that we should
 * attempt to decode.
 */
char *format_pro(struct arphdr *arp, char *pro) {
	static char buffer[1024] = {0,};
	int i;
	
	if (!pro) {
		strncpy(buffer, "(Truncated)", sizeof(buffer));
		return buffer;
	}

	switch(ntohs(arp->ar_pro)) {
		case 0x0800:
			snprintf(buffer,sizeof(buffer),"%s",
					inet_ntoa(*(struct in_addr*)pro));
			break;
		default:
			strncat(buffer," (",sizeof(buffer));
			for (i=0;i<arp->ar_pln;i++) {
				snprintf(buffer,sizeof(buffer),"%s %02x",
						buffer,(unsigned char)pro[i]);
			}
			strncat(buffer,")",sizeof(buffer));
			break;
	}
	return buffer;
	
}
	
void decode(int link_type,char *packet,int len)
{
	struct arphdr *arp = (struct arphdr*)packet;
	char *source_hrd = NULL;
	char *source_pro = NULL;
	char *dest_hrd = NULL;
	char *dest_pro = NULL;

	if (len < sizeof(struct arphdr)) {
		printf(" ARP: (Truncated)\n");
		return;
	}

	if (len >= sizeof(struct arphdr) + arp->ar_hln) 
		source_hrd = packet + sizeof(struct arphdr);
	if (len >= sizeof(struct arphdr) + arp->ar_hln + arp->ar_pln)
		source_pro = source_hrd + arp->ar_hln;
	if (len >= sizeof(struct arphdr) + arp->ar_hln * 2 + arp->ar_pln)
		dest_hrd = source_pro + arp->ar_pln;
	if (len >= sizeof(struct arphdr) + arp->ar_hln * 2 + arp->ar_pln * 2)
		dest_pro = dest_hrd + arp->ar_hln;

	switch(ntohs(arp->ar_op)) {
		case ARPOP_REQUEST:
			printf(" ARP: who-has %s", format_pro(arp, dest_pro));
			printf(" tell %s (%s)\n", format_pro(arp, source_pro),
					format_hrd(arp, source_hrd));
			break;
		case ARPOP_REPLY:
			printf(" ARP: reply %s", format_pro(arp, dest_pro));
			printf(" is-at %s\n", format_hrd(arp, dest_hrd));
			break;
		default:
			printf(" ARP: Unknown opcode (%i) from %s to %s\n",
					ntohs(arp->ar_op),
					format_pro(arp, source_pro),
					format_pro(arp, dest_pro));

			break;
	}
	return;
}
