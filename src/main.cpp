#include <iostream>

#include <netinet/if_ether.h>
#include <netinet/ip.h>

#include <pcap/pcap.h>

void pcap_callback(u_char *user, const struct pcap_pkthdr *packet_header, const u_char *packet);

int main(int argc, char *argv[]) {
	if (argc < 2) {
		std::cout << "Usage: " << argv[0] << " <input>" << std::endl;

		return 69;
	}

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_init(0, errbuf);

	pcap_t *file = pcap_open_offline(argv[1], errbuf);

	if (!file) {
		std::cerr << "failed to open file\n";
		std::cerr << "\t" << errbuf << "\n";

		return 69;
	}

	std::cout << "\t=== file opened ===\n";

	size_t packet_count = pcap_dispatch(file, 10, pcap_callback, NULL);
	if (packet_count < 0) {
		std::cerr << "error with pcap_dispatch";

		return 69;
	} else {
		std::cout << "processed packets: " << packet_count << "\n";
	}

	return 0;
}

void pcap_callback(u_char *user, const struct pcap_pkthdr *packet_header, const u_char *packet) {
	struct ether_header *eth_header = (struct ether_header *)packet;

	if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
		struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

		std::cout << "source:\t\t"      << inet_ntoa(ip_header->ip_src) << "\n";
		std::cout << "destination:\t" << inet_ntoa(ip_header->ip_dst) << "\n";
	}

	std::cout << "packet len:\t"  << packet_header->len << "\n";
	std::cout << "time stamp:\t"  << packet_header->ts.tv_sec << " sec " 
		<< " : " << packet_header->ts.tv_usec << " millisec \n\n";
}