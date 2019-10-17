zeek -F -r heartbleed.pcap local "Site::local_nets += { 192.168.11.0/24 }"
