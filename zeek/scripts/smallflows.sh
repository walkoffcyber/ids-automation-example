zeek -F -r smallFlows.pcap local file-extraction/plugins/extract-all-files.bro "Site::local_nets += { 192.168.5.0/24, 10.0.2.0/24 }"
