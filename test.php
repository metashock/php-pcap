<?php

printf("pcap library version: %s\n",
    pcap_lib_version());

$errbuf = NULL;
$dev = pcap_lookupdev($errbuf);
if($dev === FALSE) {
    die("pcap_lookupdev(): $errbuf\n");
}

echo 'pcap_lookupdev(): using device: ' . $dev . PHP_EOL;

$pcap = pcap_open_live($dev, 65535, 1, 1000, $errbuf);
if(!is_resource($pcap)) {
    die("pcap_open_live(): $errbuf\n");
}

echo "pcap_open_live(): resource is $pcap (";
echo get_resource_type($pcap) . ")\n";

echo 'pcap_datalink(): link-type is ' . pcap_datalink($pcap) . PHP_EOL;


