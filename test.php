<?php

printf("pcap library version: %s\n",
    pcap_lib_version());

$errbuf = NULL;
$dev = pcap_lookupdev($errbuf);
if($dev === FALSE) {
    die("pcap_lookupdev(): $errbuf\n");
}

echo 'using device: ' . $dev . PHP_EOL;


