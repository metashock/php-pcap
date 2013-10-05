<?php

printf("pcap library version: %s\n",
    pcap_lib_version());

$errbuf = NULL;
$dev = pcap_lookupdev($errbuf);
if($dev === FALSE) {
    die("pcap_lookupdev(): $errbuf\n");
}

if(pcap_lookupnet($dev, $net, $netmask, $errbuf) == -1) {
    die("pcap_lookupnet(): $errbuf\n");
}

printf("pcap_lookupdev(): net=%s mask=%s\n",
    long2ip($net), long2ip($netmask)
);

echo 'pcap_lookupdev(): using device: ' . $dev . PHP_EOL;

$pcap = pcap_open_live($dev, 65535, 1, 1000, $errbuf);
if(!is_resource($pcap)) {
    die("pcap_open_live(): $errbuf\n");
}

echo "pcap_open_live(): resource is $pcap (";
echo get_resource_type($pcap) . ")\n";

echo 'pcap_datalink(): link-type is ' . pcap_datalink($pcap) . PHP_EOL;

if (pcap_datalink($pcap) != 1) {
    printf('Device %s doesn\'t provide Ethernet headers - not supported%s',
        $dev, PHP_EOL);
    return(2);
}

$filter = '';
$ret = pcap_compile($pcap, $filter, 'port sad21233', 1, $netmask);
echo 'php_here';
var_dump($ret);

