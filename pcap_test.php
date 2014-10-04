<?php

require_once '/usr/share/php/Hexdump.php';
require_once '/usr/share/php/Jm/Autoloader.php';

Jm_Autoloader::singleton()
  ->addPath(__DIR__ . '/../phpshark');

function pl($msg) {
	print($msg . PHP_EOL);
}

$lib_version = pcap_lib_version();
pl("pcap lib version: $lib_version");

$dev = pcap_lookupdev($errbuf);
if($dev === false) {
	pl("pcap_lookupdev(): $errbuf");
	exit(1);
} else {
	pl("pcap_lookupdev(): Default device: $dev");
}


$pcap = pcap_open_offline("test.pcap", $errbuf);
if(!is_resource($pcap)) {
	pl("pcap_open_offline(): $errbuf");
	exit(1);
} else {
	pl("pcap_open_offline(): got resource $pcap (type: " . get_resource_type($pcap) . ")");
}


while($data = pcap_next($pcap, $header)) {
	hexdump($data);
	var_dump($header);
	break;
}


$ret = pcap_stats($pcap, $stats);
if($ret === true) {
	printf("Stats: %d packets received, %d dropped, %d iface dropped\n",
		$stats['ps_recv'], $stats['ps_drop'], $stats['ps_ifdrop']);
} else {
	echo pcap_geterr($pcap);	
}




$ret = pcap_close($pcap);
switch(true) {
	case $ret === true:
		pl("pcap_close() returned true");
		break;

	case $ret === false;
		pl("pcap_close() returned false");
		exit(1);
		break;

	default:
		pl("\$ret has an unknown return type: " . var_dump($ret));
}

################################
# LIVE capture
################################

$pcap = pcap_open_live($dev, 65535, 1, 100000, $errbuf);
if(!is_resource($pcap)) {
	pl("pcap_open_live(): $errbuf");
	exit(1);
} else {
	pl("pcap_open_live(): got resource $pcap (type: " . get_resource_type($pcap) . ")");
}

$i = 0;
while(($data = pcap_next($pcap, $header)) && $i++ < 100) {
	pl(str_repeat('-', 80));
	hexdump($data);
#	$f = Frame_Ethernet::fromstring($data);
#	do {
#		echo $f;
#	} while ($f = $f->subframe());
	
//	var_dump($header);
//	break;
}



$ret = pcap_stats($pcap, $stats);
if($ret === true) {
	printf("Stats: %d packets received, %d dropped, %d iface dropped\n",
		$stats['ps_recv'], $stats['ps_drop'], $stats['ps_ifdrop']);
} else {
	echo pcap_geterr($pcap);	
}


$ret = pcap_close($pcap);
switch(true) {
	case $ret === true:
		pl("pcap_close() returned true");
		break;

	case $ret === false;
		pl("pcap_close() returned false");
		exit(1);
		break;

	default:
		pl("\$ret has an unknown return type: " . var_dump($ret));
}

#sleep(3);
