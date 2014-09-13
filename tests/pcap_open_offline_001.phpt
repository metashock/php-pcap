--TEST--
Check if pcap_open_offline reports proper error if the .pcap
file does not exist.
--SKIPIF--
<?php if (!extension_loaded("pcap")) print "skip"; ?>
--FILE--
<?php

$pcap = pcap_open_offline("not_existing.pcap", $errbuf);
echo $errbuf;
?>
--EXPECT--
not_existing.pcap: No such file or directory
