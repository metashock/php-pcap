<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

# pcap extension for PHP

libpcap is a library for capturing and injecting network traffic on a network device. It can be used to obtain all packets sent on a certain device regardless of which process issued the traffic. Also it can be used to inject packets on a `raw-socket` basis. libpcap is used by programs like wireshark or tcpdump. This extension exposes the libpcap funtions to PHP scripts.

While the extension is under development it already implements the set of functions which are basically required to sniff or inject traffic on network device. Don't hesitate to post an issue if you miss something.

**Table of Contents**  *generated with [DocToc](http://doctoc.herokuapp.com/)*

  - [Installation](#installation)
      - [Install required packages (Debian/Ubuntu)](#install-required-packages-debianubuntu)
      - [Build dependencies](#build-dependencies)
      - [Build php-pcap](#build-php-pcap)
      - [(Optional) installing the PEAR `Hexdump` package](#optional-installing-the-pear-hexdump-package-it-is-useful-for-debugging-network-traffic)
      - [Testing the installation](#testing-the-installation)
  - [Usage](#usage)
    - [Getting devices available for live capturing](#getting-devices-available-for-live-capturing)
    - [Basic live capture example](#basic-live-capture-example)
    - [Working with capture filters](#working-with-capture-filters)
    - [Capturing from a .pcap file](#capturing-from-a-pcap-file)
  - [Design decisions](#design-decisions)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->


## Installation

#### Install required packages (Debian/Ubuntu)

    apt-get install libpcap8
    
#### Build dependencies

    apt-get install php5-dev build-essential libpcap8-dev

#### Build php-pcap

    git clone git@github.com/metashock/php-pcap.git
    cd php-pcap
    phpize
    make
    sudo make install

Finally you'll need to add the following line to your php.ini:

    extension=pcap.so
    
#### (Optional) installing the PEAR `Hexdump` package, it is useful for debugging network traffic:

    (sudo) pear channel-discover www.metashock.de/pear
    (sudo) pear install metashock/Hexdump
    
#### Testing the installation

    # Should output something like "libpcap version 1.5.3"
    php -r 'echo pcap_lib_version();'

## Usage

As mentioned in the Design decisiones below, the implementation keeps to be as close as possible to the pcap C library. This means that you can follow the pcap examples from their homepage or from other resources on the net and translate them to PHP intuitively. Most C pointer args have been implemented as call by reference parameters in php-pcap.
    
### Getting devices available for live capturing

    $devs = pcap_findalldevs();
    foreach($devs as $dev) {
        echo $dev['name'];
        # The description might being empty
        if(!empty($dev['description'])) {
            echo " ({$dev['description']})";
        }
        echo PHP_EOL;
    }

This should output a list with devices you can use for sniffing, meaning you can pass them to `pcap_open_live()` or `pcap_create()`.

If the list is empty you'll need to follow the section about permissions or simply execute it as root just for this test.
  
### Basic live capture example

Once you know on which device you want to capture packets, you can create a pcap resource and start capturing. Note that I'm using the `hexdump()` function in all the examples to prevent the screen from getting messed up. It is also useful for debugging network traffic.

    require_once 'Hexdump.php';

    // I'm using eth0 as sniffing decvice.
    $dev = "eth0";
    $pcap = pcap_open_live($dev, 65535, 1, 30000, $errbuf);
    if(!is_resource($pcap)) {
        echo $errbuf;
        exit(1);
    }

    while($data = pcap_next($pcap, $header)) {
       	hexdump($data);
    }

### Working with capture filters

...
    


### Capturing from a .pcap file

Working with .pcap files which have been previously captured using tcpdump, php-pcap or whatever dumper works mostly the same as with live captures. You just have to use `pcap_open_offline()` instead of `pcap_open_live()` to obtain a pcap handle:

    require_once 'Hexdump.php';

    // I assume that you have created "test.pcap" before
    $dev = "test.pcap";
    $pcap = pcap_open_live($filename, $errbuf);
    if(!is_resource($pcap)) {
        echo $errbuf;
        exit(1);
    }

    while($data = pcap_next($pcap, $header)) {
       	hexdump($data);
    }
---

## Design decisions

I tried to be as close as possible to the original C library. Meaning the signatures of the functions are the same as in the C library. This has the advantage, that you can use the pcap man pages and other documentation and can easily adapt every pcap example you find from C code to PHP.

However, this introduces also a lot of passing-by-reference which is uncommon in PHP an I'm not perfectly happy with it and therefore might change this in future version of the library.

I appreciate discussion about that.

