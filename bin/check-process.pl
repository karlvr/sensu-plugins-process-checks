#!/usr/bin/perl -w
# Finds processes matching various filters (name, state, etc).
# Based on https://github.com/sensu-plugins/sensu-plugins-process-checks/blob/master/bin/check-process.rb

use Getopt::Long qw(:config no_auto_abbrev no_ignore_case);
use Pod::Usage;
use Sys::Hostname;
use List::Util qw(any);

my $warn_over; # Trigger a warning if over a number
my $crit_over; # Trigger a critical if over a number
my $warn_under = 1; # Trigger a warning if under a number
my $crit_under = 1; # Trigger a critial if under a number
#my $metric; # Trigger a critical if there are METRIC procs
my $match_self = 0; # Match itself
my $match_parent = 0; # Match parent process
my $cmd_pat; # Match a command against this pattern
my $exclude_pat; # Don't match against a pattern to prevent false positives
my $file_pid; # Check against a specific PID contained in the given file
my $file_pid_crit; # Trigger a critical if pid file is specified but non-existent
my $vsz; # Trigger on a Virtual Memory size is bigger than this
my $rss; # Trigger on a Resident Set size is bigger than this
my $cpu_utilization; # Trigger on a Proportional Set Size is bigger than this
my $thcount; # Trigger on a Thread Count is bigger than this
my @states; # Trigger on a specific state, example: Z for zombie
my @users; # Trigger on a specific user
my $esec_over; # Match processes that are older than this, in SECONDS
my $esec_under; # Match process that are younger than this, in SECONDS
my $cpu_over; # Match processes cpu time that is older than this, in SECONDS
my $cpu_under; # Match processes cpu time that is younger than this, in SECONDS
my $encoding = 'ASCII-8BIT'; # Explicit encoding when reading process list

GetOptions(
	'warn-over|w=i' => \$warn_over,
	'critical-over|c=i' => \$crit_over,
	'warn-under|W=i' => \$warn_under,
	'critical-under|C=i' => \$crit_under,
	#'metric|t=s' => \$metric,
	'match-self|m' => \$match_self,
	'match-parent|M' => \$match_parent,
	'pattern|p=s' => \$cmd_pat,
	'exclude-pattern|x=s' => \$exclude_pat,
	'file-pid|f=s' => \$file_pid,
	'file-pid-crit|F' => \$file_pid_crit,
	'virtual-memory-size|z=i' => \$vsz,
	'resident-set-size|r=i' => \$rss,
	'cpu-utilization|P=f' => \$cpu_utilization,
	'thread-count|T=i' => \$thcount,
	'state|s=s' => \@states,
	'user|u=s' => \@users,
	'esec-over|e=i' => \$esec_over,
	'esec-under|E=i' => \$esec_under,
	'cpu-over|i=i' => \$cpu_over,
	'cpu-under|I=i' => \$cpu_under,
	'encoding=s' => \$encoding,
) or pod2usage(2);

@states = split(/,/, join(',', @states));
@users = split(/,/, join(',', @users));

my $now = time();
open(my $fh, "ps axwwo user,pid,vsz,rss,pcpu,nlwp,state,etime,time,command|") or die("Cannot run ps");

<$fh>; # Discard first line

my $match_pid;

# Read PID from a file
if ($file_pid) {
	if (-e $file_pid) {
		open(my $fh, "<", $file_pid) or die("Cannot open pid file: $file_pid");
		$match_pid = (<$fh>);
		close($fh);
	} else {
		print "Could not read pid file: $file_pid\n";
		exit 2 if ($file_pid_crit);
		exit 3;
	}
}

sub time_str_to_sec {
	my ($etime) = @_;
	$etime =~ /(\d+-)?((\d\d):)?(\d\d):(\d\d)/;
	return ($1 || 0) * 86400 + ($3 || 0) * 3600 + ($4 || 0) * 60 + ($5 || 0);
}

my $count = 0;

while (my $line = <$fh>) {
	my ($user, $pid, $pvsz, $prss, $pcpu, $pthcount, $state, $etime, $ctime, @command) = split(/\s+/, $line);

	my $command = join(' ', @command);
	next if $match_pid && $pid != $match_pid;
	next if !$match_self && $pid == $$;
	next if !$match_parent && $pid == getppid();
	next if $exclude_pat && $command =~ $exclude_pat;
	next if $cmd_pat && $command !~ $cmd_pat;
	next if $vsz && $pvsz <= $vsz;
	next if $rss && $prss <= $rss;
	next if $cpu_utilization && $pcpu <= $cpu_utilization;
	next if $thcount && $pthcount <= $thcount;
	next if $esec_under && time_str_to_sec($etime) >= $esec_under;
	next if $esec_over && time_str_to_sec($etime) <= $esec_over;
	next if $cpu_under && time_str_to_sec($ctime) >= $cpu_under;
	next if $cpu_over && time_str_to_sec($ctime) <= $cpu_over;
	next if @states && !any { $_ eq $state } @states;
	next if @users && !any { $_ eq $user } @users;

	$count++;
}

close($fh);

my $msg = "Found $count matching processes";
$msg .= "; cmd $cmd_pat" if $cmd_pat;
$msg .= "; state @states" if @states;
$msg .= "; user @users" if @users;
$msg .= "; vsz > $vsz" if $vsz;
$msg .= "; rss > $rss" if $rss;
$msg .= "; cpu > $cpu_utilization" if $cpu_utilization;
$msg .= "; threads > $thcount" if $thcount;
$msg .= "; esec < $esec_under" if $esec_under;
$msg .= "; esec > $esec_over" if $esec_over;
$msg .= "; csec < $cpu_under" if $cpu_under;
$msg .= "; csec > $cpu_over" if $cpu_over;
$msg .= "; pid $match_pid" if $file_pid;

print "$msg\n";
if ($crit_under && $count < $crit_under) {
	exit 2;
} elsif ($crit_over && $count > $crit_over) {
	exit 2;
} elsif ($warn_under && $count < $warn_under) {
	exit 1;
} elsif ($warn_over && $count > $warn_over) {
	exit 1;
}
