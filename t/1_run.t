#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

use File::Spec;
use Cwd qw(getcwd);

my ($sscmd, @ssh, $ssname);
if ($^O =~ /Win32/) {
    $ssname = 'sftp-server.exe';
    my $pf;
    eval {
	require Win32;
	$pf = Win32::GetFolderPath(Win32::CSIDL_PROGRAM_FILES());
    };
    $pf = "C:/Program Files/" unless defined $pf;

    @ssh = ("$pf/bin/ssh.exe",
	    "$pf/usr/bin/ssh.exe");
}
else {
    $ssname = 'sftp-server';
    @ssh = qw( /usr/bin/ssh
	       /usr/local/bin/ssh
	       /usr/local/openssh/bin/ssh
	       /opt/openssh/bin/ssh );
}

if (eval {require File::Which; 1}) {
    unshift @ssh, File::Which::where('ssh');
}
else {
    chomp(my $ssh = `which ssh`);
    unshift @ssh, $ssh if (!$? and $ssh);
}

SEARCH: for (@ssh) {
    my ($vol, $dir) = File::Spec->splitpath($_);

    my $up = File::Spec->rel2abs(File::Spec->catpath($vol, $dir, File::Spec->updir));

    for ( File::Spec->catfile($vol, $dir, $ssname),
	  File::Spec->catfile($up, 'lib', $ssname),
	  File::Spec->catfile($up, 'sbin', $ssname),
	  File::Spec->catfile($up, 'lib', 'openssh', $ssname),
	  File::Spec->catfile($up, 'usr', 'lib', $ssname),
	  File::Spec->catfile($up, 'usr', 'sbin', $ssname) ) {
	if (-x $_) {
	    $sscmd = $_;
	    diag "sftp-server found at $_\n";
	    last SEARCH;
	}
    }
}

sub filediff {
    my ($a, $b) = @_;
    open my $fa, "<", $a
	or die "unable to open file $a";

    open my $fb, "<", $b
	or die "unable to open file $b";

    binmode $fa;
    binmode $fb;

    while (1) {
	my $la = read($fa, my $da, 2048);
	my $lb = read($fb, my $db, 2048);
	
	return 1 unless (defined $la and defined $lb);
	return 1 if $la != $lb;
	return 0 if $la == 0;
	return 1 if $la ne $lb;
    }
}

plan skip_all => "sftp-server not found" unless defined $sscmd;

plan tests => 68;

use_ok('Net::SFTP::Foreign');

# $Net::SFTP::Foreign::debug = 1;

$SIG{ALRM} = sub {
    print STDERR "# timeout expired: your computer is too slow or some test is not finishing\n";
    exit 1;
};

# don't set the alarm if we are being debugged!
alarm 120 unless exists ${DB::}{sub};

my $sftp = eval { Net::SFTP::Foreign->new(open2_cmd => $sscmd) };
diag($@) if $@;

ok (defined $sftp, "creating object");

my $lcwd = File::Spec->rel2abs('t');
my $rcwd = $sftp->realpath($lcwd);
ok (defined $rcwd, "realpath");

my $dlfn = File::Spec->catfile($lcwd, 'data.l');
my $dlfn1 = File::Spec->catfile($lcwd, 'data1.l');
my $drfn = File::Spec->catfile($rcwd, 'data.r');
my $drfn_l = File::Spec->catfile($lcwd, 'data.r');


for my $i (1..8) {

    open DL, '>', $dlfn
	or die "unable to create test data file $dlfn";

    my $content = "this is a test file... "  x $i;
    print DL $content for (1..4000);
    close DL;

    ok ($sftp->put($dlfn, $drfn), "put - $i");
    diag ($sftp->error) if $sftp->error;

    ok(!filediff($dlfn, $drfn_l), "put - file content - $i");

    ok (my $attr = $sftp->stat($drfn), "stat - $i");

    is ($attr->size, (stat($dlfn))[7], "stat - size - $i");

    ok (!$sftp->put($dlfn, $drfn, overwrite => 0), "no overwrite - $i");
    is (int $sftp->error, Net::SFTP::Foreign::Constants::SFTP_ERR_REMOTE_OPEN_FAILED(), "no overwrite - error - $i");

    ok ($sftp->get($drfn, $dlfn1), "get - $i");
    diag ($sftp->error) if $sftp->error;

    ok(!filediff($drfn_l, $dlfn1), "get - file content - $i");

    unlink $dlfn;
    unlink $dlfn1;
    unlink $drfn_l;
}

alarm 0;
ok (1, "end");

