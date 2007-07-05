#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

# use Scalar::Quote qw(D Q);

use File::Spec;
use Cwd qw(getcwd);

select STDERR;
$|=1;
select STDOUT;

$ENV{PATH} = '/usr/bin:/bin' if ${^TAINT};

my ($server, $sscmd, @ssh, $ssname, $windows);

BEGIN {
    $windows = $^O =~ /MSWin32/i;
    if($windows) {
	$ssname = 'sftp-server.exe';
	my $pf;
	eval {
	    require Win32;
	    $pf = Win32::GetFolderPath(Win32::CSIDL_PROGRAM_FILES());
	};
	$pf = "C:/Program Files/" unless defined $pf;
	
	@ssh = ("$pf/openssh/bin/ssh.exe",
		"$pf/openssh/usr/bin/ssh.exe",
		"$pf/bin/ssh.exe",
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
    elsif ($^O !~ /MSWin32/i) {
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

sub mktestfile {
    my ($fn, $count, $data) = @_;

    open DL, '>', $fn
	or die "unable to create test data file $fn";

    print DL $data for (1..$count);
    close DL;
}

plan skip_all => "tests not supported on inferior OS"
    if ($windows and eval "no warnings; getlogin ne 'salva'");
plan skip_all => "sftp-server not found"
    unless defined $sscmd;

plan tests => 264;

use_ok('Net::SFTP::Foreign');
use Net::SFTP::Foreign::Constants qw(:flags);

$SIG{ALRM} = sub {
    print STDERR "# timeout expired: your computer is too slow or some test is not finishing\n";
    exit 1;
};

# don't set the alarm if we are being debugged!
alarm 300 unless exists ${DB::}{sub};

my @new_args = defined $server
    ? (host => $server, timeout => 20)
    : (open2_cmd => $sscmd, timeout => 20);

my $sftp = eval { Net::SFTP::Foreign->new(@new_args) };
diag($@) if $@;

ok (defined $sftp, "creating object");

my $lcwd = File::Spec->rel2abs('t');
my $rcwd = $sftp->realpath($lcwd);
ok (defined $rcwd, "realpath");

my $dlfn = File::Spec->catfile($lcwd, 'data.l');
my $dlfn1 = File::Spec->catfile($lcwd, 'data1.l');
my $drfn = File::Spec->catfile($rcwd, 'data.r');
my $drfn_l = File::Spec->catfile($lcwd, 'data.r');

my $drdir_l = File::Spec->catdir($lcwd, 'testdir');
my $drdir = File::Spec->catdir($rcwd, 'testdir');

for my $i (1..8) {
    mktestfile($dlfn, $i * 4000,
	       "this is just testing data... foo bar doz wahtever... ");

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

# mkdir and rmdir

rmdir $drdir_l;

ok($sftp->mkdir($drdir), "mkdir 1");
ok((-d $drdir_l), "mkdir 2");
ok($sftp->rmdir($drdir), "rmdir 1");
ok(!(-d $drdir_l), "rmdir 2");

my $attr = Net::SFTP::Foreign::Attributes->new;
$attr->set_perm(0700);

ok($sftp->mkdir($drdir, $attr), "mkdir 3");
ok((-d $drdir_l), "mkdir 4");

my @stat = stat $drdir_l;
is($stat[2] & 0777, 0700, "mkdir 5");

$attr->set_perm(0770);
ok($sftp->setstat($drdir, $attr), "setstat 1");
@stat = stat $drdir_l;
is($stat[2] & 0777, 0770, "setstat 2");

ok($sftp->rmdir($drdir), "rmdir 3");
ok(!(-d $drdir_l), "rmdir 4");

# reconnect
$sftp = eval { Net::SFTP::Foreign->new(@new_args) };
diag($@) if $@;

ok (defined $sftp, "creating object 2");

my $fh = $sftp->open($drfn, SSH2_FXF_CREAT|SSH2_FXF_WRITE);
ok ($fh, "open write file");

my @data = <DATA>;
print $fh $_ for @data;
ok((print $fh @data, @data, @data, @data), "write to file 2");
print $fh $_ for @data;
ok((print $fh @data, @data, @data, @data), "write to file 2");
ok (close $fh);

my @all = (@data) x 10;

$fh = $sftp->open($drfn);
ok($fh, "open read file");

my @read = <$fh>;
our ($a, $b);
# D("@read", "@all") and diag "got: $a\nexp: $b\n\n";

is("@read", "@all", "readline list context");
ok(close($fh), "close file");

$fh = $sftp->open($drfn);
ok($fh, "open read file 2");

@read = ();
while (<$fh>) {
    push @read, $_;
}
is("@read", "@all", "readline scalar context");
ok(close($fh), "close file");

$fh = $sftp->open($drfn, SSH2_FXF_CREAT|SSH2_FXF_WRITE);
ok ($fh, "open write file");

my $all = join('', ((@all) x 10));
my $cp = $all;
while (length $all) {
    $sftp->write($fh, substr($all, 0, 1 + int(rand 64000), ''));
}
ok (close($fh), "close write file");

$fh = $sftp->open($drfn);
ok($fh, "open read file 3");

ok(!$sftp->eof($fh), "not at eof");

while (1) {
    my $data = $sftp->read($fh, 1+int(rand 64000));
    last unless defined $data;
    $all .= $data;
}

is($all, $cp, "write and read chunks");

ok(eof($fh), "at eof");

for my $pos (0, 1000, 0, 234, 4500, 1025) {
    my $d1;
    is(seek($fh, $pos, 0), $pos, "seek");
    is(read($fh, my $data, $pos), $pos, "read");
    is($d1 = $sftp->sftpread($fh, $pos, $pos), $data, "sftpread");
    # D($d1, $data) and diag "got: $a\nexp: $b\n\n";

    my $pos1 = $pos + length $data;
    for my $off (0, -1000, 234, 4500, -200, 1025) {
	next unless $pos1 + $off >= 0;
	$pos1 += $off;

	is(seek($fh, $off, 1), $pos1, "seek - 2");
	is(tell($fh), $pos1, "tell"); # if $pos1 > 2000;
	is(read($fh, $data, $pos), $pos, "read - 2 ($pos1, $pos)");
	is($d1 = $sftp->sftpread($fh, $pos1, $pos), $data, "sftpread - 2 ($pos1, $pos)");
	# D($d1, $data) and diag "got: $a\nexp: $b\n\n";
	$pos1 += length $data;
    }
}

my $ctn = $sftp->get_content($drfn);
is($ctn, $all, "get_content");
# D($ctn, $all, -10, 30) and diag "got: $a\nexp: $b\n\n";

is(seek($fh, 0, 0), 0, 'seek - 3');
my $line = readline $fh;

my $wfh = $sftp->open($drfn, SSH2_FXF_WRITE);
ok($wfh, "open write file 3");

ok ($sftp->sftpwrite($wfh, length $line, "HELLO\n"), "sftpwrite");
$sftp->flush($fh);
is (scalar getc($fh), 'H', "getc");
is (scalar readline($fh), "ELLO\n", "readline");
ok(close($wfh), "close");

ok(seek($fh, -2000, 2), 'seek');
@all = readline $fh;

{
    local $/; undef $/;
    ok(seek($fh, -2000, 2), 'seek');
    my $all = readline $fh;
    is ($all, join('', @all), "read to end of file");
    is (length $all, 2000, "seek");
}

opendir DIR, $lcwd;
my @ld = sort grep !/^\./, readdir DIR;
closedir DIR;

# SKIP: {
#    skip "tied directory handles not available on this perl", 3
#	unless eval "use 5.9.4; 1";
#
#    my $rd = $sftp->opendir($rcwd);
#    ok($rd, "open remote dir");
#
#    my @rd = sort grep !/^\./, readdir $rd;
#    is("@rd", "@ld", "readdir array");
#
#    ok (closedir($rd), "close dir");
#
#};

my $rd = $sftp->opendir($rcwd);
ok($rd, "open remote dir 2");

my @rd = sort grep !/^\./, (map { $_->{filename} } $sftp->readdir($rd));
is("@rd", "@ld", "readdir array 1");
ok($sftp->closedir($rd), "close dir 2");


my @ls = sort map { $_->{filename} } @{$sftp->ls($rcwd, no_wanted => qr|^\.|)};
is ("@ls", "@ld", "ls");

my @ld1 = sort('t', @ld);
my @find = sort map { $_->{filename} =~ m|.*/(.*)$|; $1 }
    $sftp->find($rcwd,
		wanted => sub { $_[1]->{filename} !~ m|/\.[^/]*$| },
		descend => sub { $_[1]->{filename} eq $rcwd } );

is ("@find", "@ld1", "find 1");

@ld1 = ('t', @ld);
@find = map { $_->{filename} =~ m|.*/(.*)$|; $1 }
    $sftp->find( $rcwd,
		 ordered => 1,
		 no_wanted => qr|/\.[^/]*$|,
		 no_descend => qr|/\.svn$|);

is ("@find", "@ld1", "find 2");

my @a = glob "$lcwd/*";
is ($sftp->glob("$rcwd/*"), scalar @a, "glob");

unlink $drfn;

alarm 0;
ok (1, "end");




__DATA__

Os Pinos.

¿Qué din os rumorosos
na costa verdecente
ao raio transparente
do prácido luar?
¿Qué din as altas copas
de escuro arume arpado
co seu ben compasado
monótono fungar?

Do teu verdor cinguido
e de benignos astros
confín dos verdes castros
e valeroso chan,
non des a esquecemento
da inxuria o rudo encono;
desperta do teu sono
fogar de Breogán.

Os bos e xenerosos
a nosa voz entenden
e con arroubo atenden
o noso ronco son,
mais sóo os iñorantes
e féridos e duros,
imbéciles e escuros
non nos entenden, non.

Os tempos son chegados
dos bardos das edades
que as vosas vaguedades
cumprido fin terán;
pois, donde quer, xigante
a nosa voz pregoa
a redenzón da boa
nazón de Breogán.

  - Eduardo Pondal

