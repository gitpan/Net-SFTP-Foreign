package Net::SFTP::Foreign;

our $VERSION = '0.59';

use strict;
use warnings;
use Carp qw(carp croak);

use IPC::Open2;

use Net::SFTP::Foreign::Constants qw( :fxp :flags :status :att SSH2_FILEXFER_VERSION );
use Net::SFTP::Foreign::Util qw( fx2txt );
use Net::SFTP::Foreign::Attributes;
use Net::SFTP::Foreign::Buffer;

use constant COPY_SIZE => 32768;

our $dirty_cleanup;
BEGIN {
    if ($^O =~ /solaris/i) {
	$dirty_cleanup = 1 unless defined $dirty_cleanup;
    }
}

sub new {
    my $class = shift;
    unshift @_, 'host' if @_ & 1;
    my %opts = @_;

    my $sftp = bless {}, $class;

    delete $opts{_compat} or carp 
	"The old API for Net::SFTP::Foreign inherited from Net::SFTP is being obsoleted. ".
	    "Use Net::SFTP::Foreign::Compat for a package offering a mostly compatible API ".
		"or upgrade to the development version of this package and use the new and ".
		    "much improved API.";

    $sftp->{debug} = delete $opts{debug};
    $sftp->{status} = SSH2_FX_OK;

    $sftp->{warn} = exists $opts{warn} ? delete($opts{warn}) : 1;  # true => emit warning
    $sftp->{warn_h} = delete $opts{warn_h} || sub { carp $_[1] };

    $sftp->{_msg_id} = 0;

    if (defined $opts{open2_cmd}) {
	$opts{open2_cmd} = [$opts{open2_cmd}]
	    unless UNIVERSAL::isa($opts{open2_cmd}, 'ARRAY');
	
	for (qw(host user port ssh_cmd more)) {
	    defined $opts{$_}
		and $sftp->warn("both '$_' and 'open2_cmd' options defined, ignoring '$_'!");
	}
    }
    else {
	defined $opts{host}
	    or croak "sftp target host not defined";

	my @port = defined $opts{port} ? (-p => $opts{port}) : ();
	my @user = defined $opts{user} ? (-l => $opts{user}) : ();
	my @more = defined $opts{more} ? (UNIVERSAL::isa($opts{more}, 'ARRAY') ? @{$opts{more}} : $opts{more}) : ();

	$opts{ssh_cmd} = 'ssh' unless defined $opts{ssh_cmd};
	$opts{open2_cmd} = [$opts{ssh_cmd}, @port, @user, @more, $opts{host}, -s => 'sftp'];
    }

    $sftp->{pid} = open2($sftp->{ssh_in}, $sftp->{ssh_out}, @{$opts{open2_cmd}})
	or croak "running '@_' failed ($!)";

    $sftp->do_init;

    $sftp
}

sub DESTROY {
    my $sftp = shift;
    my $pid = $sftp->{pid};
    if (defined $pid) {
	close $sftp->{ssh_out} if defined $sftp->{ssh_out};
	close $sftp->{ssh_in} if defined $sftp->{ssh_in};
	if ($dirty_cleanup) {
	    for my $sig (1, 1, 1, 9, 9) {
		kill $sig, $pid;
		eval {
		    local $SIG{ALRM} = sub { die "timeout\n" };
		    alarm 2;
		    waitpid($pid, 0);
		    alarm 0;
		};
		if ($@) {
		    next if $@ =~ /^timeout/;
		    die $@;
		}
		last;
	    }
	}
	elsif ($^O =~ /mswin/i) {
	    kill 1, $pid
		and waitpid($pid, 0);
	}
	else {
	    waitpid($pid, 0);
	}
    }
}

# call the warning handler with the object and message
sub warn {
    my ($sftp,$msg,$status) = @_;
    $msg .= ': '.fx2txt($status) if defined $status;
    $sftp->{status} = $status || SSH2_FX_OK;
    $sftp->{warn} and $sftp->{warn_h}->($sftp, $msg);
}

# returns last SSH error, or SSH2_FX_OK (only useful after failure)
sub status {
    my $sftp = shift;
    my $status = $sftp->{status};
    wantarray ? ($status, fx2txt($status)) : $status
}

sub do_init {
    my $sftp = shift;

    $sftp->debug("Sending SSH2_FXP_INIT");
    my $msg = $sftp->new_msg(SSH2_FXP_INIT, int32 => SSH2_FILEXFER_VERSION);
    $sftp->send_msg($msg);

    $msg = $sftp->get_msg;
    my $type = $msg->get_int8;
    $type == SSH2_FXP_VERSION
        or croak "Invalid packet back from SSH2_FXP_INIT (type $type)";

    my $version = $msg->get_int32;
    $sftp->debug("Remote version: $version");

    ## XXX Check for extensions.
}

sub debug { shift->{debug} and print STDERR "sftp: @_" }

## Server -> client methods.

# reads SSH2_FXP_STATUS packet and returns Net::SFTP::Foreign::Attributes object or undef
sub get_attrs {
    my $sftp = shift;
    my($expected_id) = @_;
    my $msg = $sftp->get_msg;
    my $type = $msg->get_int8;
    my $id = $msg->get_int32;
    $sftp->debug("Received stat reply T:$type I:$id");
    croak "ID mismatch ($id != $expected_id)" unless $id == $expected_id;
    if ($type == SSH2_FXP_STATUS) {
        my $status = $msg->get_int32;
	$sftp->warn("Couldn't stat remote file",$status);
        return;
    }
    elsif ($type != SSH2_FXP_ATTRS) {
        croak "Expected SSH2_FXP_ATTRS packet, got $type";
    }
    $msg->get_attributes;
}

# reads SSH2_FXP_STATUS packet and returns SFTP::Foreign status value
sub get_status {
    my $sftp = shift;
    my($expected_id) = @_;
    my $msg = $sftp->get_msg;
    my $type = $msg->get_int8;
    my $id = $msg->get_int32;

    croak "ID mismatch ($id != $expected_id)" unless $id == $expected_id;
    if ($type != SSH2_FXP_STATUS) {
        croak "Expected SSH2_FXP_STATUS packet, got $type";
    }

    $msg->get_int32;
}

# reads SSH2_FXP_HANDLE packet and returns handle, or undef on failure
sub get_handle {
    my $sftp = shift;
    my($expected_id) = @_;

    my $msg = $sftp->get_msg;
    my $type = $msg->get_int8;
    my $id = $msg->get_int32;

    croak "ID mismatch ($id != $expected_id)" unless $id == $expected_id;
    if ($type == SSH2_FXP_STATUS) {
        my $status = $msg->get_int32;
	$sftp->warn("Couldn't get handle",$status);
        return;
    }
    elsif ($type != SSH2_FXP_HANDLE) {
        croak "Expected SSH2_FXP_HANDLE packet, got $type";
    }

    $msg->get_str;
}

## Client -> server methods.

sub _send_str_request {
    my $sftp = shift;
    my($code, $str) = @_;
    my($msg, $id) = $sftp->new_msg_w_id($code, str => $str);
    $sftp->send_msg($msg);
    $sftp->debug("Sent message T:$code I:$id");
    $id;
}

sub _send_str_attrs_request {
    my $sftp = shift;
    my($code, $str, $a) = @_;
    my($msg, $id) = $sftp->new_msg_w_id($code, str => $str, attr => $a);
    $sftp->send_msg($msg);
    $sftp->debug("Sent message T:$code I:$id");
    $id;
}

sub _check_ok_status {
    my $status = $_[0]->get_status($_[1]);
    $_[0]->warn("Couldn't $_[2]",$status) unless $status == SSH2_FX_OK;
    $status;
}

## SSH2_FXP_OPEN (3)
# returns handle on success, undef on failure
sub do_open {
    my $sftp = shift;
    my($path, $flags, $a) = @_;
    $a ||= Net::SFTP::Foreign::Attributes->new;
    my($msg, $id) = $sftp->new_msg_w_id(SSH2_FXP_OPEN, str => $path,
					int32 => $flags, attr => $a);
    $sftp->send_msg($msg);
    $sftp->debug("Sent SSH2_FXP_OPEN I:$id P:$path");
    $sftp->get_handle($id);
}

## SSH2_FXP_READ (4)
# returns data on success, (undef,$status) on failure
sub do_read {
    my $sftp = shift;
    my($handle, $offset, $size) = @_;
    $size ||= COPY_SIZE;
    my($msg, $expected_id) = $sftp->new_msg_w_id(SSH2_FXP_READ, str=> $handle,
						 int64 => $offset, int32 => $size);
    $sftp->send_msg($msg);
    $sftp->debug("Sent message SSH2_FXP_READ I:$expected_id O:$offset");
    $msg = $sftp->get_msg;
    my $type = $msg->get_int8;
    my $id = $msg->get_int32;
    $sftp->debug("Received reply T:$type I:$id");
    croak "ID mismatch ($id != $expected_id)" unless $id == $expected_id;
    if ($type == SSH2_FXP_STATUS) {
        my $status = $msg->get_int32;
        if ($status != SSH2_FX_EOF) {
	    $sftp->warn("Couldn't read from remote file",$status);
            $sftp->do_close($handle);
        }
        return(undef, $status);
    }
    elsif ($type != SSH2_FXP_DATA) {
        croak "Expected SSH2_FXP_DATA packet, got $type";
    }
    $msg->get_str;
}

## SSH2_FXP_WRITE (6)
# returns status (SSH2_FX_OK on success)
sub do_write {
    my $sftp = shift;
    my($handle, $offset, $data) = @_;
    my($msg, $id) = $sftp->new_msg_w_id(SSH2_FXP_WRITE, str => $handle,
				       int64 => $offset, str => $data);
    $sftp->send_msg($msg);
    $sftp->debug("Sent message SSH2_FXP_WRITE I:$id O:$offset");
    my $status = $sftp->_check_ok_status($id,'write to remote file');
    $sftp->do_close($handle) unless $status == SSH2_FX_OK;
    return $status;
}

## SSH2_FXP_LSTAT (7), SSH2_FXP_FSTAT (8), SSH2_FXP_STAT (17)
# these all return a Net::SFTP::Foreign::Attributes object on success, undef on failure
sub do_lstat { $_[0]->_do_stat(SSH2_FXP_LSTAT, $_[1]) }
sub do_fstat { $_[0]->_do_stat(SSH2_FXP_FSTAT, $_[1]) }
sub do_stat  { $_[0]->_do_stat(SSH2_FXP_STAT , $_[1]) }
sub _do_stat {
    my $sftp = shift;
    my $id = $sftp->_send_str_request(@_);
    $sftp->get_attrs($id);
}

## SSH2_FXP_OPENDIR (11)
sub do_opendir {
    my $sftp = shift;
    my $id = $sftp->_send_str_request(SSH2_FXP_OPENDIR, @_);
    $sftp->get_handle($id);
}

## SSH2_FXP_CLOSE (4),   SSH2_FXP_REMOVE (13),
## SSH2_FXP_MKDIR (14),  SSH2_FXP_RMDIR (15),
## SSH2_FXP_SETSTAT (9), SSH2_FXP_FSETSTAT (10)
# all of these return a status (SSH2_FX_OK on success)
{
    # no strict 'refs';
    *do_close    = _gen_simple_method(SSH2_FXP_CLOSE,  'close file');
    *do_remove   = _gen_simple_method(SSH2_FXP_REMOVE, 'delete file');
    *do_mkdir    = _gen_simple_method(SSH2_FXP_MKDIR,  'create directory');
    *do_rmdir    = _gen_simple_method(SSH2_FXP_RMDIR,  'remove directory');
    *do_setstat  = _gen_simple_method(SSH2_FXP_SETSTAT , 'setstat');
    *do_fsetstat = _gen_simple_method(SSH2_FXP_FSETSTAT , 'fsetstat');
}

sub _gen_simple_method {
    my($code, $msg) = @_;
    sub {
        my $sftp = shift;
        my $id = @_ > 1 ?
            $sftp->_send_str_attrs_request($code, @_) :
            $sftp->_send_str_request($code, @_);
        $sftp->_check_ok_status($id, $msg);
    };
}

## SSH2_FXP_REALPATH (16)
sub do_realpath {
    my $sftp = shift;
    my($path) = @_;
    my $expected_id = $sftp->_send_str_request(SSH2_FXP_REALPATH, $path);
    my $msg = $sftp->get_msg;
    my $type = $msg->get_int8;
    my $id = $msg->get_int32;
    croak "ID mismatch ($id != $expected_id)" unless $id == $expected_id;
    if ($type == SSH2_FXP_STATUS) {
        my $status = $msg->get_int32;
	$sftp->warn("Couldn't canonicalise $path",$status);
        return;
    }
    elsif ($type != SSH2_FXP_NAME) {
        croak "Expected SSH2_FXP_NAME packet, got $type";
    }
    my $count = $msg->get_int32;
    croak "Got multiple names ($count) from SSH2_FXP_REALPATH"
        unless $count == 1;
    $msg->get_str;   ## Filename.
}

## SSH2_FXP_RENAME (18)
sub do_rename {
    my $sftp = shift;
    my($old, $new) = @_;
    my($msg, $id) = $sftp->new_msg_w_id(SSH2_FXP_RENAME,
					str => $old, str => $new);
    $sftp->send_msg($msg);
    $sftp->debug("Sent message SSH2_FXP_RENAME '$old' => '$new'");
    $sftp->_check_ok_status($id, "rename '$old' to '$new'");
}

## High-level client -> server methods.

# always returns undef on failure
# if local filename is provided, returns '' on success, else file contents
sub get {
    my $sftp = shift;
    my($remote, $local, $cb) = @_;
    my $ssh = $sftp->{ssh};
    my $want = defined wantarray ? 1 : 0;

    my $a = $sftp->do_stat($remote) or return;
    my $handle = $sftp->do_open($remote, SSH2_FXF_READ) or return;

    local *FH;
    if ($local) {
	open FH, ">$local" or
	    $sftp->do_close($handle), croak "Can't open $local: $!";
	binmode FH or
	    $sftp->do_close($handle), croak "Can't binmode FH: $!";
    }

    my $offset = 0;
    my $ret = '';
    while (1) {
        my($data, $status) = $sftp->do_read($handle, $offset, COPY_SIZE);
        last if defined $status && $status == SSH2_FX_EOF;
        return unless $data;
        my $len = length($data);
        croak "Received more data than asked for $len > " . COPY_SIZE
            if $len > COPY_SIZE;
        $sftp->debug("In read loop, got $len offset $offset");
        $cb->($sftp, $data, $offset, $a->size) if defined $cb;
        if ($local) {
            print FH $data;
        }
        elsif ($want) {
            $ret .= $data;
        }
        $offset += $len;
    }
    $sftp->do_close($handle);

    if ($local) {
        close FH;
        my $flags = $a->flags;
        my $mode = $flags & SSH2_FILEXFER_ATTR_PERMISSIONS ?
            $a->perm & 0777 : 0666;
        chmod $mode, $local or croak "Can't chmod $local: $!";

        if ($flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
            utime $a->atime, $a->mtime, $local or
                croak "Can't utime $local: $!";
        }
    }
    $ret;
}

sub put {
    my $sftp = shift;
    my($local, $remote, $cb) = @_;
    my $ssh = $sftp->{ssh};

    my @stat = stat $local or croak "Can't stat local $local: $!";
    my $size = $stat[7];
    my $a = Net::SFTP::Foreign::Attributes->new(Stat => \@stat);
    my $flags = $a->flags;
    $flags &= ~SSH2_FILEXFER_ATTR_SIZE;
    $flags &= ~SSH2_FILEXFER_ATTR_UIDGID;
    $a->flags($flags);
    $a->perm( $a->perm & 0777 );

    local *FH;
    open FH, $local or croak "Can't open local file $local: $!";
    binmode FH or croak "Can't binmode FH: $!";

    my $handle = $sftp->do_open($remote, SSH2_FXF_WRITE | SSH2_FXF_CREAT |
	SSH2_FXF_TRUNC, $a) or return;  # check status for info

    my $offset = 0;
    while (1) {
        my($len, $data, $msg, $id);
        $len = read FH, $data, COPY_SIZE;
        last unless $len;
        $cb->($sftp, $data, $offset, $size) if defined $cb;
        my $status = $sftp->do_write($handle, $offset, $data);
        if ($status != SSH2_FX_OK) {
            close FH;
            return;
        }
        $sftp->debug("In write loop, got $len offset $offset");
        $offset += $len;
    }

    close FH or $sftp->warn("Can't close local file $local: $!");

    # ignore failures here, the transmission is the important part
    $sftp->do_fsetstat($handle, $a);
    $sftp->do_close($handle);
    return 1;
}

# returns ()/undef on error, directory list/reference to same otherwise
sub ls {
    my $sftp = shift;
    my($remote, $code) = @_;
    my @dir;
    my $handle = $sftp->do_opendir($remote) or return;
    while (1) {
        my $expected_id = $sftp->_send_str_request(SSH2_FXP_READDIR, $handle);
        my $msg = $sftp->get_msg;
        my $type = $msg->get_int8;
        my $id = $msg->get_int32;
        $sftp->debug("Received reply T:$type I:$id");

        croak "ID mismatch ($id != $expected_id)" unless $id == $expected_id;
        if ($type == SSH2_FXP_STATUS) {
            my $status = $msg->get_int32;
            $sftp->debug("Received SSH2_FXP_STATUS $status");
            if ($status == SSH2_FX_EOF) {
                last;
            }
            else {
		$sftp->warn("Couldn't read directory",$status);
                $sftp->do_close($handle);
                return;
            }
        }
        elsif ($type != SSH2_FXP_NAME) {
            croak "Expected SSH2_FXP_NAME packet, got $type";
        }

        my $count = $msg->get_int32;
        last unless $count;
        $sftp->debug("Received $count SSH2_FXP_NAME responses");
        for my $i (0..$count-1) {
            my $fname = $msg->get_str;
            my $lname = $msg->get_str;
            my $a = $msg->get_attributes;
            my $rec = {
                filename => $fname,
                longname => $lname,
                a        => $a,
            };
            if ($code && ref($code) eq "CODE") {
                $code->($rec);
            }
            else {
                push @dir, $rec;
            }
        }
    }
    $sftp->do_close($handle);
    wantarray ? @dir : \@dir;
}

## Messaging methods--messages are essentially sub-packets.

sub msg_id { $_[0]->{_msg_id}++ }

sub new_msg {
    shift;
    @_ & 1 or croak 'invalid number of arguments';
    Net::SFTP::Foreign::Buffer->new(int8 => @_);
}

sub new_msg_w_id {
    my $sftp = shift;
    my $code = shift;
    my $id = $sftp->msg_id;
    my $msg = Net::SFTP::Foreign::Buffer->new(int8 => $code, int32 => $id, @_);
    ($msg, $id)
}

sub send_msg {
    my ($sftp, $buf)=@_;
    my $bytes = $buf->bytes;
    $bytes = pack('N', length($bytes)) . $bytes;
    my $len = length $bytes;
    my $off = 0;
    local $SIG{PIPE}='IGNORE';
    while ($len) {
	my $limlen = $len < 8192 ? $len : 8192;
	my $bw = syswrite($sftp->{ssh_out}, $bytes, $limlen,  $off);
	unless (defined $bw) {
	    $sftp->{status}=SSH2_FX_CONNECTION_LOST;
	    croak "writing to ssh pipe failed ($!)";
	}
	$len-=$bw;
	$off+=$bw;
    }
}

sub my_sysread {
    my $sftp = shift;
    my ($in, $len)=@_;
    my $off=0;
    my $bytes;
    local $SIG{PIPE}='IGNORE';
    while ($len) {
	my $limlen = $len < 8192 ? $len : 8192;
	my  $br=sysread($in, $bytes, $limlen, $off);
	unless (defined $br and $br) {
	    $sftp->{status}=SSH2_FX_CONNECTION_LOST;
	    croak "reading from ssh pipe failed ($!)";
	}
	$len-=$br;
	$off+=$br;
    }
    $bytes
}

sub get_msg {
    my $sftp=shift;
    my $len = unpack('N', $sftp->my_sysread($sftp->{ssh_in}, 4));
    $len > 256*1024 and croak "message too long ($len bytes)";
    Net::SFTP::Foreign::Buffer->make($sftp->my_sysread($sftp->{ssh_in}, $len));
}

1;
__END__

=head1 NAME

Net::SFTP::Foreign - Secure File Transfer Protocol client

=head1 SYNOPSIS

    use Net::SFTP::Foreign::Compat;
    my $sftp = Net::SFTP::Foreign::Compat->new($host);
    $sftp->get("foo", "bar");
    $sftp->put("bar", "baz");

=head1 DESCRIPTION

  *** WARNING!!!

  The old Net::SFTP::Foreign API inherited from the Net::SFTP package
  is being obsolete. New versions of Net::SFTP::Foreign are going to
  provide a new much improved but backward incompatible API.

  Development versions exposing this new API are already available
  from CPAN, they use version numbers as 0.9x_xx and so are not
  automatically installed by the CPAN module.

  If you want to continue using the old API you should change your
  scripts to use the adaptor package Net::SFTP::Foreign::Compat
  available from this distribution.


Net::SFTP::Foreign is a Perl client for the SFTP. It provides a
subset of the commands listed in the SSH File Transfer Protocol IETF
draft, which can be found at
L<http://www.openssh.org/txt/draft-ietf-secsh-filexfer-02.txt>.

Net::SFTP::Foreign is a forked version of Net::SFTP that uses an
external C<ssh> client (i.e. OpenSSH, L<http://www.openssh.org/>)
instead of Net::SSH::Perl to connect to the server.

SFTP stands for Secure File Transfer Protocol and is a method of
transferring files between machines over a secure, encrypted
connection (as opposed to regular FTP, which functions over an
insecure connection). The security in SFTP comes through its
integration with SSH, which provides an encrypted transport layer over
which the SFTP commands are executed, and over which files can be
transferred. The SFTP protocol defines a client and a server; only the
client, not the server, is implemented in Net::SFTP::Foreign.

=head2 Net::SFTP::Foreign Vs. Net::SFTP

Why should I prefer Net::SFTP::Foreign over Net::SFTP?

Well, both modules have their pros and cons:

Net::SFTP::Foreign does not requiere a bunch of additional modules and
external libraries to work, just the OpenBSD ssh client (or the
commercial one).

I trust OpenSSH ssh client more than Net::SSH::Perl: there are lots of
paranoid people ensuring that OpenSSH doesn't have security holes!

If you have an ssh infrastructure already deployed in your
environment, using the binary ssh client ensures a seamless
integration with it.

On the other hand, using the external command means an additional
proccess being launched and running, depending on your OS this could
eat more resources than the in process pure perl implementation in
Net::SSH::Perl used by Net::SFTP.

Net::SFTP::Foreign supports version 2 of the ssh protocol only.

Finally Net::SFTP::Foreign does not (and will never) allow to use
passwords for authentication, as Net::SFTP does.


=head1 USAGE

=head2 Net::SFTP::Foreign->new($host, %args)

Opens a new SFTP connection with a remote host C<$host>, and returns a
Net::SFTP::Foreign object representing that open connection.

C<%args> can contain:

=over 4

=item * host => $hostname

remote host name

=item * user => $username

username to use to log in to the remote server. This should
be your SSH login, and can be empty, in which case the username
is drawn from the user executing the process.

=item * port => $portnumber

port number where the remote ssh server is listening

=item * more => [@more_ssh_args]

additional args passed to ssh command.

=item * ssh_cmd => $sshcmd

name of the external ssh client.

=item * debug => 1

if set to a true value, debugging messages will be printed out. The
default is false.

=item * open2_cmd => [@cmd]

=item * open2_cmd => $cmd;

allows to completely redefine how C<ssh> is called. Its arguments are
passed to L<IPC::Open2::open2> to open a pipe to the remote
server. When present, other options are ignored (host, user, etc.)

=back

=head2 $sftp->status

Returns the last remote SFTP status value.  Only useful after one
of the following methods has failed.  Returns SSH2_FX_OK if there
is no remote error (e.g. local file not found).  In list context,
returns a list of (status code, status text from C<fx2txt>).

If a low-level protocol error or unexpected local error occurs,
we die with an error message.

=head2 $sftp->get($remote [, $local [, \&callback ] ])

Downloads a file C<$remote> from the remote host. If C<$local>
is specified, it is opened/created, and the contents of the
remote file C<$remote> are written to C<$local>. In addition,
its filesystem attributes (atime, mtime, permissions, etc.)
will be set to those of the remote file.

If C<get> is called in a non-void context, returns the contents
of C<$remote> (as well as writing them to C<$local>, if C<$local>
is provided.  Undef is returned on failure.

C<$local> is optional. If not provided, the contents of the
remote file C<$remote> will be either discarded, if C<get> is
called in void context, or returned from C<get> if called in
a non-void context. Presumably, in the former case, you will
use the callback function C<\&callback> to "do something" with
the contents of C<$remote>.

If C<\&callback> is specified, it should be a reference to a
subroutine. The subroutine will be executed at each iteration
of the read loop (files are generally read in 8192-byte
blocks, although this depends on the server implementation).
The callback function will receive as arguments: a
Net::SFTP::Foreign object with an open SFTP connection; the data
read from the SFTP server; the offset from the beginning of
the file (in bytes); and the total size of the file (in
bytes). You can use this mechanism to provide status messages,
download progress meters, etc.:

    sub callback {
        my($sftp, $data, $offset, $size) = @_;
        print "Read $offset / $size bytes\r";
    }

=head2 $sftp->put($local, $remote [, \&callback ])

Uploads a file C<$local> from the local host to the remote
host, and saves it as C<$remote>.

If C<\&callback> is specified, it should be a reference to a
subroutine. The subroutine will be executed at each iteration
of the write loop, directly after the data has been read from
the local file. The callback function will receive as arguments:
a Net::SFTP::Foreign object with an open SFTP connection; the data
read from C<$local>, generally in 8192-byte chunks;; the offset
from the beginning of the file (in bytes); and the total size
of the file (in bytes). You can use this mechanism to provide
status messages, upload progress meters, etc.:

    sub callback {
        my($sftp, $data, $offset, $size) = @_;
        print "Wrote $offset / $size bytes\r";
    }

Returns true on success, undef on error.

=head2 $sftp->ls($remote [, $subref ])

Fetches a directory listing of C<$remote>.

If C<$subref> is specified, for each entry in the directory,
C<$subref> will be called and given a reference to a hash
with three keys: C<filename>, the name of the entry in the
directory listing; C<longname>, an entry in a "long" listing
like C<ls -l>; and C<a>, a Net::SFTP::Foreign::Attributes object,
which contains the file attributes of the entry (atime, mtime,
permissions, etc.).

If C<$subref> is not specified, returns a list of directory
entries, each of which is a reference to a hash as described
in the previous paragraph.

=head1 COMMAND METHODS

Net::SFTP::Foreign supports all of the commands listed in the SFTP
version 3 protocol specification. Each command is available
for execution as a separate method, with a few exceptions:
C<SSH_FXP_INIT>, C<SSH_FXP_VERSION>, and C<SSH_FXP_READDIR>.

These are the available command methods:

=head2 $sftp->do_open($path, $flags [, $attrs ])

Sends the C<SSH_FXP_OPEN> command to open a remote file C<$path>,
and returns an open handle on success. On failure returns
C<undef>. The "open handle" is not a Perl filehandle, nor is
it a file descriptor; it is merely a marker used to identify
the open file between the client and the server.

C<$flags> should be a bitmask of open flags, whose values can
be obtained from Net::SFTP::Foreign::Constants:

    use Net::SFTP::Foreign::Constants qw( :flags );

C<$attrs> should be a Net::SFTP::Foreign::Attributes object,
specifying the initial attributes for the file C<$path>. If
you're opening the file for reading only, C<$attrs> can be
left blank, in which case it will be initialized to an
empty set of attributes.

=head2 $sftp->do_read($handle, $offset, $copy_size)

Sends the C<SSH_FXP_READ> command to read from an open file
handle C<$handle>, starting at C<$offset>, and reading at most
C<$copy_size> bytes.

Returns a two-element list consisting of the data read from
the SFTP server in the first slot, and the status code (if any)
in the second. In the case of a successful read, the status code
will be C<undef>, and the data will be defined and true. In the
case of EOF, the status code will be C<SSH2_FX_EOF>, and the
data will be C<undef>. And in the case of an error in the read,
a warning will be emitted, the status code will contain the
error code, and the data will be C<undef>.

=head2 $sftp->do_write($handle, $offset, $data)

Sends the C<SSH_FXP_WRITE> command to write to an open file handle
C<$handle>, starting at C<$offset>, and where the data to be
written is in C<$data>.

Returns the status code. On a successful write, the status code
will be equal to SSH2_FX_OK; in the case of an unsuccessful
write, a warning will be emitted, and the status code will
contain the error returned from the server.

=head2 $sftp->do_close($handle)

Sends the C<SSH_FXP_CLOSE> command to close either an open
file or open directory, identified by C<$handle> (the handle
returned from either C<do_open> or C<do_opendir>).

Emits a warning if the C<CLOSE> fails.

Returns the status code for the operation. To turn the
status code into a text message, take a look at the C<fx2txt>
function in Net::SFTP::Foreign::Util.

=head2 $sftp->do_lstat($path)

=head2 $sftp->do_fstat($handle)

=head2 $sftp->do_stat($path)

These three methods all perform similar functionality: they
run a C<stat> on a remote file and return the results in a
Net::SFTP::Foreign::Attributes object on success.

On failure, all three methods return C<undef>, and emit a
warning.

C<do_lstat> sends a C<SSH_FXP_LSTAT> command to obtain file
attributes for a named file C<$path>. C<do_stat> sends a
C<SSH_FXP_STAT> command, and differs from C<do_lstat> only
in that C<do_stat> follows symbolic links on the server,
whereas C<do_lstat> does not follow symbolic links.

C<do_fstat> sends a C<SSH_FXP_FSTAT> command to obtain file
attributes for an open file handle C<$handle>.

=head2 $sftp->do_setstat($path, $attrs)

=head2 $sftp->do_fsetstat($handle, $attrs)

These two methods both perform similar functionality: they
set the file attributes of a remote file. In both cases
C<$attrs> should be a Net::SFTP::Foreign::Attributes object.

C<do_setstat> sends a C<SSH_FXP_SETSTAT> command to set file
attributes for a remote named file C<$path> to C<$attrs>.

C<do_fsetstat> sends a C<SSH_FXP_FSETSTAT> command to set the
attributes of an open file handle C<$handle> to C<$attrs>.

Both methods emit a warning if the operation failes, and
both return the status code for the operation. To turn the
status code into a text message, take a look at the C<fx2txt>
function in Net::SFTP::Foreign::Util.

=head2 $sftp->do_opendir($path)

Sends a C<SSH_FXP_OPENDIR> command to open the remote
directory C<$path>, and returns an open handle on success.
On failure returns C<undef>.

=head2 $sftp->do_remove($path)

Sends a C<SSH_FXP_REMOVE> command to remove the remote file
C<$path>.

Emits a warning if the operation fails.

Returns the status code for the operation. To turn the
status code into a text message, take a look at the C<fx2txt>
function in Net::SFTP::Foreign::Util.

=head2 $sftp->do_mkdir($path, $attrs)

Sends a C<SSH_FXP_MKDIR> command to create a remote directory
C<$path> whose attributes should be initialized to C<$attrs>,
a Net::SFTP::Foreign::Attributes object.

Emits a warning if the operation fails.

Returns the status code for the operation. To turn the
status code into a text message, take a look at the C<fx2txt>
function in Net::SFTP::Foreign::Util.

=head2 $sftp->do_rmdir($path)

Sends a C<SSH_FXP_RMDIR> command to remove a remote directory
C<$path>.

Emits a warning if the operation fails.

Returns the status code for the operation. To turn the
status code into a text message, take a look at the C<fx2txt>
function in Net::SFTP::Foreign::Util.

=head2 $sftp->do_realpath($path)

Sends a C<SSH_FXP_REALPATH> command to canonicalise C<$path>
to an absolute path. This can be useful for turning paths
containing C<'..'> into absolute paths.

Returns the absolute path on success, C<undef> on failure.

=head2 $sftp->do_rename($old, $new)

Sends a C<SSH_FXP_RENAME> command to rename C<$old> to C<$new>.

Emits a warning if the operation fails.

Returns the status code for the operation. To turn the
status code into a text message, take a look at the C<fx2txt>
function in Net::SFTP::Foreign::Util.

=head1 BUGS

On some operative systems, closing the pipes used to comunicate with
the slave ssh process does not terminate it and a work around has to
be applied. If you find that your scripts hung when the sftp object
gets out of scope, try setting C<$Net::SFTP::Foreign::dirty_cleanup>
to a true value and also send me a report including the value of
C<$^O> on your machine.

To report bugs, please, send me and email or use
L<http://rt.cpan.org>.


=head1 SEE ALSO

OpenSSH web site at L<www.openssh.org>, L<sftp(1)> and
L<sftp-server(8)> manual pages.

Documentation for the original packages L<Net::SFTP> and
L<Net::SSH::Perl>.

=head1 AUTHOR

Salvador FandiE<ntilde>o <sfandino@yahoo.com>.

Net::SFTP::Foreign is based on Net::SFTP (95% of the code comes from
there!) developed by Benjamin Trott and Dave Rolsky.

=head1 COPYRIGHT

Copyright (c) 2005, 2006 Salvador FandiE<ntilde>o.

Copyright (c) 2001 Benjamin Trott, Copyright (c) 2003 David Rolsky.

All rights reserved.  This program is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the LICENSE file included
with this module.

=cut
