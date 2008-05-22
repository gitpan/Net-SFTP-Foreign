package Net::SFTP::Foreign;

our $VERSION = '1.37_06';

use strict;
use warnings;
use Carp qw(carp croak);

use Fcntl qw(:mode O_NONBLOCK F_SETFL F_GETFL);
use IPC::Open2;
use Symbol ();
use Errno ();
use Scalar::Util;

our $debug;
our $dirty_cleanup;
my $windows;

BEGIN {
    $windows = $^O =~ /Win32/;

    if ($^O =~ /solaris/i) {
	$dirty_cleanup = 1 unless defined $dirty_cleanup;
    }
}

sub _hexdump {
    no warnings qw(uninitialized);
    my $data = shift;
    while ($data =~ /(.{1,32})/smg) {
        my $line=$1;
        my @c= (( map { sprintf "%02x",$_ } unpack('C*', $line)),
                (("  ") x 32))[0..31];
        $line=~s/(.)/ my $c=$1; unpack("c",$c)>=32 ? $c : '.' /egms;
        print STDERR join(" ", @c, '|', $line), "\n";
    }
}

use Net::SFTP::Foreign::Constants qw( :fxp :flags :att
				      :status :error
				      SSH2_FILEXFER_VERSION );
use Net::SFTP::Foreign::Attributes;
use Net::SFTP::Foreign::Buffer;
use Net::SFTP::Foreign::Helpers;

use Net::SFTP::Foreign::Common;
our @ISA = qw(Net::SFTP::Foreign::Common);


use constant COPY_SIZE => 16384;

sub _next_msg_id { shift->{_msg_id}++ }

use constant _empty_attributes => Net::SFTP::Foreign::Attributes->new;

sub _queue_new_msg {
    my $sftp = shift;
    my $code = shift;
    my $id = $sftp->_next_msg_id;
    my $msg = Net::SFTP::Foreign::Buffer->new(int8 => $code, int32 => $id, @_);
    $sftp->_queue_msg($msg);
    return $id;
}

sub _queue_msg {
    my ($sftp, $buf) = @_;

    my $bytes = $buf->bytes;
    my $len = length $bytes;

    if ($debug and $debug & 1) {
	$sftp->{_queued}++;
	_debug(sprintf("queueing msg len: %i, code:%i, id:%i ... [$sftp->{_queued}]",
		       $len, unpack(CN => $bytes)));

        ($debug & 16) and _hexdump(pack('N', length($bytes)) . $bytes);
    }

    $sftp->{_bout} .= pack('N', length($bytes));
    $sftp->{_bout} .= $bytes;
}

sub _sysreadn {
    my ($sftp, $n) = @_;
    my $bin = \$sftp->{_bin};
    while (1) {
	my $len = length $$bin;
	return 1 if $len >= $n;
	my $read = sysread($sftp->{ssh_in}, $$bin, $n - $len, $len);
	unless ($read) {
	    $sftp->_conn_lost;
	    return undef;
	}
    }
    return $n;
}

sub _do_io_unix {
    my ($sftp, $timeout) = @_;

    $debug and $debug & 32 and _debug(sprintf "_do_io connected: %s", $sftp->{_connected} || 0);

    return undef unless $sftp->{_connected};

    my $fnoout = fileno $sftp->{ssh_out};
    my $fnoin = fileno $sftp->{ssh_in};
    my ($rv, $wv) = ('', '');
    vec($rv, $fnoin, 1) = 1;
    vec($wv, $fnoout, 1) = 1;

    my $bin = \$sftp->{_bin};
    my $bout = \$sftp->{_bout};

    local $SIG{PIPE} = 'IGNORE';

    while (1) {
        my $lbin = length $$bin;
        if ($lbin >= 4) {
            my $len = 4 + unpack N => $$bin;
            return 1 if $lbin >= $len;
            if ($len > 256 * 1024) {
                $sftp->_set_status(SSH2_FX_BAD_MESSAGE);
                $sftp->_set_error(SFTP_ERR_REMOTE_BAD_MESSAGE,
                                  "bad remote message received");
                return undef;
            }
        }

        my $rv1 = $rv;
        my $wv1 = length($$bout) ? $wv : '';

        $debug and $debug & 32 and _debug("_do_io select(-,-,-, $timeout)");

        my $n = select($rv1, $wv1, undef, $timeout);
        if ($n > 0) {
            if (vec($wv1, $fnoout, 1)) {
                my $written = syswrite($sftp->{ssh_out}, $$bout, 16384);
                $debug and $debug & 32 and _debug (sprintf "_do_io write queue: %d, syswrite: %s, max: %d",
                                                   length $$bout,
                                                   (defined $written ? $written : 'undef'),
                                                   16384);
                unless ($written) {
                    $sftp->_conn_lost;
                    return undef;
                }
                substr($$bout, 0, $written, '');
            }
            if (vec($rv1, $fnoin, 1)) {
                my $read = sysread($sftp->{ssh_in}, $sftp->{_bin}, 16384, length($$bin));
                $debug and $debug & 32 and _debug (sprintf "_do_io read sysread: %s, total read: %d",
                                                   (defined $read ? $read : 'undef'),
                                                   length $sftp->{_bin});
                unless ($read) {
                    $sftp->_conn_lost;
                    return undef;
                }
            }
        }
        else {
            $debug and $debug & 32 and _debug "_do_io select failed: $!";
            next if ($n < 0 and $! == Errno::EINTR());
            return undef;
        }
    }
}

sub _do_io_win {
    my ($sftp, $timeout) = @_;

    return undef unless $sftp->{_connected};

    my $bin = \$sftp->{_bin};
    my $bout = \$sftp->{_bout};

    while (length $$bout) {
	my $written = syswrite($sftp->{ssh_out}, $$bout, 16384);
	unless ($written) {
	    $sftp->_conn_lost;
	    return undef;
	}
	substr($$bout, 0, $written, "");
    }

    $sftp->_sysreadn(4) or return undef;

    my $len = 4 + unpack N => $$bin;
    if ($len > 256 * 1024) {
	$sftp->_set_status(SSH2_FX_BAD_MESSAGE);
	$sftp->_set_error(SFTP_ERR_REMOTE_BAD_MESSAGE,
			  "bad remote message received");
	return undef;
    }
    $sftp->_sysreadn($len);
}

*_do_io = $windows ? \&_do_io_win : \&_do_io_unix;

sub _conn_lost {
    my ($sftp, $status, $err, @str) = @_;

    $debug and $debug & 32 and _debug("_conn_lost");

    $sftp->{_status} or
	$sftp->_set_status(defined $status ? $status : SSH2_FX_CONNECTION_LOST);

    $sftp->{_error} or
	$sftp->_set_error((defined $err ? $err : SFTP_ERR_CONNECTION_BROKEN),
			  (@str ? @str : "Connection to remote server is broken"));

    undef $sftp->{_connected};
}

sub _conn_failed {
    shift->_conn_lost(SSH2_FX_NO_CONNECTION,
                      SFTP_ERR_CONNECTION_BROKEN,
                      @_)
}

sub _get_msg {
    my $sftp = shift;

    $debug and $debug & 1 and _debug("waiting for message... [$sftp->{_queued}]");

    unless ($sftp->_do_io($sftp->{_timeout})) {
	$sftp->_conn_lost(undef, undef, "Connection to remote server stalled");
	return undef;
    }

    my $bin = \$sftp->{_bin};
    my $len = unpack N => substr($$bin, 0, 4, '');
    my $msg = Net::SFTP::Foreign::Buffer->make(substr($$bin, 0, $len, ''));

    if ($debug and $debug & 1) {
	$sftp->{_queued}--;
        my ($code, $id, $status) = unpack( CNN => $$msg);
        $status = '-' unless $code == SSH2_FXP_STATUS;
	_debug(sprintf("got it!, len:%i, code:%i, id:%i, status: %s",
                       $len, $code, $id, $status));
        ($debug & 8) and _hexdump($$msg);
    }

    return $msg;
}

sub _ipc_open2_bug_workaround {
    # in some cases, IPC::Open3::open2 returns from the child
    my $pid = shift;
    unless ($pid == $$) {
        require POSIX;
        POSIX::_exit(-1);
    }
}

sub new {
    ${^TAINT} and &_catch_tainted_args;

    my $class = shift;
    unshift @_, 'host' if @_ & 1;
    my %opts = @_;

    my $sftp = { _msg_id => 0,
		 _queue_size => ($windows ? 4 : 10),
		 _block_size => 16384,
		 _read_ahead => 16384 * 4,
		 _bout => '',
		 _bin => '',
		 _connected => 1,
		 _queued => 0 };

    bless $sftp, $class;

    $sftp->_set_status;
    $sftp->_set_error;

    my $transport = delete $opts{transport};

    $sftp->{_timeout} = delete $opts{timeout};
    $sftp->{_autoflush} = delete $opts{autoflush};

    my ($pass, $passphrase, $expect_log_user);

    my @open2_cmd;
    unless (defined $transport) {

        $pass = delete $opts{passphrase};

        if (defined $pass) {
            $passphrase = 1;
        }
        else {
            $pass = delete $opts{password};
        }

        $expect_log_user = delete $opts{expect_log_user} || 0;

        my $open2_cmd = delete $opts{open2_cmd};
        if (defined $open2_cmd) {
            @open2_cmd = _ensure_list($open2_cmd);
        }
        else {
            my $host = delete $opts{host};
            defined $host or croak "sftp target host not defined";

            my $ssh_cmd = delete $opts{ssh_cmd};
            @open2_cmd = defined $ssh_cmd ? $ssh_cmd : 'ssh';

            my $port = delete $opts{port};
            push @open2_cmd, -p => $port if defined $port;

            my $user = delete $opts{user};
            push @open2_cmd, -l => $user if defined $user;

            my $more = delete $opts{more};
            if (defined $more) {
                if (!ref($more) and $more =~ /^-\w\s+\S/) {
                    carp "'more' argument looks like if it needs to be splited first"
                }
                push @open2_cmd, _ensure_list($more)
            }

            push @open2_cmd, $host, -s => 'sftp';
        }
    }

    croak "invalid option(s) '".CORE::join("', '", keys %opts)."' or bad combination"
                                           if %opts;

    if (defined $transport) {
        if (ref $transport eq 'ARRAY') {
            @{$sftp}{qw(ssh_in ssh_out pid)} = @$transport;
        }
        else {
            $sftp->{ssh_in} = $sftp->{ssh_out} = $transport;
            $sftp->{_ssh_out_is_not_dupped} = 1;
        }
    }
    else {
        if (${^TAINT} and Scalar::Util::tainted($ENV{PATH})) {
            _tcroak('Insecure $ENV{PATH}')
        }

        my $this_pid = $$;
        local $@;
        local $SIG{__DIE__};

        if (defined $pass) {

            # user has requested to use a password or a passphrase for authentication
            # we use Expect to handle that

            eval { require IO::Pty };
            $@ and croak "password authentication is not available, IO::Pty and Expect are not installed";
            eval { require Expect };
            $@ and croak "password authentication is not available, Expect is not installed";

            local $ENV{SSH_ASKPASS} if $passphrase;
            local $ENV{SSH_AUTH_SOCK} if $passphrase;

            my $name = $passphrase ? 'Passphrase' : 'Password';
            my $eto = $sftp->{_timeout} ? $sftp->{_timeout} * 4 : 120;

            my $pty = IO::Pty->new;
            my $expect = Expect->init($pty);
            $expect->raw_pty(1);
            $expect->log_user($expect_log_user);

            my $child = eval { open2($sftp->{ssh_in}, $sftp->{ssh_out}, '-') };
            if (defined $child and !$child) {
                $pty->make_slave_controlling_terminal;
                exec @open2_cmd;
                exit -1;
            }
            _ipc_open2_bug_workaround $this_pid;

            unless (defined $child) {
                $sftp->_conn_failed("Bad ssh command", $!);
                return $sftp;
            }
            $sftp->{pid} = $child;
            $sftp->{_expect} = $expect;

            unless($expect->expect($eto, ":")) {
                $sftp->_conn_failed("$name not requested as expected", $expect->error);
                return $sftp;
            }
            $expect->send("$pass\n");

            unless ($expect->expect($eto, "\n")) {
                $sftp->_conn_failed("$name interchange did not complete", $expect->error);
                return $sftp;
            }
        }
        else {
            _debug "ssh cmd: @open2_cmd\n" if ($debug and $debug & 1);

            $sftp->{pid} = eval { open2($sftp->{ssh_in}, $sftp->{ssh_out}, @open2_cmd) };
            _ipc_open2_bug_workaround $this_pid;
            unless (defined $sftp->{pid}) {
                $sftp->_conn_failed("Bad ssh command", $!);
                return $sftp;
            }
        }
        unless ($windows) {
            for my $dir (qw(ssh_in ssh_out)) {
                my $flags = fcntl($sftp->{$dir}, F_GETFL, 0);
                fcntl($sftp->{$dir}, F_SETFL, $flags | O_NONBLOCK);
            }
        }
    }

    $sftp->_init;
    $sftp
}

sub DESTROY {
    my $sftp = shift;
    my $pid = $sftp->{pid};

    $debug and $debug & 4 and Net::SFTP::Foreign::_debug("$sftp->DESTROY called (ssh pid: ".($pid||'').")");

    if (defined $pid) {
        local $?;
        local $!;
        close $sftp->{ssh_out} if (defined $sftp->{ssh_out} and not $sftp->{_ssh_out_is_not_dupped});
        close $sftp->{ssh_in} if defined $sftp->{ssh_in};
        if ($windows) {
            kill 1, $pid
                and waitpid($pid, 0);
        }
        else {
            local $@;
            local $SIG{__DIE__};
            for my $sig (0, 1, 1, 9, 9) {
                if ($sig) {
                    kill $sig, $pid
                }
                else {
                    next if $dirty_cleanup
                }
                eval {
                    local $SIG{ALRM} = sub { die "timeout\n" };
                    alarm 8;
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
    }
}

sub _init {
    my $sftp = shift;
    $sftp->_queue_msg( Net::SFTP::Foreign::Buffer->new(int8 => SSH2_FXP_INIT,
						       int32 => SSH2_FILEXFER_VERSION));

    if (my $msg = $sftp->_get_msg) {
	my $type = $msg->get_int8;
	if ($type == SSH2_FXP_VERSION) {
	    my $version = $msg->get_int32;

	    ## XXX Check for extensions.

	    $sftp->{server_version} = $version;
            $sftp->{server_extensions} = {};
            while (length $$msg) {
                my $key = $msg->get_str;
                my $value = $msg->get_str;
                $sftp->{server_extensions}{$key} = $value;
            }

	    return $version;
	}

	$sftp->_conn_lost(SSH2_FX_BAD_MESSAGE,
			  SFTP_ERR_REMOTE_BAD_MESSAGE,
			  "bad packet type, expecting SSH2_FXP_VERSION, got $type");
    }
    return undef;
}

sub _rel2abs {
    my ($sftp, $path) = @_;
    if (defined $sftp->{cwd} and $path !~/^\//) {
        # carp "sftp->rel2abs($path) => $sftp->{cwd}/$path\n";
        return "$sftp->{cwd}/$path"
    }
    return $path
}

# helper methods:
sub _get_msg_and_check {
    my ($sftp, $etype, $eid, $err, $errstr) = @_;
    my $msg = $sftp->_get_msg;
    if ($msg) {
	my $type = $msg->get_int8;
	my $id = $msg->get_int32;
	
	$sftp->_set_status;
	$sftp->_set_error;
	
	if ($id != $eid) {
	    $sftp->_conn_lost(SSH2_FX_BAD_MESSAGE,
			      SFTP_ERR_REMOTE_BAD_MESSAGE,
			      $errstr, "bad packet sequence, expected $eid, got $id");
	    return undef;
	}

	if ($type != $etype) {
	    if ($type == SSH2_FXP_STATUS) {
		my $status = $sftp->_set_status($msg->get_int32, $msg->get_str);
		$sftp->_set_error($err, $errstr, $status);
	    }
	    else {
		$sftp->_conn_lost(SSH2_FX_BAD_MESSAGE,
				  SFTP_ERR_REMOTE_BAD_MESSAGE,
				  $errstr, "bad packet type, expected $etype packet, got $type");	
	    }
	    return undef;
	}
    }
    $msg;
}

# reads SSH2_FXP_HANDLE packet and returns handle, or undef on failure
sub _get_handle {
    my ($sftp, $eid, $error, $errstr) = @_;
    if (my $msg = $sftp->_get_msg_and_check(SSH2_FXP_HANDLE, $eid,
					    $error, $errstr)) {
	return $msg->get_str;
    }
    return undef;
}

## Client -> server methods

sub _rid {
    my ($sftp, $rfh) = @_;
    my $rid = $rfh->_rid;
    unless (defined $rid) {
	$sftp->_set_error(SFTP_ERR_REMOTE_ACCESING_CLOSED_FILE,
			  "Couldn't access a file that has been previosly closed");
    }
    $rid
}

sub _rfid {
    $_[1]->_check_is_file;
    &_rid;
}

sub _rdid {
    $_[1]->_check_is_dir;
    &_rid;
}

sub _queue_rid_request {
    my ($sftp, $code, $fh, $attrs) = @_;
    my $rid = $sftp->_rid($fh);
    return undef unless defined $rid;

    $sftp->_queue_new_msg($code, str => $rid,
			 (defined $attrs ? (attr => $attrs) : ()));
}

sub _queue_rfid_request {
    $_[2]->_check_is_file;
    &_queue_rid_request;
}

sub _queue_rdid_request {
    $_[2]->_check_is_dir;
    &_queue_rid_request;
}

sub _queue_str_request {
    my($sftp, $code, $str, $attrs) = @_;
    $sftp->_queue_new_msg($code, str => $str,
			 (defined $attrs ? (attr => $attrs) : ()));
}

sub _check_status_ok {
    my ($sftp, $eid, $error, $errstr) = @_;
    if (my $msg = $sftp->_get_msg_and_check(SSH2_FXP_STATUS, $eid,
					    $error, $errstr)) {
	
	my $status = $sftp->_set_status($msg->get_int32, $msg->get_str);
	return 1 if $status == SSH2_FX_OK;

	$sftp->_set_error($error, $errstr, $status);
    }
    return undef;
}

sub setcwd {

    @_ == 2 or croak 'Usage: $sftp->setcwd($path)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $cwd) = @_;
    if (defined $cwd) {
        $cwd = $sftp->realpath($cwd);
        return undef unless defined $cwd;
        $sftp->{cwd} = $cwd;
    }
    else {
        delete $sftp->{cwd};
        return $sftp->cwd;
    }
}

sub cwd {
    @_ == 1 or croak 'Usage: $sftp->cwd()';

    my $sftp = shift;
    return defined $sftp->{cwd} ? $sftp->{cwd} : $sftp->realpath('');
}

## SSH2_FXP_OPEN (3)
# returns handle on success, undef on failure
sub open {
    (@_ >= 2 and @_ <= 4)
	or croak 'Usage: $sftp->open($path [, $flags [, $attrs]])';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $path, $flags, $a) = @_;
    $path = $sftp->_rel2abs($path);
    $flags ||= 0;
    $a ||= Net::SFTP::Foreign::Attributes->new;
    my $id = $sftp->_queue_new_msg(SSH2_FXP_OPEN, str => $path,
				  int32 => $flags, attr => $a);

    my $rid = $sftp->_get_handle($id,
				SFTP_ERR_REMOTE_OPEN_FAILED,
				"Couldn't open remote file '$path'");

    if ($debug and $debug & 2) {
        _debug("new remote file '$path' open, rid:");
        _hexdump($rid);
    }

    defined $rid
	or return undef;

    my $fh = Net::SFTP::Foreign::FileHandle->_new_from_rid($sftp, $rid);
    $fh->_flag(append => 1)
	if ($flags & SSH2_FXF_APPEND);

    $fh;
}

## SSH2_FXP_OPENDIR (11)
sub opendir {
    (@_ >= 2 and @_ <= 3)
	or croak 'Usage: $sftp->opendir($path [, $attrs])';
    ${^TAINT} and &_catch_tainted_args;

    my $sftp = shift;
    my $path = shift;
    my $abspath = $sftp->_rel2abs($path);
    my $id = $sftp->_queue_str_request(SSH2_FXP_OPENDIR, $abspath, @_);

    my $rid = $sftp->_get_handle($id, SFTP_ERR_REMOTE_OPENDIR_FAILED,
				 "Couldn't open remote dir '$path'");

    if ($debug and $debug & 2) {
        _debug("new remote dir '$path' open, rid:");
        _hexdump($rid);
    }

    defined $rid
	or return undef;

    Net::SFTP::Foreign::DirHandle->_new_from_rid($sftp, $rid, 0)
}

## SSH2_FXP_READ (4)
# returns data on success undef on failure
sub sftpread {
    (@_ >= 3 and @_ <= 4)
	or croak 'Usage: $sftp->sftpread($fh, $offset [, $size])';

    my ($sftp, $rfh, $offset, $size) = @_;

    unless ($size) {
	return '' if defined $size;
	$size = COPY_SIZE;
    }

    my $rfid = $sftp->_rfid($rfh);
    defined $rfid or return undef;

    my $id = $sftp->_queue_new_msg(SSH2_FXP_READ, str=> $rfid,
				  int64 => $offset, int32 => $size);

    if (my $msg = $sftp->_get_msg_and_check(SSH2_FXP_DATA, $id,
					    SFTP_ERR_REMOTE_READ_FAILED,
					    "Couldn't read from remote file")) {
	return $msg->get_str;
    }
    return undef;
}

## SSH2_FXP_WRITE (6)
# returns true on success, undef on failure
sub sftpwrite {
    @_ == 4 or croak 'Usage: $sftp->sftpwrite($fh, $offset, $data)';

    my ($sftp, $rfh, $offset, $data) = @_;
    my $rfid = $sftp->_rfid($rfh);
    defined $rfid or return undef;

    my $id = $sftp->_queue_new_msg(SSH2_FXP_WRITE, str => $rfid,
				  int64 => $offset, str => $data);

    if ($sftp->_check_status_ok($id,
				SFTP_ERR_REMOTE_WRITE_FAILED,
				"Couldn't write to remote file")) {
	return 1;
    }
    return undef;
}

sub seek {
    (@_ >= 3 and @_ <= 4)
	or croak 'Usage: $sftp->seek($fh, $pos [, $whence])';

    my ($sftp, $rfh, $pos, $whence) = @_;
    $sftp->flush($rfh) or return undef;

    $whence ||= 0;

    if ($whence == 0) {
	return $rfh->_pos($pos)
    }
    elsif ($whence == 1) {
	return $rfh->_inc_pos($pos)
    }
    elsif ($whence == 2) {
	if (my $a = $sftp->fstat($rfh)) {
	    return $rfh->_pos($pos + $a->size);
	}
	else {
	    return undef;
	}
    }
    else {
	croak "invalid whence argument";
    }
}

sub tell {
    @_ == 2 or croak 'Usage: $sftp->tell($fh)';

    my ($sftp, $rfh) = @_;
    return $rfh->_pos + length ${$rfh->_bout};
}

sub eof {
    @_ == 2 or croak 'Usage: $sftp->eof($fh)';

    my ($sftp, $rfh) = @_;
    $sftp->_fill_read_cache($rfh, 1);
    return length(${$rfh->_bin}) == 0
}

sub _write {
    my ($sftp, $rfh, $off, $cb) = @_;

    $sftp->_set_error;
    $sftp->_set_status;

    my $rfid = $sftp->_rfid($rfh);
    defined $rfid or return undef;

    my $qsize = $sftp->{_queue_size};

    my @msgid;
    my @written;
    my $written = 0;
    my $end;

    my $selin = '';
    vec($selin, fileno($sftp->{ssh_in}), 1) = 1;

    while (!$end or @msgid) {
	while (!$end and @msgid < $qsize) {
	    my $data = $cb->();
	    if (defined $data and length $data) {
		my $id = $sftp->_queue_new_msg(SSH2_FXP_WRITE, str => $rfid,
					      int64 => $off + $written, str => $data);
		push @written, $written;
		$written += length $data;
		push @msgid, $id;
	    }
	    else {
		$end = 1;
	    }
	}

	my $eid = shift @msgid;
	my $last = shift @written;
	unless ($sftp->_check_status_ok($eid,
					SFTP_ERR_REMOTE_WRITE_FAILED,
					"Couldn't write to remote file")) {

	    # discard responses to queued requests:
	    $sftp->_get_msg for @msgid;
	    return $last;
	}
    }

    return $written;
}

sub write {
    @_ == 3 or croak 'Usage: $sftp->write($fh, $data)';

    my ($sftp, $rfh) = @_;
    $sftp->flush($rfh, 'in') or return undef;

    my $datalen = length $_[2];

    my $bout = $rfh->_bout;
    $$bout .= $_[2];
    my $len = length $$bout;

    $sftp->flush($rfh, 'out')
	if ($len > COPY_SIZE or ($len and $sftp->{_autoflush} ));

    return $datalen;
}

sub flush {
    (@_ >= 2 and @_ <= 3)
	or croak 'Usage: $sftp->flush($fh [, $direction])';

    my ($sftp, $rfh, $dir) = @_;
    $dir ||= '';

    if ($dir ne 'out') { # flush in!
	${$rfh->_bin} = '';
    }

    if ($dir ne 'in') { # flush out!
	my $bout = $rfh->_bout;
	my $len = length $$bout;
	if ($len) {
	    my $start;
	    my $append = $rfh->_flag('append');
	    if ($append) {
		$start = 0;
	    }
	    else {
		$start = $rfh->_pos;
		${$rfh->_bin} = '';
	    }
	    my $off = 0;
	    my $written = $sftp->_write($rfh, $start,
					sub {
					    my $data = substr($$bout, $off, COPY_SIZE);
					    $off += length $data;
					    $data;
					} );
	    $rfh->_inc_pos($written)
		unless $append;

	    substr($$bout, 0, $written, '');
	    $written == $len or return undef;
	}
    }
    1;
}

sub _fill_read_cache {
    my ($sftp, $rfh, $len) = @_;

    $sftp->_set_error;
    $sftp->_set_status;

    $sftp->flush($rfh, 'out')
	or return undef;

    my $rfid = $sftp->_rfid($rfh);
    defined $rfid or return undef;

    my $bin = $rfh->_bin;

    if (defined $len) {
	return 1 if ($len < length $$bin);

	my $read_ahead = $sftp->{_read_ahead};
	$len = length($$bin) + $read_ahead
	    if $len - length($$bin) < $read_ahead;
    }

    my $pos = $rfh->_pos;

    my $qsize = $sftp->{_queue_size};
    my $bsize = $sftp->{_block_size};

    my @msgid;
    my $askoff = length $$bin;
    my $eof;

    while (!defined $len or length $$bin < $len) {
	while ((!defined $len or $askoff < $len) and @msgid < $qsize) {
	    my $id = $sftp->_queue_new_msg(SSH2_FXP_READ, str=> $rfid,
					  int64 => $pos + $askoff, int32 => $bsize);
	    push @msgid, $id;
	    $askoff += $bsize;
	}

	my $eid = shift @msgid;
	my $msg = $sftp->_get_msg_and_check(SSH2_FXP_DATA, $eid,
					    SFTP_ERR_REMOTE_READ_FAILED,
					    "Couldn't read from remote file")
	    or last;

	my $data = $msg->get_str;
	
	$$bin .= $data;
	if (length $data < $bsize) {
	    unless (defined $len) {
		$eof = $sftp->_queue_new_msg(SSH2_FXP_READ, str=> $rfid,
					     int64 => $pos + length $$bin, int32 => 1);
	    }
	    last;
	}

    }

    $sftp->_get_msg for @msgid;

    if ($eof) {
	$sftp->_get_msg_and_check(SSH2_FXP_DATA, $eof,
				  SFTP_ERR_REMOTE_BLOCK_TOO_SMALL,
				  "received block was too small")
    }

    if ($sftp->{_status} == SSH2_FX_EOF and length $$bin) {
	$sftp->_set_status();
	$sftp->_set_error();
    }

    return $sftp->{_error} ? undef : length $$bin;
}

sub read {
    @_ == 3 or croak 'Usage: $sftp->read($fh, $len)';

    my ($sftp, $rfh, $len) = @_;
    if ($sftp->_fill_read_cache($rfh, $len)) {
	my $bin = $rfh->_bin;
	my $data = substr($$bin, 0, $len, '');
	$rfh->_inc_pos(length $data);
	return $data;
    }
    return undef;
}

sub _readline {
    my ($sftp, $rfh, $sep) = @_;

    $sep = "\n" if @_ < 3;

    my $sl = length $sep;

    my $bin = $rfh->_bin;
    my $last = 0;

    while(1) {
	my $ix = index $$bin, $sep, $last + 1 - $sl ;
	if ($ix >= 0) {
	    $ix += $sl;
	    $rfh->_inc_pos($ix);
	    return substr($$bin, 0, $ix, '');
	}

	$last = length $$bin;
	$sftp->_fill_read_cache($rfh, length($$bin) + 1);

	unless (length $$bin > $last) {
	    $sftp->{_error}
		and return undef;

	    my $line = $$bin;
	    $rfh->_inc_pos(length $line);
	    $$bin = '';
	    return $line;
	}
    }
}

sub readline {
    (@_ >= 2 and @_ <= 3)
	or croak 'Usage: $sftp->readline($fh [, $sep])';

    my ($sftp, $rfh, $sep) = @_;
    if (!defined $sep or length $sep == 0) {
	$sftp->_fill_read_cache($rfh);
	$sftp->{_error}
	    and return undef;
	my $bin = $rfh->_bin;
	my $line = $$bin;
	$rfh->_inc_pos(length $line);
	$$bin = '';
	return $line;
    }
    if (wantarray) {
	my @lines;
	while (defined (my $line = $sftp->_readline($rfh, $sep))) {
	    push @lines, $line;
	}
	return @lines;
    }
    return $sftp->_readline($rfh, $sep);
}

sub getc {
    @_ == 2 or croak 'Usage: $sftp->getc($fh)';

    my ($sftp, $rfh) = @_;

    $sftp->_fill_read_cache($rfh, 1);
    my $bin = $rfh->_bin;
    if (length $bin) {
	$rfh->_inc_pos(1);
	return substr $$bin, 0, 1, '';
    }
    return undef;
}

sub _gen_stat_method {
    my ($code, $error, $errstr) = @_;
    return sub {
	@_ == 2 or croak 'Usage: $sftp->stat|lstat($path)';
        ${^TAINT} and &_catch_tainted_args;

	my ($sftp, $path) = @_;
        $path = $sftp->_rel2abs($path);
	my $id = $sftp->_queue_str_request($code, $path);
	if (my $msg = $sftp->_get_msg_and_check(SSH2_FXP_ATTRS, $id,
						$error, $errstr)) {
	    return $msg->get_attributes;
	}
	return undef;
    };
}

## SSH2_FXP_LSTAT (7), SSH2_FXP_FSTAT (8), SSH2_FXP_STAT (17)
# these all return a Net::SFTP::Foreign::Attributes object on success, undef on failure

*lstat = _gen_stat_method(SSH2_FXP_LSTAT,
			  SFTP_ERR_REMOTE_LSTAT_FAILED,
			  "Couldn't stat remote file (lstat)");

*stat = _gen_stat_method(SSH2_FXP_STAT,
			 SFTP_ERR_REMOTE_FSTAT_FAILED,
			 "Couldn't stat remote file (stat)");

sub fstat {
    @_ == 2 or croak 'Usage: $sftp->fstat($path)';
    ${^TAINT} and &_catch_tainted_args;

    my $sftp = shift;
    my $id = $sftp->_queue_rfid_request(SSH2_FXP_FSTAT, @_);
    defined $id or return undef;
    if (my $msg = $sftp->_get_msg_and_check(SSH2_FXP_ATTRS, $id,
					    SFTP_ERR_REMOTE_STAT_FAILED,
					    "Couldn't stat remote file (fstat)")) {
	return $msg->get_attributes;
    }
    return undef;
}

## SSH2_FXP_RMDIR (15), SSH2_FXP_REMOVE (13)
# these return true on success, undef on failure

sub _gen_remove_method {
    my($code, $error, $errstr) = @_;
    return sub {
	@_ == 2 or croak 'Usage: $sftp->remove|rmdir($path)';
        ${^TAINT} and &_catch_tainted_args;

        my ($sftp, $path) = @_;
        $path = $sftp->_rel2abs($path);
        my $id = $sftp->_queue_str_request($code, $path);
        return $sftp->_check_status_ok($id, $error, $errstr);
    };
}

*remove = _gen_remove_method(SSH2_FXP_REMOVE,
			     SFTP_ERR_REMOTE_REMOVE_FAILED,
			     "Couldn't delete remote file");

*rmdir = _gen_remove_method(SSH2_FXP_RMDIR,
			    SFTP_ERR_REMOTE_RMDIR_FAILED,
			    "Couldn't remove remote directory");


## SSH2_FXP_MKDIR (14), SSH2_FXP_SETSTAT (9)
# these return true on success, undef on failure

sub mkdir {
    (@_ >= 2 and @_ <= 3)
        or croak 'Usage: $sftp->mkdir($path [, $attrs])';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $path, $attrs) = @_;
    $path = $sftp->_rel2abs($path);
    $attrs = _empty_attributes unless defined $attrs;
    my $id = $sftp->_queue_str_request(SSH2_FXP_MKDIR, $path, $attrs);
    return $sftp->_check_status_ok($id,
                                   SFTP_ERR_REMOTE_MKDIR_FAILED,
                                   "Couldn't create remote directory");
}

sub setstat {
    @_ == 3 or croak 'Usage: $sftp->setstat($str, $attrs)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $path, $attrs) = @_;
    $path = $sftp->_rel2abs($path);
    my $id = $sftp->_queue_str_request(SSH2_FXP_SETSTAT, $path, $attrs);
    return $sftp->_check_status_ok($id,
                                   SFTP_ERR_REMOTE_SETSTAT_FAILED,
                                   "Couldn't setstat remote file (setstat)'");
}

## SSH2_FXP_CLOSE (4), SSH2_FXP_FSETSTAT (10)
# these return true on success, undef on failure

sub fsetstat {
    @_ == 3 or croak 'Usage: $sftp->fsetstat($fh, $attrs)';
    ${^TAINT} and &_catch_tainted_args;

    my $sftp = shift;
    my $id = $sftp->_queue_rid_request(SSH2_FXP_FSETSTAT, @_);
    defined $id or return undef;

    return $sftp->_check_status_ok($id,
                                   SFTP_ERR_REMOTE_FSETSTAT_FAILED,
                                   "Couldn't setstat remote file (fsetstat)");
}

sub _close {
    @_ == 2 or croak 'Usage: $sftp->close($fh, $attrs)';

    my $sftp = shift;
    my $id = $sftp->_queue_rid_request(SSH2_FXP_CLOSE, @_);
    defined $id or return undef;

    my $ok = $sftp->_check_status_ok($id,
                                     SFTP_ERR_REMOTE_CLOSE_FAILED,
                                     "Couldn't close remote file");

    if ($debug and $debug & 2) {
        _debug("closing file handle, return: $ok, rid:");
        _hexdump($sftp->_rid($_[0]));
    }

    return $ok;
}

sub close {
    @_ == 2 or croak 'Usage: $sftp->close($fh)';

    my ($sftp, $rfh) = @_;
    $rfh->_check_is_file;
    $sftp->flush($rfh)
	or return undef;

    if ($sftp->_close($rfh)) {
	$rfh->_close;
	return 1
    }
    undef
}

sub closedir {
    @_ == 2 or croak 'Usage: $sftp->closedir($dh)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $rdh) = @_;
    $rdh->_check_is_dir;

    if ($sftp->_close($rdh)) {
	$rdh->_close;
	return 1;
    }
    undef
}

sub readdir {
    @_ == 2 or croak 'Usage: $sftp->readdir($dh)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $rdh) = @_;

    my $rdid = $sftp->_rdid($rdh);
    defined $rdid or return undef;

    my $cache = $rdh->_cache;

    while (!@$cache or wantarray) {
	my $id = $sftp->_queue_str_request(SSH2_FXP_READDIR, $rdid);
	if (my $msg = $sftp->_get_msg_and_check(SSH2_FXP_NAME, $id,
						SFTP_ERR_REMOTE_READDIR_FAILED,
						"Couldn't read remote directory" )) {
	    my $count = $msg->get_int32 or last;

	    for (1..$count) {
		push @$cache, { filename => $msg->get_str,
				longname => $msg->get_str,
				a => $msg->get_attributes };
	    }
	}
	else {
	    $sftp->_set_error if $sftp->status == SSH2_FX_EOF;
	    last;
	}
    }

    if (wantarray) {
	my $old = $cache;
	$cache = [];
	return @$old;
    }
    shift @$cache;
}

sub _readdir {
    my ($sftp, $rdh);
    if (wantarray) {
	my $line = $sftp->readdir($rdh);
	if (defined $line) {
	    return $line->{filename};
	}
    }
    else {
	return map { $_->{filename} } $sftp->readdir($rdh);
    }
}

sub _gen_getpath_method {
    my ($code, $error, $name) = @_;
    return sub {
	@_ == 2 or croak 'Usage: $sftp->some_method($path)';
        ${^TAINT} and &_catch_tainted_args;

	my ($sftp, $path) = @_;
	$path = $sftp->_rel2abs($path);
	my $id = $sftp->_queue_str_request($code, $path);

	if (my $msg = $sftp->_get_msg_and_check(SSH2_FXP_NAME, $id,
						$error,
						"Couldn't get $name for remote '$path'")) {
	    $msg->get_int32 > 0
		and return $msg->get_str;

	    $sftp->_set_error($error,
			      "Couldn't get $name for remote '$path', no names on reply")
	}
	return undef;
    };
}

## SSH2_FXP_REALPATH (16)
## SSH2_FXP_READLINK (19)
# return path on success, undef on failure
*realpath = _gen_getpath_method(SSH2_FXP_REALPATH,
				SFTP_ERR_REMOTE_REALPATH_FAILED,
				"realpath");
*readlink = _gen_getpath_method(SSH2_FXP_READLINK,
				SFTP_ERR_REMOTE_READLINK_FAILED,
				"link target");

## SSH2_FXP_RENAME (18)
# true on success, undef on failure
sub rename {
    @_ == 3 or croak 'Usage: $sftp->rename($old, $new)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $old, $new) = @_;
    $old = $sftp->_rel2abs($old);
    $new = $sftp->_rel2abs($new);
    my $id = $sftp->_queue_new_msg(SSH2_FXP_RENAME,
				  str => $old,
				  str => $new);

    return $sftp->_check_status_ok($id, SFTP_ERR_REMOTE_RENAME_FAILED,
				   "Couldn't rename remote file '$old' to '$new'");
}

## SSH2_FXP_SYMLINK (20)
# true on success, undef on failure
sub symlink {
    @_ == 3 or croak 'Usage: $sftp->symlink($sl, $target)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $sl, $target) = @_;
    $sl = $sftp->_rel2abs($sl);
    my $id = $sftp->_queue_new_msg(SSH2_FXP_SYMLINK,
				  str => $target,
				  str => $sl);

    return $sftp->_check_status_ok($id, SFTP_ERR_REMOTE_SYMLINK_FAILED,
				   "Couldn't create symlink '$sl' pointing to '$target'");
}

sub _gen_save_status_method {
    my $method = shift;
    sub {
	my $sftp = shift;
	my $oerror = $sftp->{_error};
	my $ostatus = $sftp->{_status};
	my $ret = $sftp->$method(@_);
	if ($oerror) {
	    $sftp->{_error} = $oerror;
	    $sftp->{_status} = $ostatus;
	}
	$ret;
    }
}

*_close_save_status = _gen_save_status_method('close');
*_closedir_save_status = _gen_save_status_method('closedir');


## High-level client -> server methods.

sub abort {
    my $sftp = shift;
    $sftp->_set_error(SFTP_ERR_ABORTED, ($@ ? $_[0] : "Aborted"));
}

# returns true on success, undef on failure
sub get {
    @_ >= 3 or croak 'Usage: $sftp->get($remote, $local, %opts)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $remote, $local, %opts) = @_;
    $remote = $sftp->_rel2abs($remote);

    $sftp->_set_status;
    $sftp->_set_error;

    my $cb = delete $opts{callback};
    my $umask = delete $opts{umask};
    my $perm = delete $opts{perm};
    my $copy_perm = delete $opts{copy_perm} || delete $opts{copy_perms};
    my $copy_time = delete $opts{copy_time};
    my $overwrite = delete $opts{overwrite};
    my $block_size = delete $opts{block_size} || $sftp->{_block_size};
    my $queue_size = delete $opts{queue_size} || $sftp->{_queue_size};
    my $dont_save = delete $opts{dont_save};

    my $oldumask = umask;

    %opts and croak "invalid option(s) '".CORE::join("', '", keys %opts)."'";

    croak "'perm' and 'umask' options can not be used simultaneously"
	if (defined $perm and defined $umask);

    croak "'perm' and 'copy_perm' options can not be used simultaneously"
	if (defined $perm and defined $copy_perm);

    my $numask;

    if (defined $perm) {
	$numask = $perm;
    }
    else {
	$umask = $oldumask unless defined $umask;
	$numask = 0777 & ~$umask;
    }

    $overwrite = 1 unless defined $overwrite;
    $copy_perm = 1 unless (defined $perm or defined $copy_perm);
    $copy_time = 1 unless defined $copy_time;

    my $a = $sftp->stat($remote)
	or return undef;
    my $size = $a->size;

    my $rfh = $sftp->open($remote, SSH2_FXF_READ);
    defined $rfh or return undef;

    my $rfid = $sftp->_rfid($rfh);
    defined $rfid or return undef;

    my $fh;
    my @msgid;

    unless ($dont_save) {
        if (!$overwrite and -e $local) {
            $sftp->_set_error(SFTP_ERR_LOCAL_ALREADY_EXISTS,
                              "local file $local already exists");
            return undef
        }
	
        if ($copy_perm) {
            my $aperm = $a->perm;
            $perm = 0666 unless defined $perm;
            $a->perm =~ /^(\d+)$/ or die "perm is not numeric";
            $perm = int $1;
        }

        $perm = (0666 & $numask) unless defined $perm;

        my $lumask = ~$perm & 0666;
        umask $lumask;

        unlink $local;

        unless (CORE::open $fh, ">", $local) {
            umask $oldumask;
            $sftp->_set_error(SFTP_ERR_LOCAL_OPEN_FAILED,
                              "Can't open $local", $!);
            return undef;
        }
        umask $oldumask;

        binmode $fh;

        # if ((0666 & ~$lumask) != $perm) { ...
        # this optimization removed because it doesn't work for already
        # existant files :-(

        # unless (chmod $perm & $numask, $fh) {
        # fchmod is not available everywhere!

        unless (chmod $perm & $numask, $local) {
            $sftp->_set_error(SFTP_ERR_LOCAL_CHMOD_FAILED,
                              "Can't chmod $local", $!);
            return undef
        }
    }

    my @askoff;
    my $askoff = 0;
    my $loff = 0;
    my $rfno = fileno($sftp->{ssh_in});
    my $selin = '';
    my $n = 0;

    vec ($selin, $rfno, 1) = 1;

    while (1) {
	# request a new block if queue is not full
	while (!@msgid or ($size > $askoff and @msgid < $queue_size and $n != 1)) {

	    my $id = $sftp->_queue_new_msg(SSH2_FXP_READ, str=> $rfid,
					   int64 => $askoff, int32 => $block_size);
		
	    push @msgid, $id;
	    push @askoff, $askoff;
	    $askoff += $block_size;
            $n++;
	}

        # printf STDERR "queue_size: %d, askoff: %d, bs: %d \r", scalar(@msgid), $askoff, $block_size;

	my $eid = shift @msgid;
	my $roff = shift @askoff;

	my $msg = $sftp->_get_msg_and_check(SSH2_FXP_DATA, $eid,
					    SFTP_ERR_REMOTE_READ_FAILED,
					    "Couldn't read from remote file");

	unless ($msg) {
	    if ($sftp->{_status} == SSH2_FX_EOF) {
		$sftp->_set_error();
		next if $roff != $loff;
	    }
	    last;
	}

	my $data = $msg->get_str;
	my $len = length $data;
	
	if ($roff != $loff or !$len) {
	    $sftp->_set_error(SFTP_ERR_REMOTE_BLOCK_TOO_SMALL);
	    last;
	}

	$loff += $len;
        if ($len < $block_size) {
          $block_size = $len < 2048 ? 2048 : $len;
          $askoff = $loff;
        }

	if (defined $cb) {
	    $size = $loff if $loff > $size;
	    $cb->($sftp, $data, $roff, $size);

            last if $sftp->error;
	}

        unless ($dont_save) {
            unless (print $fh $data) {
                $sftp->_set_error(SFTP_ERR_LOCAL_WRITE_FAILED,
                                  "unable to write data to local file $local", $!);
                last;
            }
        }
    }

    $sftp->_get_msg for (@msgid);

    return undef if $sftp->error;

    unless ($dont_save) {
        unless (CORE::close $fh) {
            $sftp->_set_error(SFTP_ERR_LOCAL_WRITE_FAILED,
                              "unable to write data to local file $local", $!);
            return undef;
        }

        # we can be running on taint mode, so some checks are
        # performed to untaint data from the remote side.

        if ($copy_time) {
            if ($a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
                $a->atime =~ /^(\d+)$/ or die "Bad atime from remote file $remote";
                my $atime = int $1;
                $a->mtime =~ /^(\d+)$/ or die "Bad mtime from remote file $remote";
                my $mtime = int $1;

                unless (utime $atime, $mtime, $local) {
                    $sftp->_set_error(SFTP_ERR_LOCAL_UTIME_FAILED,
                                      "Can't utime $local", $!);
                    return undef;
                }
            }
        }
    }

    return !$sftp->{_error}
}

# return file contents on success, undef on failure
sub get_content {
    @_ == 2 or croak 'Usage: $sftp->get_content($remote)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $name) = @_;
    $name = $sftp->_rel2abs($name);
    my @data;

    my $rfh = $sftp->open($name)
	or return undef;

    return scalar $sftp->readline($rfh, undef);
}

sub put {
    @_ >= 3 or croak 'Usage: $sftp->put($local, $remote, %opts)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $local, $remote, %opts) = @_;
    $remote = $sftp->_rel2abs($remote);

    $sftp->_set_error;
    $sftp->_set_status;

    my $cb = delete $opts{callback};

    my $umask = delete $opts{umask};
    my $perm = delete $opts{perm};
    my $copy_perm = delete $opts{copy_perm} || delete $opts{copy_perms};
    my $copy_time = delete $opts{copy_time};
    my $overwrite = delete $opts{overwrite};
    my $block_size = delete $opts{block_size} || COPY_SIZE;
    my $queue_size = delete $opts{queue_size} || 10;

    %opts and croak "invalid option(s) '".CORE::join("', '", keys %opts)."'";

    croak "'perm' and 'umask' options can not be used simultaneously"
	if (defined $perm and defined $umask);

    croak "'perm' and 'copy_perm' options can not be used simultaneously"
	if (defined $perm and defined $copy_perm);

    my $numask;

    if (defined $perm) {
	$numask = $perm;
    }
    else {
	$umask = umask unless defined $umask;
	$numask = 0777 & ~$umask;
    }
    $overwrite = 1 unless defined $overwrite;
    $copy_perm = 1 unless (defined $perm or defined $copy_perm);
    $copy_time = 1 unless defined $copy_time;

    my $fh;
    unless (CORE::open $fh, '<', $local) {
	$sftp->_set_error(SFTP_ERR_LOCAL_OPEN_FAILED,
			 "Unable to open local file '$local'", $!);
	return undef;
    }

    binmode $fh;

    my ($lmode, $lsize, $latime, $lmtime);
    unless ((undef, undef, $lmode, undef, undef,
	     undef, undef, $lsize, $latime, $lmtime) = CORE::stat $fh) {
	$sftp->_set_error(SFTP_ERR_LOCAL_STAT_FAILED,
			 "Couldn't stat local file '$local'", $!);
	return undef;
    }

    $perm = $lmode & $numask if $copy_perm;

    my $attrs = Net::SFTP::Foreign::Attributes->new;
    $attrs->set_perm($perm) if defined $perm;

    my $rfh = $sftp->open($remote,
			     SSH2_FXF_WRITE | SSH2_FXF_CREAT |
			     ($overwrite ? SSH2_FXF_TRUNC : SSH2_FXF_EXCL),
			     $attrs)
	or return undef;

    # open does not set the attributes for existant files so we do it again:
    if (defined $perm) {
        $sftp->fsetstat($rfh, $attrs)
            or return undef;
    }

    my $rfid = $sftp->_rfid($rfh);
    defined $rfid or return undef;

    my @msgid;
    my @readoff;
    my $readoff = 0;
    my $rfno = fileno($sftp->{ssh_in});

 OK: for (1) {
	my $eof;
	while (1) {
	    if (!$eof and @msgid < $queue_size) {
		my $len = CORE::read $fh, my ($data), $block_size;
		unless (defined $len) {
		    $sftp->_set_error(SFTP_ERR_LOCAL_READ_ERROR,
				     "Couldn't read from local file '$local'", $!);
		    last OK;
		}
		
		my $nextoff = $readoff + $len;

		if (defined $cb) {
		    $lsize = $nextoff if $nextoff > $lsize;
		    $cb->($sftp, $data, $readoff, $lsize);

                    last OK if $sftp->error;

		    $len = length $data;
		    $nextoff = $readoff + $len;
		}

		if ($len) {
		    my $id = $sftp->_queue_new_msg(SSH2_FXP_WRITE, str => $rfid,
                                                   int64 => $readoff, str => $data);
		
		    push @msgid, $id;
		    push @readoff, $readoff;
		    $readoff = $nextoff;
		}
		else {
		    $eof = 1;
		}
	    }

	    last if ($eof and !@msgid);

	    next unless  ($eof
			  or @msgid >= $queue_size
			  or $sftp->_do_io(0));

	    my $id = shift @msgid;
	    my $loff = shift @readoff;
	    unless ($sftp->_check_status_ok($id,
					    SFTP_ERR_REMOTE_WRITE_FAILED,
					    "Couldn't write to remote file")) {
		last OK;
	    }
	}
    };

    CORE::close $fh;

    $sftp->_get_msg for (@msgid);

    $sftp->_close_save_status($rfh);

    return undef if $sftp->error;

    if ($copy_time) {
	$attrs = Net::SFTP::Foreign::Attributes->new;
	$attrs->set_amtime($latime, $lmtime);
	$sftp->setstat($remote, $attrs);
    }
	
    return $sftp->{_error} == 0;
}

sub ls {
    @_ >= 1 or croak 'Usage: $sftp->ls($remote_dir, %opts)';
    ${^TAINT} and &_catch_tainted_args;

    my $sftp = shift;
    my %opts = @_ & 1 ? (dir => @_) : @_;

    my $dir = delete $opts{dir};
    my $ordered = delete $opts{ordered};
    my $follow_links = delete $opts{follow_links};
    my $atomic_readdir = delete $opts{atomic_readdir};
    my $names_only = delete $opts{names_only};
    my $realpath = delete $opts{realpath};
    my $wanted = delete $opts{_wanted} ||
	_gen_wanted(delete $opts{wanted},
		    delete $opts{no_wanted});

    %opts and croak "invalid option(s) '".CORE::join("', '", keys %opts)."'";

    $dir = '.' unless defined $dir;
    $dir = $sftp->_rel2abs($dir);

    my $rdh = $sftp->opendir($dir);
    return unless defined $rdh;

    my $rdid = $sftp->_rdid($rdh);
    defined $rdid or return undef;

    my @dir;
    OK: while (1) {
        my $id = $sftp->_queue_str_request(SSH2_FXP_READDIR, $rdid);

	if (my $msg = $sftp->_get_msg_and_check(SSH2_FXP_NAME, $id,
						SFTP_ERR_REMOTE_READDIR_FAILED,
						"Couldn't read directory '$dir'" )) {

	    my $count = $msg->get_int32 or last;

	    for (1..$count) {
                my $fn = $msg->get_str;
                my $ln = $msg->get_str;
                my $a = $msg->get_attributes;

		my $entry =  { filename => $fn,
			       longname => $ln,
			       a => $a };

		if ($follow_links and S_ISLNK($a->perm)) {

		    if ($a = $sftp->stat($sftp->join($dir, $fn))) {
			$entry->{a} = $a;
		    }
		    else {
			$sftp->_set_error;
			$sftp->_set_status;
		    }
		}


                if ($realpath) {
                    my $rp = $sftp->realpath($fn);
                    if (defined $rp) {
                        $fn = $entry->{realpath} = $rp;
                    }
                    else {
			$sftp->_set_error;
			$sftp->_set_status;
                    }
                }

		if ($atomic_readdir or !$wanted or $wanted->($sftp, $entry)) {
		    push @dir, ($names_only ? $fn : $entry);
		}
            }
	}
	else {
	    $sftp->_set_error if $sftp->{_status} == SSH2_FX_EOF;
	    last;
	}
    }

    $sftp->_closedir_save_status($rdh) if $rdh;

    unless ($sftp->{_error}) {
	if ($atomic_readdir and $wanted) {
	    @dir = grep { $wanted->($sftp, $_) } @dir;
	}

        if ($ordered) {
            if ($names_only) {
                @dir = sort @dir;
            }
            else {
                _sort_entries \@dir;
            }
        }
	
	return \@dir;
    }

    return undef;
}

sub join {
    my $sftp = shift;

    my $a = '.';
    for my $b (@_) {
	if ($b ne '') {
	    if ($b =~ m|^/|) {
		$a = $b;
	    }
	    else {
		$a .= '/' . $b;
	    }
	}
    }
    $a =~ s|/\./|/|g;
    $a =~ s|^\./||;
    $a =~ s|//+|/|g;
    $a;
}

sub glob {
    @_ >= 2 or croak 'Usage: $sftp->glob($pattern, %opts)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $glob, %opts) = @_;
    return () if $glob eq '';

    my $on_error = delete $opts{on_error};
    my $follow_links = delete $opts{follow_links};
    my $ignore_case = delete $opts{ignore_case};
    my $names_only = delete $opts{names_only};
    my $realpath = delete $opts{realpath};
    my $ordered = delete $opts{ordered};
    my $wanted = _gen_wanted( delete $opts{wanted},
			      delete $opts{no_wanted});
    my $strict_leading_dot =
	exists $opts{strict_leading_dot} ? delete $opts{strict_leading_dot} : 1;

    %opts and croak "invalid option(s) '".CORE::join("', '", keys %opts)."'";

    my $wantarray = wantarray;

    my @parts = ($glob =~ m{\G/*([^/]+)}g);
    push @parts, '.' unless @parts;

    my $top = ($glob =~ m|^/|) ? '/' : '.';
    my @res = ( {filename => $top} );
    my $res = 0;

    while (@parts and @res) {
	my @parents = @res;
	@res = ();
	my $part = shift @parts;
	my ($re, $has_wildcards) = _glob_to_regex($part, $strict_leading_dot, $ignore_case);

	for my $parent (@parents) {
	    my $pfn = $parent->{filename};
            if ($has_wildcards) {
                $sftp->ls( $pfn,
                           ordered => $ordered,
                           _wanted => sub {
                               my $e = $_[1];
                               if ($e->{filename} =~ $re) {
                                   my $fn = $e->{filename} = $sftp->join($pfn, $e->{filename});
                                   if ( (@parts or $follow_links)
                                        and S_ISLNK($e->{a}->perm) ) {
                                       if (my $a = $sftp->stat($fn)) {
                                           $e->{a} = $a;
                                       }
                                       else {
                                           $sftp->_call_on_error($on_error, $e);
                                           return undef;
                                       }
                                   }
                                   if (@parts) {
                                       push @res, $e if S_ISDIR($e->{a}->perm)
                                   }
                                   elsif (!$wanted or $wanted->($sftp, $e)) {
                                       if ($wantarray) {
                                           if ($realpath) {
                                               my $rp = $e->{realpath} = $sftp->realpath($e->{filename});
                                               unless (defined $rp) {
                                                   $sftp->_call_on_error($on_error, $e);
                                                   return undef;
                                               }
                                           }
                                           push @res, ($names_only
                                                       ? ($realpath ? $e->{realpath} : $e->{filename} )
                                                       : $e);
                                       }
                                       $res++;
                                   }
                               }
                               return undef
                           } )
                    or $sftp->_call_on_error($on_error, $parent);
            }
            else {
                my $fn = $sftp->join($pfn, $part);
                my $method = ((@parts or $follow_links) ? 'stat' : 'lstat');
                if (my $a = $sftp->$method($fn)) {
                    my $e = { filename => $fn, a => $a };
                    if (@parts) {
                        push @res, $e if S_ISDIR($a->{perm})
                    }
                    elsif (!$wanted or $wanted->($sftp, $e)) {
                        if ($wantarray) {
                            if ($realpath) {
                                my $rp = $fn = $e->{realpath} = $sftp->realpath($fn);
                                unless (defined $rp) {
                                    $sftp->_call_on_error($on_error, $e);
                                    next;
                                }
                            }
                            push @res, ($names_only ? $fn : $e)
                        }
                        $res++;
                    }
                }
            }
        }
    }
    return wantarray ? @res : $res;
}

sub rremove {
    @_ >= 2 or croak 'Usage: $sftp->rremove($dirs, %opts)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $dirs, %opts) = @_;

    my $on_error = delete $opts{on_error};
    my $wanted = _gen_wanted( delete $opts{wanted},
			      delete $opts{no_wanted});

    %opts and croak "invalid option(s) '".CORE::join("', '", keys %opts)."'";

    my $count = 0;

    my @dirs;
    $sftp->find( $dirs,
		 on_error => $on_error,
		 atomic_readdir => 1,
		 wanted => sub {
		     my $e = $_[1];
		     my $fn = $e->{filename};
		     if (S_ISDIR($e->{a}->perm)) {
			 push @dirs, $e;
		     }
		     else {
			 if (!$wanted or $wanted->($sftp, $e)) {
			     if ($sftp->remove($fn)) {
				 $count++;
			     }
			     else {
				 $sftp->_call_on_error($on_error, $e);
			     }
			 }
		     }
		 } );

    _sort_entries(\@dirs);

    while (@dirs) {
	my $e = pop @dirs;
	if (!$wanted or $wanted->($sftp, $e)) {
	    if ($sftp->rmdir($e->{filename})) {
		$count++;
	    }
	    else {
		$sftp->_call_on_error($on_error, $e);
	    }
	}
    }

    return $count;
}

sub rget {
    @_ >= 3 or croak 'Usage: $sftp->rget($remote, $local, %opts)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $remote, $local, %opts) = @_;

    # my $cb = delete $opts{callback};
    my $umask = delete $opts{umask};
    my $copy_perm = delete $opts{copy_perm} || delete $opts{copy_perms};
    my $copy_time = delete $opts{copy_time};
    my $block_size = delete $opts{block_size};
    my $queue_size = delete $opts{queue_size};
    my $overwrite = delete $opts{overwrite};
    my $newer_only = delete $opts{newer_only};
    my $on_error = delete $opts{on_error};
    my $ignore_links = delete $opts{ignore_links};

    # my $relative_links = delete $opts{relative_links};

    my $wanted = _gen_wanted( delete $opts{wanted},
			      delete $opts{no_wanted} );

    %opts and croak "invalid option(s) '".CORE::join("', '", keys %opts)."'";

    $remote = $sftp->join($remote, './');
    my $qremote = quotemeta $remote;
    my $reremote = qr/^$qremote(.*)$/i;

    $umask = umask $umask if (defined $umask);

    $copy_perm = 1 unless defined $copy_perm;
    $copy_time = 1 unless defined $copy_time;

    require File::Spec;

    my $count = 0;
    $sftp->find( [$remote],
		 descend => sub {
		     my $e = $_[1];
		     # print "descend: $e->{filename}\n";
		     if (!$wanted or $wanted->($sftp, $e)) {
			 my $fn = $e->{filename};
			 if ($fn =~ $reremote) {
			     my $lpath = File::Spec->catdir($local, $1);
                             ($lpath) = $lpath =~ /(.*)/ if ${^TAINT};
			     if (-d $lpath) {
				 $sftp->_set_error(SFTP_ERR_LOCAL_ALREADY_EXISTS,
						   "directory '$lpath' already exists");
				 $sftp->_call_on_error($on_error, $e);
				 return 1;
			     }
			     else {
				 if (CORE::mkdir $lpath, ($copy_perm ? $e->{a}->perm & 0777 : 0777)) {
				     $count++;
				     return 1;
				 }
				 else {
				     $sftp->_set_error(SFTP_ERR_LOCAL_MKDIR_FAILED,
						       "mkdir '$lpath' failed", $!);
				 }
			     }
			 }
			 else {
			     $sftp->_set_error(SFTP_ERR_REMOTE_BAD_PATH,
					       "bad remote path '$fn'");
			 }
			 $sftp->_call_on_error($on_error, $e);
		     }
		     return undef;
		 },
		 wanted => sub {
		     my $e = $_[1];
		     # print "file fn:$e->{filename}, a:$e->{a}\n";
		     unless (S_ISDIR($e->{a}->perm)) {
			 if (!$wanted or $wanted->($sftp, $e)) {
			     my $fn = $e->{filename};
			     if ($fn =~ $reremote) {
				 my $lpath = File::Spec->catfile($local, $1);
                                 ($lpath) = $lpath =~ /(.*)/ if ${^TAINT};
				 if (S_ISLNK($e->{a}->perm) and !$ignore_links) {
				     if (my $link = $sftp->readlink($fn)) {
                                         {
                                             local $@;
                                             local $SIG{__DIE__};
                                             if (eval {CORE::symlink $link, $lpath}) {
                                                 $count++;
                                                 return undef;
                                             }
                                         }
					 $sftp->_set_error(SFTP_ERR_LOCAL_SYMLINK_FAILED,
							   "creation of symlink '$lpath' failed", $!);
				     }
				 }
				 elsif (S_ISREG($e->{a}->perm)) {
				     if ($newer_only and -e $lpath
					 and (CORE::stat _)[9] >= $e->{a}->mtime) {
					 $sftp->_set_error(SFTP_ERR_LOCAL_ALREADY_EXISTS,
							   "newer local file '$lpath' already exists");
				     }
				     else {
					 if ($sftp->get($fn, $lpath,
							overwrite => $overwrite,
							queue_size => $queue_size,
							block_size => $block_size,
							copy_perm => $copy_perm,
							copy_time => $copy_time)) {
					     $count++;
					     return undef;
					 }
				     }
				 }
				 else {
				     $sftp->_set_error(SFTP_ERR_REMOTE_BAD_OBJECT,
						       ( $ignore_links
							 ? "remote file '$fn' is not regular file or directory"
							 : "remote file '$fn' is not regular file, directory or link"));
				 }
			     }
			     else {
				 $sftp->_set_error(SFTP_ERR_REMOTE_BAD_PATH,
						   "bad remote path '$fn'");
			     }
			     $sftp->_call_on_error($on_error, $e);
			 }
		     }
		     return undef;
		 } );

    umask $umask if defined $umask;

    return $count;
}

sub rput {
    @_ >= 3 or croak 'Usage: $sftp->rput($local, $remote, %opts)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $local, $remote, %opts) = @_;

    # my $cb = delete $opts{callback};
    my $umask = delete $opts{umask};
    my $copy_perm = delete $opts{copy_perm} || delete $opts{copy_perms};
    my $copy_time = delete $opts{copy_time};
    my $block_size = delete $opts{block_size};
    my $queue_size = delete $opts{queue_size};
    my $overwrite = delete $opts{overwrite};
    my $newer_only = delete $opts{newer_only};
    my $on_error = delete $opts{on_error};
    my $ignore_links = delete $opts{ignore_links};

    # my $relative_links = delete $opts{relative_links};

    my $wanted = _gen_wanted( delete $opts{wanted},
			      delete $opts{no_wanted} );

    %opts and croak "invalid option(s) '".CORE::join("', '", keys %opts)."'";

    require Net::SFTP::Foreign::Local;
    my $lfs = Net::SFTP::Foreign::Local->new;

    $local = $lfs->join($local, './');
    my $qlocal = quotemeta $local;
    my $relocal = qr/^$qlocal(.*)$/i;

    $copy_perm = 1 unless defined $copy_perm;
    $copy_time = 1 unless defined $copy_time;

    $umask = umask unless defined $umask;
    my $mask = ~$umask;

    if ($on_error) {
	my $on_error1 = $on_error;
	$on_error = sub {
	    my $lfs = shift;
	    $sftp->_copy_error($lfs);
	    $sftp->_call_on_error($on_error1, @_);
	}
    }

    my $count = 0;
    $lfs->find( [$local],
		descend => sub {
		    my $e = $_[1];
		    # print "descend: $e->{filename}\n";
		    if (!$wanted or $wanted->($lfs, $e)) {
			my $fn = $e->{filename};
			if ($fn =~ $relocal) {
			    my $rpath = $sftp->join($remote, $1);
			    if ($sftp->test_d($rpath)) {
				$lfs->_set_error(SFTP_ERR_REMOTE_ALREADY_EXISTS,
						 "remote directory '$rpath' already exists");
				$lfs->_call_on_error($on_error, $e);
				return 1;
			    }
			    else {
				my $a = Net::SFTP::Foreign::Attributes->new;
				$a->set_perm(($copy_perm ? $e->{a}->perm & 0777 : 0777) & $mask);
				if ($sftp->mkdir($rpath, $a)) {
				    $count++;
				    return 1;
				}
				else {
				    $lfs->_copy_error($sftp);
				}
			    }
			}
			else {
			    $lfs->_set_error(SFTP_ERR_LOCAL_BAD_PATH,
					      "bad local path '$fn'");
			}
			$lfs->_call_on_error($on_error, $e);
		    }
		    return undef;
		},
		wanted => sub {
		    my $e = $_[1];
		    # print "file fn:$e->{filename}, a:$e->{a}\n";
		    unless (S_ISDIR($e->{a}->perm)) {
			if (!$wanted or $wanted->($lfs, $e)) {
			    my $fn = $e->{filename};
			    if ($fn =~ $relocal) {
				my $rpath = $sftp->join($remote, $1);
				if (S_ISLNK($e->{a}->perm) and !$ignore_links) {
				    if (my $link = $lfs->readlink($fn)) {
					if ($sftp->symlink($link, $rpath)) {
					    $count++;
					    return undef;
					}
					$lfs->_copy_error($sftp);
				    }
				}
				elsif (S_ISREG($e->{a}->perm)) {
				    my $ra;
				    if ( $newer_only and
					 $ra = $sftp->stat($rpath) and
					 $ra->mtime >= $e->{a}->mtime) {
					$lfs->_set_error(SFTP_ERR_REMOTE_ALREADY_EXISTS,
							 "newer remote file '$rpath' already exists");
				    }
				    else {
					if ($sftp->put($fn, $rpath,
						       overwrite => $overwrite,
						       queue_size => $queue_size,
						       block_size => $block_size,
						       perm => ($copy_perm ? $e->{a}->perm : 0777) & $mask,
						       copy_time => $copy_time)) {
					    $count++;
					    return undef;
					}
					$lfs->_copy_error($sftp);
				    }
				}
				else {
				    $lfs->_set_error(SFTP_ERR_LOCAL_BAD_OBJECT,
						      ( $ignore_links
							? "local file '$fn' is not regular file or directory"
							: "local file '$fn' is not regular file, directory or link"));
				}
			    }
			    else {
				$lfs->_set_error(SFTP_ERR_LOCAL_BAD_PATH,
						  "bad local path '$fn'");
			    }
			    $lfs->_call_on_error($on_error, $e);
			}
		    }
		    return undef;
		} );

    return $count;
}

package Net::SFTP::Foreign::Handle;

use Tie::Handle;
our @ISA = qw(Tie::Handle);

my $gen_accessor = sub {
    my $ix = shift;
    sub {
	my $st = *{shift()}->{ARRAY};
	if (@_) {
	    $st->[$ix] = shift;
	}
	else {
	    $st->[$ix]
	}
    }
};

my $gen_proxy_method = sub {
    my $method = shift;
    sub {
	my $self = $_[0];
	$self->_check
	    or return undef;

	my $sftp = $self->_sftp;
	if (wantarray) {
	    my @ret = $sftp->$method(@_);
	    $sftp->_set_errno unless @ret;
	    return @ret;
	}
	else {
	    my $ret = $sftp->$method(@_);
	    $sftp->_set_errno unless defined $ret;
	    return $ret;
	}
    }
};

my $gen_not_supported = sub {
    sub {
	$! = Errno::ENOTSUP();
	undef
    }
};

sub TIEHANDLE { return shift }

# sub UNTIE {}

sub _new_from_rid {
    my $class = shift;
    my $sftp = shift;
    my $rid = shift;
    my $flags = shift || 0;

    my $self = Symbol::gensym;
    bless $self, $class;
    tie *$self, $self;
    *{$self}->{ARRAY} = [ $sftp, $rid, 0, $flags, @_];

    $self;
}

sub _close {
    my $self = shift;
    @{*$self->{ARRAY}} = ();
}

sub _check {
    return 1 if defined(*{shift()}->{ARRAY}[0]);
    $! = Errno::EBADF;
    undef;
}

sub FILENO {
    my $self = shift;
    $self->_check
	or return undef;

    my $hrid = unpack 'H*' => $self->_rid;
    "-1:sftp(0x$hrid)"
}

sub _sftp { *{shift()}->{ARRAY}[0] }
sub _rid { *{shift()}->{ARRAY}[1] }

* _pos = $gen_accessor->(2);

sub _inc_pos {
    my ($self, $inc) = @_;
    *{shift()}->{ARRAY}[2] += $inc;
}


my %flag_bit = (append => 0x1);

sub _flag {
    my $st = *{shift()}->{ARRAY};
    my $fn = shift;
    my $flag = $flag_bit{$fn};
    Carp::croak("unknown flag $fn") unless defined $flag;
    if (@_) {
	if (shift) {
	    $st->[3] |= $flag;
	}
	else {
	    $st->[3] &= ~$flag;
	}
    }
    $st->[3] & $flag ? 1 : 0
}

sub _check_is_file {
    Carp::croak("expecting remote file handler, got directory handler");
}
sub _check_is_dir {
    Carp::croak("expecting remote directory handler, got file handler");
}

my $autoloaded;
sub AUTOLOAD {
    my $self = shift;
    our $AUTOLOAD;
    if ($autoloaded) {
	my $class = ref $self || $self;
	Carp::croak qq|Can't locate object method "$AUTOLOAD" via package "$class|;
    }
    else {
	$autoloaded = 1;
	require IO::File;
	require IO::Dir;
	my ($method) = $AUTOLOAD =~ /^.*::(.*)$/;
	$self->$method(@_);
    }
}

package Net::SFTP::Foreign::FileHandle;
our @ISA = qw(Net::SFTP::Foreign::Handle IO::File);

sub _new_from_rid {
    my $class = shift;
    my $sftp = shift;
    my $rid = shift;
    my $flags = shift;

    my $self = $class->SUPER::_new_from_rid($sftp, $rid, $flags, '', '');
}

sub _check_is_file {}

sub _bin { \(*{shift()}->{ARRAY}[4]) }
sub _bout { \(*{shift()}->{ARRAY}[5]) }

sub WRITE {
    my ($self, undef, $length, $offset) = @_;
    $self->_check
	or return undef;

    $offset = 0 unless defined $offset;
    $offset = length $_[1] + $offset if $offset < 0;
    $length = length $_[1] unless defined $length;

    my $sftp = $self->_sftp;

    my $ret = $sftp->write($self, substr($_[1], $offset, $length));
    $sftp->_set_errno unless defined $ret;
    $ret;
}

sub READ {
    my ($self, undef, $len, $offset) = @_;
    $self->_check
	or return undef;

    $_[1] = '' unless defined $_[1];
    $offset ||= 0;
    if ($offset > length $_[1]) {
	$_[1] .= "\0" x ($offset - length $_[1])
    }

    if ($len == 0) {
	substr($_[1], $offset) = '';
	return 0;
    }

    my $sftp = $self->_sftp;
    $sftp->_fill_read_cache($self, $len);

    my $bin = $self->_bin;
    if (length $$bin) {
	my $data = substr($$bin, 0, $len, '');
	$self->_inc_pos($len);
	substr($_[1], $offset) = $data;
	return length $data;
    }
    return 0 if $sftp->{_status} == $sftp->SSH2_FX_EOF;
    $sftp->_set_errno;
    undef;
}

*GETC = $gen_proxy_method->('getc');
*EOF = $gen_proxy_method->('eof');
*TELL = $gen_proxy_method->('tell');
*SEEK = $gen_proxy_method->('seek');
*CLOSE = $gen_proxy_method->('close');

my $readline = $gen_proxy_method->('readline');
sub READLINE { $readline->($_[0], $/) }

sub OPEN {
    shift->CLOSE;
    undef;
}

sub DESTROY {
    my $self = shift;
    my $sftp = $self->_sftp;

    $debug and $debug & 4 and Net::SFTP::Foreign::_debug("$self->DESTROY called (sftp: ".($sftp||'').")");

    if ($self->_check and $sftp) {
	$sftp->_close_save_status($self)
    }
}

package Net::SFTP::Foreign::DirHandle;
use Tie::Handle;
our @ISA = qw(Net::SFTP::Foreign::Handle IO::Dir);


sub _new_from_rid {
    my $class = shift;
    my $sftp = shift;
    my $rid = shift;
    my $flags = shift;

    my $self = $class->SUPER::_new_from_rid($sftp, $rid, $flags, []);
}

sub _check_is_dir {}

sub _cache { *{shift()}->{ARRAY}[4] }

*CLOSEDIR = $gen_proxy_method->('closedir');
*READDIR = $gen_proxy_method->('_readdir');

sub OPENDIR {
    shift->CLOSEDIR;
    undef;
}

*REWINDDIR = $gen_not_supported->();
*TELLDIR = $gen_not_supported->();
*SEEKDIR = $gen_not_supported->();

sub DESTROY {
    my $self = shift;
    my $sftp = $self->_sftp;

    $debug and $debug & 4 and Net::SFTP::Foreign::_debug("$self->DESTROY called (sftp: ".($sftp||'').")");

    if ($self->_check and $sftp) {
	$sftp->_closedir_save_status($self)
    }
}

#sub _forbidden {
#    my $method = shift;
#    no strict;
#    *{$method} = sub { croak qq(forbidden method "$method" called) }
#}

1;
__END__

=head1 NAME

Net::SFTP::Foreign - Secure File Transfer Protocol client

=head1 SYNOPSIS

    use Net::SFTP::Foreign;
    my $sftp = Net::SFTP::Foreign->new($host);
    $sftp->get("foo", "bar");
    $sftp->put("bar", "baz");

=head1 DESCRIPTION

SFTP stands for SSH File Transfer Protocol and is a method of
transferring files between machines over a secure, encrypted
connection (as opposed to regular FTP, which functions over an
insecure connection). The security in SFTP comes through its
integration with SSH, which provides an encrypted transport layer over
which the SFTP commands are executed.

Net::SFTP::Foreign is a Perl client for the SFTP version 3. It
provides a subset of the commands listed in the SSH File Transfer
Protocol IETF draft, which can be found at
L<http://www.openssh.org/txt/draft-ietf-secsh-filexfer-02.txt> (also
included on this package distribution, on the C<rfc> directory).

Net::SFTP::Foreign uses any compatible C<ssh> command installed on
your system (for instance, OpenSSH C<ssh>) to establish the secure
connection to the remote server.

Formerly, Net::SFTP::Foreign was a hacked version of Net::SFTP, but
from version 0.90 it has been rewritten almost completely from scratch
and a new much improved API introduced (an adaptor module,
L<Net::SFTP::Foreign::Compat>, is also provided for backward
compatibility).


=head2 Net::SFTP::Foreign Vs. Net::SFTP

Why should I prefer Net::SFTP::Foreign over L<Net::SFTP>?

Well, both modules have their pros and cons:

Net::SFTP::Foreign does not requiere a bunch of additional modules and
external libraries to work, just the OpenBSD SSH client (or any other
client compatible enough).

I trust OpenSSH SSH client more than L<Net::SSH::Perl>, there are lots
of paranoid people ensuring that OpenSSH doesn't have security
holes!!!

If you have an SSH infrastructure already deployed, by using the same
binary SSH client, Net::SFTP::Foreign ensures a seamless integration
within your environment (configuration files, keys, etc.).

Net::SFTP::Foreign is much faster transferring files, specially over
networks with high (relative) latency.

Net::SFTP::Foreign provides several high level methods not available
from Net::SFTP as for instance C<find>, C<rget>, C<rput>.

On the other hand, using the external command means an additional
proccess being launched and running, depending on your OS this could
eat more resources than the in process pure perl implementation
provided by Net::SSH::Perl.

Net::SFTP::Foreign supports version 2 of the SSH protocol only.


=head2 USAGE

Most of the methods available from this package return undef on
failure and a true value or the requested data on
success. C<$sftp-E<gt>error> can be used to explicitly check for
errors after every method call.

Don't forget to read also the FAQ and BUGS sections at the end of this
document!

=over 4

=item Net::SFTP::Foreign->new($host, %args)

=item Net::SFTP::Foreign->new(%args)

Opens a new SFTP connection with a remote host C<$host>, and returns a
Net::SFTP::Foreign object representing that open connection.

C<%args> can contain:

=over 4

=item host =E<gt> $hostname

remote host name

=item user =E<gt> $username

username to log in to the remote server. This should be your SSH
login, and can be empty, in which case the username is drawn from the
user executing the process.

=item port =E<gt> $portnumber

port number where the remote SSH server is listening

=item more =E<gt> [@more_ssh_args]

additional args passed to C<ssh> command.

For debugging purposes you can run C<ssh> in verbose mode passing it
the C<-v> option:

  my $sftp = Net::SFTP::Foreign->new($host, more => '-v');


=item ssh_cmd =E<gt> $sshcmd

name of the external SSH client. By default C<ssh> is used.

=item open2_cmd =E<gt> [@cmd]

=item open2_cmd =E<gt> $cmd;

allows to completely redefine how C<ssh> is called. Its arguments are
passed to L<IPC::Open2::open2> to open a pipe to the remote
server.

=item autoflush =E<gt> $bool

by default, and for performance reasons, write operations are cached,
and only when the write buffer becomes big enough is the data written to
the remote file. Setting this flag makes the write operations inmediate.

=item timeout =E<gt> $seconds

when this parameter is set, the connection is dropped if no data
arrives on the SSH socket for the given time while waiting for some
command to complete.

When the timeout expires, the current method is aborted and
the SFTP connection becomes invalid.

=item transport =E<gt> $fh

=item transport =E<gt> [$in_fh, $out_fh]

=item transport =E<gt> [$in_fh, $out_fh, $pid]

This option allows to use an already open pipe or socket as the
transport for the SFTP protocol.

It can be (ab)used to make this module work with password
authentication or with keys requiring a passphrase.

On some systems, when using a pipe as the transport, closing it, does
not cause the process at the other side to exit. The additional
C<$pid> argument can be used to instruct this module to kill that
process if it doesn't exit by itself.

=item password => $password

=item passphrase => $passphrase

Use L<Expect> to handle password authentication or keys requiring a
passphrase. This is an experimental feature!

=item expect_log_user => $bool

Activate password/passphrase authentication interaction loging (see
C<Expect::log_user> method documentation).

=back

An explicit check for errors should be included always after the
constructor call:

  my $sftp = Net::SFTP::Foreign->new(...);
  $sftp->error and die "SSH connection failed: " . $sftp->error;

=item $sftp-E<gt>error

Returns the error code from the last executed command. The value
returned is similar to C<$!>, when used as a string it yields the
corresponding error string.

See L<Net::SFTP::Foreign::Constants> for a list of possible error
codes and how to import them on your scripts.

=item $sftp-E<gt>status

Returns the code from the last SSH2_FXP_STATUS response. It is also a
dualvar that yields the status string when used as a string.

Usually C<$sftp-E<gt>error> should be checked first to see if there was
any error and then C<$sftp-E<gt>status> to find out its low level cause.

=item $sftp-E<gt>cwd

Returns the remote current working directory.

When a relative remote path is passed to any of the methods on this
package, this directory is used to compose the absolute path.

=item $sftp-E<gt>setcwd($dir)

Changes the remote current working directory. The remote directory
should exist, otherwise the call fails.

Returns the new remote current working directory or undef on failure.

=item $sftp-E<gt>get($remote, $local, %options)

Copies remote file C<$remote> to local $local. By default file
attributes are also copied (permissions, atime and mtime).

The method accepts several options (not all combinations are
possible):

=over 4

=item copy_time =E<gt> $bool

determines if access and modification time attributes have to be
copied from remote file. Default is to copy them.

=item copy_perm =E<gt> $bool

determines if permision attributes have to be copied from remote
file. Default is to copy them after applying the local process umask.

=item umask =E<gt> $umask

allows to select the umask to apply when setting the permissions of
the copied file. Default is to use the umask for the current process.

=item perm =E<gt> $perm

sets the permision mask of the file to be $perm, umask and remote
permissions are ignored.

=item block_size =E<gt> $bytes

size of the blocks the file is being splittered on for
transfer. Incrementing this value can improve performance but some
servers limit its size.

=item callback =E<gt> $callback

C<$callback> is a reference to a subroutine that will be called after
every iteration of the download process.

The callback function will receive as arguments: the current
Net::SFTP::Foreign object; the data read from the remote file; the
offset from the beginning of the file in bytes; and the total size of
the file in bytes.

This mechanism can be used to provide status messages, download
progress meters, etc.:

    sub callback {
        my($sftp, $data, $offset, $size) = @_;
        print "Read $offset / $size bytes\r";
    }

=back

The C<abort> method can be called from inside the callback to abort
the transfer:

    sub callback {
        my($sftp, $data, $offset, $size) = @_;
        if (want_to_abort_transfer()) {
            $sftp->abort("You wanted to abort the transfer");
        }
    }


=item $sftp-E<gt>get_content($remote)

Returns the content of the remote file.

=item $sftp-E<gt>put($local, $remote, %opts)

Uploads a file C<$local> from the local host to the remote host, and
saves it as C<$remote>. By default file attributes are also copied.

This method accepts several options:

=over 4

=item copy_time =E<gt> $bool

determines if access and modification time attributes have to be
copied from remote file. Default is to copy them.

=item copy_perm =E<gt> $bool

determines if permision attributes have to be copied from remote
file. Default is to copy them after applying the local process umask.

=item umask =E<gt> $umask

allows to select the umask to apply when setting the permissions of
the copied file. Default is to use the umask for the current process.

=item perm =E<gt> $perm

sets the permision mask of the file to be $perm, umask and local
permissions are ignored.

=item block_size =E<gt> $bytes

size of the blocks the file is being splittered on for
transfer. Incrementing this value can improve performance but some
servers limit its size and if this limit is overpassed the command
will fail.

=item callback =E<gt> $callback

C<$callback> is a reference to a subrutine that will be called after
every iteration of the upload process.

The callback function will receive as arguments: the current
Net::SFTP::Foreign object; the data that is going to be written to the
remote file; the offset from the beginning of the file in bytes; and
the total size of the file in bytes.

This mechanism can be used to provide status messages, download
progress meters, etc.

The C<abort> method can be called from inside the callback to abort
the transfer.

=back

=item $sftp-E<gt>abort()

=item $sftp-E<gt>abort($msg)

This method, when called from inside a callback sub, causes the
current transfer to be aborted

The error state is set to SFTP_ERR_ABORTED and the optional $msg
argument is used as its textual value.

=item $sftp-E<gt>ls($remote, %opts)

Fetches a directory listing of the remote B<directory> C<$remote>. If
C<$remote> is not given, the remote current working directory is
listed.

Returns a reference to a list of entries. Every entry is a reference
to a hash with three keys: C<filename>, the name of the entry;
C<longname>, an entry in a "long" listing like C<ls -l>; and C<a>, a
L<Net::SFTP::Foreign::Attributes> object containing file atime, mtime,
permissions and size.

    my $ls = $sftp->ls('/home/foo')
        or die "unable to retrieve directory: ".$sftp->error;

    print "$_->{filename}\n" for (@$ls);

The options accepted by this method are:

=over 4

=item wanted =E<gt> qr/.../

Only elements which filename match the regular expresion are included
on the listing.

=item wanted =E<gt> sub {...}

Only elements for which the callback returns a true value are included
on the listing. The callback is called with two arguments: the
C<$sftp> object and the current entry (a hash reference as described
before). For instance:

  use Fcntl ':mode';

  my $files = $sftp->ls ( '/home/hommer',
			  wanted => sub {
			      my $entry = $_[1];
			      S_ISREG($entry->{a}->perm)
			  } )
	or die "ls failed: ".$sftp->error;


=item no_wanted =E<gt> qr/.../

=item no_wanted =E<gt> sub {...}

those options have the oposite result to their C<wanted> counterparts:

  my $no_hidden = $sftp->ls( '/home/homer',
			     no_wanted => qr/^\./ )
	or die "ls failed";


When both C<no_wanted> and C<wanted> rules are used, the C<no_wanted>
rule is applied first and then the C<wanted> one (order is important
if the callbacks have side effects).

=item ordered =E<gt> 1

the list of entries is ordered by filename.

=item follow_links =E<gt> 1

by default, the attributes on the listing correspond to a C<lstat>
operation, setting this option causes the method to perform C<stat>
requests instead. C<lstat> attributes will stil appear for links
pointing to non existant places.

=item atomic_readdir =E<gt> 1

reading a directory is not an atomic SFTP operation and the protocol
draft does not define what happens if C<readdir> requests and write
operations (for instance C<remove> or C<open>) affecting the same
directory are intermixed.

This flag ensures that no callback call (C<wanted>, C<no_wanted>) is
performed in the middle of reading a directory and has to be set if
any of the callbacks can modify the file system.

=item realpath =E<gt> 1

for every file object, performs a realpath operation and populates de
C<realpath> entry.

=item names_only =E<gt> 1

makes the method return a simple array containing the file names from
the remote directory only. For instance, these two sentences are
equivalent:

  my $ls1 = $sftp->ls('.', names_only => 1);

  my $ls2 = map { $_->{filename} } $sftp->ls('.');

=back

=item $sftp-E<gt>find($path, %opts)

=item $sftp-E<gt>find(\@paths, %opts)

Does a recursive search over the given directory C<$path> (or
directories C<@path>) and returns a list of the entries found or the
total number of them on scalar context.

Every entry is a reference to a hash with two keys: C<filename>, the
full path of the entry; and C<a>, a L<Net::SFTP::Foreign::Attributes>
object containing file atime, mtime, permissions and size.

This method tries to recover and continue under error conditions.

The options accepted:

=over 4

=item on_error =E<gt> sub { ... }

the callback is called when some error is detected, two arguments are
passed: the C<$sftp> object and the entry that was being processed
when the error happened. For instance:

  my @find = $sftp->find( '/',
			  on_error => sub {
			      my ($sftp, $e) = @_;
		 	      print STDERR "error processing $e->{filename}: "
				   . $sftp->error;
			  } );

=item realpath =E<gt> 1

calls method C<realpath> for every entry, the result is stored under
the key C<realpath>. This option slows down the process as a new
remote query is performed for every entry, specially on networks with
high latency.

=item follow_links =E<gt> 1

By default symbolic links are not resolved and appear as that on the
final listing. This option causes then to be resolved and substituted
by the target file system object. Dangling links are ignored, though
they generate a call to the C<on_error> callback when stat'ing them
fails.

Following sym links can introduce loops on the search. Infinite loops
are detected and broken but files can still appear repeated on the
final listing under different names unless the option C<realpath> is
also actived.

=item ordered =E<gt> 1

By default, the file system is searched in an implementation dependant
order (actually optimized for low memory comsumption). If this option
is included, the file system is searched in a deep-first, sorted by
filename fashion.

=item wanted =E<gt> qr/.../

=item wanted =E<gt> sub { ... }

=item no_wanted =E<gt> qr/.../

=item no_wanted =E<gt> sub { ... }

These options have the same effect as on the C<ls> method, allowing to
filter out unwanted entries (note that filename keys contain B<full
paths> here).

The callbacks can also be used to perform some action instead of
creating the full listing of entries in memory (that could use huge
amounts of RAM for big file trees):

  $sftp->find($src_dir,
	      wanted => sub {
		  my $fn = $_[1]->{filename}
		  print "$fn\n" if $fn =~ /\.p[ml]$/;
		  return undef # so it is discarded
	      });

=item descend =E<gt> qr/.../

=item descend =E<gt> sub { ... }

=item no_descend =E<gt> qr/.../

=item no_descend =E<gt> sub { ... }

These options, similar to the C<wanted> ones, allow to prune the
search, discarding full subdirectories. For instance:

    use Fcntl ':mode';
    my @files = $sftp->find( '.',
			     no_descend => qr/\.svn$/,
			     wanted => sub {
				 S_ISREG($_[1]->{a}->perm)
			     } );


C<descend> and C<wanted> rules are unrelated. A directory discarded by
a C<wanted> rule will still be recursively searched unless it is also
discarded on a C<descend> rule and vice-versa.

=item atomic_readdir =E<gt> 1

see C<ls> method documentation.

=item names_only =E<gt> 1

makes the method return a list with the names of the files only (see C<ls>
method documentation).

equivalent:

  my $ls1 = $sftp->ls('.', names_only => 1);

=back

=item $sftp-E<gt>glob($pattern, %opts)

performs a remote glob and returns the list of matching entries in the
same format as C<find> method.

This method tries to recover and continue under error conditions.

The options accepted:

=over 4

=item ignore_case =E<gt> 1

by default the matching over the file system is carried out in a case
sensitive fashion, this flag changes it to be case insensitive.

=item strict_leading_dot =E<gt> 0

by default, a dot character at the begining of a file or directory
name is not matched by willcards (C<*> or C<?>). Setting this flags to
a false value changes the behaviour.

=item follow_links =E<gt> 1

=item ordered =E<gt> 1

=item names_only =E<gt> 1

=item realpath =E<gt> 1

=item on_error =E<gt> sub { ... }

=item wanted =E<gt> ...

=item no_wanted =E<gt> ...

these options perform as on the C<ls> method.

=back

=item $sftp-E<gt>rget($remote, $local, %opts)

Recursively copies the contents of remote directory C<$remote> to
local directory C<$local>. Returns the total number of elements
(files, dirs and symbolic links) successfully copied.

This method tries to recover and continue when some error happens.

The options accepted are:

=over 4

=item umask =E<gt> $umask

use umask C<$umask> to set permissions on the files and directories
created.

=item copy_perm =E<gt> $bool;

if set to a true value, file and directory permissions are copied to
the remote server (after applying the umask). On by default.

=item copy_time =E<gt> $bool;

if set to a true value, file atime and mtime are copied from the
remote server. By default it is on.

=item overwrite =E<gt> $bool

if set to a true value, when a local file with the same name
already exists it is overwritten. On by default.

=item newer_only =E<gt> $bool

if set to a true value, when a local file with the same name
already exists it is overwritten only if the remote file is newer.

=item ignore_links =E<gt> $bool

if set to a true value, symbolic links are not copied.

=item on_error =E<gt> sub { ... }

the passed sub is called when some error happens. It is called with two
arguments, the C<$sftp> object and the entry causing the error.

=item wanted =E<gt> ...

=item no_wanted =E<gt> ...

This option allows to select which files and directories have to be
copied. See also C<ls> method docs.

If a directory is discarded all of its contents are also discarded (as
it is not possible to copy child files without creating the directory
first!).

=item block_size =E<gt> $block_size

=item queue_size =E<gt> $queue_size

see docs for C<get> method.

=back

=item $sftp-E<gt>rput($local, $remote, %opts)

Recursively copies the contents of local directory C<$local> to
remote directory C<$remote>.

This method tries to recover and continue when some error happens.

Accepted options are:

=over 4

=item umask =E<gt> $umask

use umask C<$umask> to set permissions on the files and directories
created.

=item copy_perm =E<gt> $bool;

if set to a true value, file and directory permissions are copied
to the remote server (after applying the umask). On by default.

=item copy_time =E<gt> $bool;

if set to a true value, file atime and mtime are copied to the
remote server. On by default.

=item overwrite =E<gt> $bool

if set to a true value, when a remote file with the same name already
exists it is overwritten. On by default.

=item newer_only =E<gt> $bool

if set to a true value, when a remote file with the same name already exists it is
overwritten only if the local file is newer.

=item ignore_links =E<gt> $bool

if set to a true value, symbolic links are not copied

=item on_error =E<gt> sub { ... }

the passed sub is called when some error happens. It is called with two
arguments, the C<$sftp> object and the entry causing the error.

=item wanted =E<gt> ...

=item no_wanted =E<gt> ...

This option allows to select which files and directories have to be
copied. See also C<ls> method docs.

If a directory is discarded all of its contents are also discarded (as
it is not possible to copy child files without creating the directory
first!).

=item block_size =E<gt> $block_size

=item queue_size =E<gt> $queue_size

see docs C<put> method docs.

=back

=item $sftp-E<gt>rremove($dir, %opts)

=item $sftp-E<gt>rremove(\@dirs, %opts)

recursively remove directory $dir (or directories @dirs) and its
contents. Returns the number of elements successfully removed.

This method tries to recover and continue when some error happens.

The options accepted are:

=over 4

=item on_error =E<gt> sub { ... }

This callback is called when some error is occurs. The arguments
passed are the C<$sftp> object and the current entry (see C<ls> docs
for more information).

=item wanted =E<gt> ...

=item no_wanted =E<gt> ...

Allow to select which file system objects have to be deleted.

=back

=item $sftp-E<gt>join(@paths)

returns the given path fragments joined in one path (currently the
remote file system is expected to be Unix like).

=item $sftp-E<gt>open($path, $flags [, $attrs ])

Sends the C<SSH_FXP_OPEN> command to open a remote file C<$path>,
and returns an open handle on success. On failure returns
C<undef>.

The returned value is a tied handle that can be used to access the
remote file both with the methods available from this module and with
perl built-ins, for instance:

  # reading from the remote file
  my $fh1 = $sftp->open("/etc/passwd")
    or die $sftp->error;
  while (<$fh1>) { ... }

  # writting to the remote file
  my $fh2 = $sftp->open("/foo/bar", SSH2_FXF_WRITE|SSH2_FXF_CREAT)
    or die $sftp->error;
  print $fh2 "printing on the remote file\n";
  $sftp->write($fh2, "writting more");

C<$flags> should be a bitmask of open flags, whose values can
be obtained from L<Net::SFTP::Foreign::Constants>:

    use Net::SFTP::Foreign::Constants qw( :flags );

C<$attrs> should be a L<Net::SFTP::Foreign::Attributes> object,
specifying the initial attributes for the file C<$path>. If you're
opening the file for reading only, C<$attrs> can be left blank, in
which case it will be initialized to an empty set of attributes.

=item $sftp-E<gt>close($handle)

Closes the remote file handle C<$handle>.

Files are automatically closed on the handle C<DESTROY> method when
not done explicitelly.

Returns true on success and undef on failure.

=item $sftp-E<gt>read($handle, $length)

reads C<$length> bytes from an open file handle C<$handle>. On success
returns the data read from the remote file and undef on failure
(including EOF).

=item $sftp-E<gt>write($handle, $data)

writes C<$data> to the remote file C<$handle>. Returns the number of
bytes written or undef on failure.

=item $sftp-E<gt>readline($handle)

=item $sftp-E<gt>readline($handle, $sep)

in scalar context reads and returns the next line from the remote
file. In list context, it returns all the lines from the current
position to the end of the file.

By default "\n" is used as the separator between lines, but a
different one can be used passing it as the second method argument. If
the empty string is used, it returns all the data from the current
position to the end of the file as one line.

=item $sftp-E<gt>getc($handle)

returns the next character from the file.

=item $sftp-E<gt>seek($handle, $pos, $whence)

sets the current position for the remote file handle C<$handle>. If
C<$whence> is 0, the position is set relative to the beginning of the
file; if C<$whence> is 1, position is relative to current position and
if $<$whence> is 2, position is relative to the end of the file.

returns a trues value on success, undef on failure.

=item $sftp-E<gt>tell($fh)

returns the current position for the remote file handle C<$handle>.

=item $sftp-E<gt>eof($fh)

reports whether the remote file handler points at the end of the file.

=item $sftp-E<gt>flush($fh)

writes to the remote file any pending data and discards the read
cache.

=item $sftp-E<gt>sftpread($handle, $offset, $length)

low level method that sends a SSH2_FXP_READ request to read from an
open file handle C<$handle>, C<$length> bytes starting at C<$offset>.

Returns the data read on success and undef on failure.

Some servers (for instance OpenSSH SFTP server) limit the size of the
read requests and so the length of data returned can be smaller than
requested.

=item $sftp-E<gt>sftpwrite($handle, $offset, $data)

low level method that sends a C<SSH_FXP_WRITE> request to write to an
open file handle C<$handle>, starting at C<$offset>, and where the
data to be written is in C<$data>.

Returns true on success and undef on failure.

=item $sftp-E<gt>opendir($path)

Sends a C<SSH_FXP_OPENDIR> command to open the remote directory
C<$path>, and returns an open handle on success (unfortunatelly,
current versions of perl does not support directory operations via
tied handles, so it is not possible to use the returned handle as a
native one).

On failure returns C<undef>.

=item $sftp-E<gt>closedir($handle)

closes the remote directory handle C<$handle>.

Directory handles are closed from their C<DESTROY> method when not
done explicitly.

Return true on success, undef on failure.

=item $sftp-E<gt>readdir($handle)

returns the next entry from the remote directory C<$handle> (or all
the remaining entries when called in list context).

The return values are a hash with three keys: C<filename>, C<longname> and
C<a>. The C<a> value contains a C<Net::SFTP::Foreign::Attributes>
object describing the entry.

Returns undef on error or when no more entries exist on the directory.

=item $sftp-E<gt>stat($path)

performs a C<stat> on the remote file C<$path> and returns a
L<Net::SFTP::Foreign::Attributes> object with the result values.

Returns undef on failure.

=item $sftp-E<gt>fstat($handle)

is similar to the previous method but its argument has to be a handle
to an already open remote file instead of a file name.

=item $sftp-E<gt>lstat($path)

is similar to C<stat> method but stats a symbolic link instead of the
file the symbolic links points to.

=item $sftp-E<gt>setstat($path, $attrs)

sets file attributes on remote file C<$path>.

Returns true on success and undef on failure.

=item $sftp-E<gt>fsetstat($handle, $attrs)

is similar to setstat but its first argument has to be an open remote
file handle instead of a file name.

=item $sftp-E<gt>remove($path)

Sends a C<SSH_FXP_REMOVE> command to remove the remote file
C<$path>. Returns a true value on success and undef on failure.

=item $sftp-E<gt>mkdir($path)

=item $sftp-E<gt>mkdir($path, $attrs)

Sends a C<SSH_FXP_MKDIR> command to create a remote directory C<$path>
whose attributes are initialized to C<$attrs> (a
L<Net::SFTP::Foreign::Attributes> object) if given.

Returns a true value on success and undef on failure.

=item $sftp-E<gt>rmdir($path)

Sends a C<SSH_FXP_RMDIR> command to remove a remote directory
C<$path>. Returns a true value on success and undef on failure.

=item $sftp-E<gt>realpath($path)

Sends a C<SSH_FXP_REALPATH> command to canonicalise C<$path>
to an absolute path. This can be useful for turning paths
containing C<'..'> into absolute paths.

Returns the absolute path on success, C<undef> on failure.

=item $sftp-E<gt>rename($old, $new)

Sends a C<SSH_FXP_RENAME> command to rename C<$old> to C<$new>.
Returns a true value on success and undef on failure.

=item $sftp-E<gt>readlink($path)

Sends a C<SSH_FXP_READLINK> command to read the path where the
simbolic link is pointing.

Returns the target path on success and undef on failure.

=item $sftp-E<gt>symlink($sl, $target)

Sends a C<SSH_FXP_SYMLINK> command to create a new symbolic link
C<$sl> pointing to C<$target>.

C<$target> is stored as-is, without any path expansion taken place on
it. User C<realpath> to normalize it:

  $sftp->symlink("foo.lnk" => $sftp->realpath("../bar"))

=back

=head1 FAQ

=over 4

=item Closing the connection:

B<Q>: How do I close the connection to the remote server?

B<A>: let the C<$sftp> object go out of scope or just undefine it:

  undef $sftp;

=item Using Net::SFTP::Foreign from a cron script:

B<Q>: I wrote a script for performing sftp file transfers that works
beautifully from the command line. However when I try to run the same
script from cron it fails with a broken pipe error:

  open2: exec of ssh -l user some.location.com -s sftp
    failed at Net/SFTP/Foreign.pm line 67

B<A>: C<ssh> is not on your cron PATH.

The remedy is either to add the location of the C<ssh> application to
your cron PATH or to use the C<ssh_cmd> option of the C<new> method to
hardcode the location of C<ssh> inside your script, for instance:

  my $ssh = Net::SFTP::Foreign->new($host,
                                    ssh_cmd => '/usr/local/ssh/bin/ssh');

=item Login/password authentication:

B<Q>: I noticed that the examples/synopsis that is provided has no
mention of using a password to login. How is one, able to login to a
SFTP server that requires uid/passwd for login?

B<A>: You can't!... well, actually, now, you can!

Use the C<password> option when calling the constructor:

  my $sftp = Net::SFTP::Foreign->new('foo@host', password => $password);

It will use L<Expect> to log into the remote machine after the SSH
connection is stablished, though as the prompt used by SSH to ask for
the password can be customized, it is not gauranteed to work.

You can also handle the connection and login yourself with L<Expect>
or any other way, and then call the constructor with the C<transport>
option:

  use Expect;

  my $conn = Expect->new;
  $conn->raw_pty(1);
  $conn->log_user(0);

  $conn->spawn('/usr/bin/ssh', -l => $user, $host, -s => 'sftp')
      or die $errstr;

  $conn->expect($timeout, "Password:")
      or die "Password not requested as expected";
  $conn->send("$passwd\n");
  $conn->expect($timeout, "\n");

  my $sftp = Net::SFTP::Foreign->new(transport => $conn);
  die "unable to stablish SSH connection: ". $sftp->error
      if $sftp->error;

(full example code is available from the C<samples> directory in this
package)

Anyway, I highly discourage this practice. You better use public-key
authentication instead!

=item Using passphrase protected keys:

B<Q>: How can I use keys protected by a passphrase?

B<A>: You can't ... well, ok, see answer to previous question. The
constructor also supports a C<passphrase> option.

=item C<more> constructor option expects an array reference:

B<Q>: I'm trying to pass in the private key file using the -i option,
but it keep saying it couldn't find the key. What I'm doing wrong?

B<A>: The C<more> argument on the constructor expects a single option
or a reference to an array of options. It will not split an string
containing several options.

Arguments to SSH options have to be also passed as different entries
on the array:

  my $sftp = Net::SFTP::Foreign->new($host,
                                      more => [qw(-i /home/foo/.ssh/id_dsa)]);


=back

=head1 BUGS

These are the currently known bugs

=over 4

=item - Doesn't work on VMS:

The problem is related to L<IPC::Open2> not working on VMS. Patches
are welcome!

=item - Dirty cleanup:

On some operative systems, closing the pipes used to comunicate with
the slave SSH process does not terminate it and a work around has to
be applied. If you find that your scripts hung when the $sftp object
gets out of scope, try setting C<$Net::SFTP::Foreign::dirty_cleanup>
to a true value and also send me a report including the value of
C<$^O> on your machine and the OpenSSH version.

From version 0.90_18 upwards, a dirty cleanup is performed anyway when
the SSH process does not terminate by itself in 8 seconds or less.

=back

Support for Windows OSs is still experimental!

Support for taint mode is experimental!

Support for setcwd/cwd is experimental!

Support for password/passphrase handling via Expect is also
experimental. On Windows it only works under the cygwin version of
Perl.

To report bugs, please, send me and email or use
L<http://rt.cpan.org>.

=head1 SEE ALSO

Information about the constants used on this module is available from
L<Net::SFTP::Foreign::Constants>. Information about attribute objects
is available from L<Net::SFTP::Foreign::Attributes>.

General information about SSH and the OpenSSH implementation is
available from the OpenSSH web site at L<http://www.openssh.org/> and
from the L<sftp(1)> and L<sftp-server(8)> manual pages.

Other modules offering similar functionality are L<Net::SFTP> or
L<Net::SSH2>.

=head1 COPYRIGHT

Copyright (c) 2005-2008 Salvador FandiE<ntilde>o (sfandino@yahoo.com).

Copyright (c) 2001 Benjamin Trott, Copyright (c) 2003 David Rolsky.

_glob_to_regex method based on code (c) 2002 Richard Clamp.

All rights reserved.  This program is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the LICENSE file included
with this module.

=cut
