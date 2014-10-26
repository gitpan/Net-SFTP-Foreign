package Net::SFTP::Foreign::Backend::Unix;

our $VERSION = '0.02';

use strict;
use warnings;

use Carp;
our @CARP_NOT = qw(Net::SFTP::Foreign);

use Fcntl qw(O_NONBLOCK F_SETFL F_GETFL);
use IPC::Open2;
use Net::SFTP::Foreign::Helpers qw(_tcroak _ensure_list _debug _hexdump $debug);
use Net::SFTP::Foreign::Constants qw(SSH2_FX_BAD_MESSAGE
				     SFTP_ERR_REMOTE_BAD_MESSAGE);

sub _new { shift }

sub _defaults {
   ( default_queue_size => 32 )
}

sub _init_transport_streams {
    my ($self, $sftp) = @_;
    for my $dir (qw(ssh_in ssh_out)) {
	binmode $sftp->{$dir};
	my $flags = fcntl($sftp->{$dir}, F_GETFL, 0);
	fcntl($sftp->{$dir}, F_SETFL, $flags | O_NONBLOCK);
    }
}

sub _ipc_open2_bug_workaround {
    # in some cases, IPC::Open3::open2 returns from the child
    my $pid = shift;
    unless ($pid == $$) {
        require POSIX;
        POSIX::_exit(-1);
    }
}

sub _init_transport {
    my ($class, $sftp, $opts) = @_;

    my $transport = delete $opts->{transport};

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
	my (@open2_cmd, $pass, $passphrase, $expect_log_user);

        $pass = delete $opts->{passphrase};

        if (defined $pass) {
            $passphrase = 1;
        }
        else {
            $pass = delete $opts->{password};
	    defined $pass and $sftp->{_password_authentication} = 1;
        }

        $expect_log_user = delete $opts->{expect_log_user} || 0;

        my $open2_cmd = delete $opts->{open2_cmd};
        if (defined $open2_cmd) {
            @open2_cmd = _ensure_list($open2_cmd);
        }
        else {
            my $host = delete $opts->{host};
            defined $host or croak "sftp target host not defined";

            my $ssh_cmd = delete $opts->{ssh_cmd};
            $ssh_cmd = 'ssh' unless defined $ssh_cmd;
            @open2_cmd = ($ssh_cmd);

            my $ssh_cmd_interface = delete $opts->{ssh_cmd_interface};
            unless (defined $ssh_cmd_interface) {
                $ssh_cmd_interface = ( $ssh_cmd =~ /\bplink(?:\.exe)?$/i
                                       ? 'plink'
                                       : 'ssh');
            }

            my $port = delete $opts->{port};
            my $user = delete $opts->{user};
	    my $ssh1 = delete $opts->{ssh1};

            my $more = delete $opts->{more};
            carp "'more' argument looks like if it should be splited first"
                if (defined $more and !ref($more) and $more =~ /^-\w\s+\S/);

            if ($ssh_cmd_interface eq 'plink') {
                $pass and !$passphrase
                    and croak "Password authentication via Expect is not supported for the plink client";
                push @open2_cmd, -P => $port if defined $port;
            }
            elsif ($ssh_cmd_interface eq 'ssh') {
                push @open2_cmd, -p => $port if defined $port;
		if ($pass and !$passphrase) {
		    push @open2_cmd, (-o => 'NumberOfPasswordPrompts=1',
				      -o => 'PreferredAuthentications=keyboard-interactive,password');
		}
            }
            else {
                die "Unsupported ssh_cmd_interface '$ssh_cmd_interface'";
            }
            push @open2_cmd, -l => $user if defined $user;
            push @open2_cmd, _ensure_list($more) if defined $more;
            push @open2_cmd, $host;
	    push @open2_cmd, ($ssh1 ? "/usr/lib/sftp-server" : -s => 'sftp');
        }
	_debug "ssh cmd: @open2_cmd\n" if ($debug and $debug & 1);

	%$opts and return; # Net::SFTP::Foreign will find the
                           # unhandled options and croak

	        if (${^TAINT} and Scalar::Util::tainted($ENV{PATH})) {
            _tcroak('Insecure $ENV{PATH}')
        }

        my $this_pid = $$;

        if (defined $pass) {

            # user has requested to use a password or a passphrase for
            # authentication we use Expect to handle that

            eval { require IO::Pty };
            $@ and croak "password authentication is not available, IO::Pty and Expect are not installed";
            eval { require Expect };
            $@ and croak "password authentication is not available, Expect is not installed";

            local ($ENV{SSH_ASKPASS}, $ENV{SSH_AUTH_SOCK}) if $passphrase;

            my $name = $passphrase ? 'Passphrase' : 'Password';
            my $eto = $sftp->{_timeout} ? $sftp->{_timeout} * 4 : 120;

	    my $child;
	    my $expect;
	    if (eval $IPC::Open3::VERSION >= 1.0105) {
		# open2(..., '-') only works from this IPC::Open3 version upwards;
		my $pty = IO::Pty->new;
		$expect = Expect->init($pty);
		$expect->raw_pty(1);
		$expect->log_user($expect_log_user);

		$child = do {
		    local ($@, $SIG{__DIE__}, $SIG{__WARN__});
		    eval { open2($sftp->{ssh_in}, $sftp->{ssh_out}, '-') }
		};
		if (defined $child and !$child) {
		    $pty->make_slave_controlling_terminal;
		    do { exec @open2_cmd }; # work around suppress warning under mod_perl
		    exit -1;
		}
		_ipc_open2_bug_workaround $this_pid;
		# $pty->close_slave();
	    }
	    else {
		$expect = Expect->new;
		$expect->raw_pty(1);
		$expect->log_user($expect_log_user);
		$expect->spawn(@open2_cmd);
		$sftp->{ssh_in} = $sftp->{ssh_out} = $expect;
		$sftp->{_ssh_out_is_not_dupped} = 1;
		$child = $expect->pid;
	    }
            unless (defined $child) {
                $sftp->_conn_failed("Bad ssh command", $!);
                return;
            }
            $sftp->{pid} = $child;
            $sftp->{_expect} = $expect;

            unless($expect->expect($eto, ':', '?')) {
                $sftp->_conn_failed("$name not requested as expected", $expect->error);
                return;
            }
	    my $before = $expect->before;
	    if ($before =~ /^The authenticity of host /i or
		$before =~ /^Warning: the \w+ host key for /i) {
		$sftp->_conn_failed("the authenticity of the target host can not be established, connect from the command line first");
		return;
	    }
            $expect->send("$pass\n");
	    $sftp->{_password_sent} = 1;

            unless ($expect->expect($eto, "\n")) {
                $sftp->_conn_failed("$name interchange did not complete", $expect->error);
                return;
            }
	    $expect->close_slave();
        }
        else {
	    do {
                local ($@, $SIG{__DIE__}, $SIG{__WARN__});
		$sftp->{pid} = eval { open2($sftp->{ssh_in}, $sftp->{ssh_out}, @open2_cmd) };
	    };
            _ipc_open2_bug_workaround $this_pid;

            unless (defined $sftp->{pid}) {
                $sftp->_conn_failed("Bad ssh command", $!);
                return;
            }
        }
    }
    $class->_init_transport_streams($sftp);
}


sub _do_io {
    my ($self, $sftp, $timeout) = @_;

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

    my $len;
    while (1) {
        my $lbin = length $$bin;
	if (defined $len) {
            return 1 if $lbin >= $len;
	}
	elsif ($lbin >= 4) {
            $len = 4 + unpack N => $$bin;
            if ($len > 256 * 1024) {
                $sftp->_set_status(SSH2_FX_BAD_MESSAGE);
                $sftp->_set_error(SFTP_ERR_REMOTE_BAD_MESSAGE,
                                  "bad remote message received");
                return undef;
            }
            return 1 if $lbin >= $len;
        }

        my $rv1 = $rv;
        my $wv1 = length($$bout) ? $wv : '';

        $debug and $debug & 32 and _debug("_do_io select(-,-,-, ". (defined $timeout ? $timeout : 'undef') .")");

        my $n = select($rv1, $wv1, undef, $timeout);
        if ($n > 0) {
            if (vec($wv1, $fnoout, 1)) {
                my $written = syswrite($sftp->{ssh_out}, $$bout, 64 * 1024);
                if ($debug and $debug & 32) {
		    _debug (sprintf "_do_io write queue: %d, syswrite: %s, max: %d",
			    length $$bout,
			    (defined $written ? $written : 'undef'),
			    64 * 1024);
		    $debug & 2048 and $written and _hexdump(substr($$bout, 0, $written));
		}
                unless ($written) {
                    $sftp->_conn_lost;
                    return undef;
                }
                substr($$bout, 0, $written, '');
            }
            if (vec($rv1, $fnoin, 1)) {
                my $read = sysread($sftp->{ssh_in}, $$bin, 64 * 1024, length($$bin));
                if ($debug and $debug & 32) {
		    _debug (sprintf "_do_io read sysread: %s, total read: %d",
			    (defined $read ? $read : 'undef'),
			    length $$bin);
		    $debug & 1024 and $read and _hexdump(substr($$bin, -$read));
		}
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

1;
