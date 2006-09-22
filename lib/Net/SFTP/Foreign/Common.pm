package Net::SFTP::Foreign::Common;

our $VERSION = '0.01';

use strict;
use warnings;
use Carp;
use Scalar::Util qw(dualvar);
use Fcntl qw(S_ISLNK S_ISDIR);

use Net::SFTP::Foreign::Helpers qw(_gen_wanted _ensure_list);
use Net::SFTP::Foreign::Constants qw(:status);

my %status_str = ( SSH2_FX_OK, "OK",
		   SSH2_FX_EOF, "End of file",
		   SSH2_FX_NO_SUCH_FILE, "No such file or directory",
		   SSH2_FX_PERMISSION_DENIED, "Permission denied",
		   SSH2_FX_FAILURE, "Failure",
		   SSH2_FX_BAD_MESSAGE, "Bad message",
		   SSH2_FX_NO_CONNECTION, "No connection",
		   SSH2_FX_CONNECTION_LOST, "Connection lost",
		   SSH2_FX_OP_UNSUPPORTED, "Operation unsupported" );

sub _set_status {
    my ($sftp, $code, $str) = @_;
    if ($code) {
	$str = $status_str{$code} unless defined $str;
	$str = "Unknown status ($code)" unless defined $str;
	return $sftp->{_status} = dualvar($code, $str);
    }
    else {
	return $sftp->{_status} = 0;
    }
}

sub status { shift->{_status} }

sub _set_error {
    my ($sftp, $code, $str) = @_;
    if ($code) {
	unless (defined $str) {
	    $str = $code ? "Unknown error $code" : "OK";
	}
	return $sftp->{_error} = dualvar $code, $str;
    }
    else {
	return $sftp->{_error} = 0;
    }
}

sub _copy_error {
    $_[0]->{_error} = $_[1]->{_error};
}

sub error { shift->{_error} }

sub _set_errno {
    my $sftp = shift;
    if ($sftp->{_error}) {
	my $status = $sftp->{_status} + 0;
	my $error = $sftp->{_error} + 0;
	if ($status == SSH2_FX_EOF) {
	    return;
	}
	elsif ($status == SSH2_FX_NO_SUCH_FILE) {
	    $! = Errno::ENOENT();
	}
	elsif ($status == SSH2_FX_PERMISSION_DENIED) {
	    $! = Errno::EACCES();
	}
	elsif ($status == SSH2_FX_BAD_MESSAGE) {
	    $! = Errno::EBADMSG();
	}
	elsif ($status == SSH2_FX_OP_UNSUPPORTED) {
	    $! = Errnor::ENOTSUP()
	}
	elsif ($status) {
	    $! = Errnor::EIO()
	}
    }
}

sub _call_on_error {
    my ($sftp, $on_error, $entry) = @_;
    if ($on_error and $sftp->error) {
	$on_error->($sftp, $entry);
	$sftp->_set_error;
	$sftp->_set_status;
    }
}

# this method code is a little convoluted because we are trying to
# keep in memory as few entries as possible!!!
sub find {
    my ($self, $dirs, %opts) = @_;

    $self->_set_error;
    $self->_set_status;

    my $follow_links = delete $opts{follow_links};
    my $on_error = delete $opts{on_error};
    my $realpath = delete $opts{realpath};
    my $ordered = delete $opts{ordered};
    my $atomic_readdir = delete $opts{atomic_readdir};
    my $wanted = _gen_wanted( delete $opts{wanted},
			      delete $opts{no_wanted} );
    my $descend = _gen_wanted( delete $opts{descend},
			       delete $opts{no_descend} );

    %opts and croak "invalid option(s) '".CORE::join("', '", keys %opts)."'";

    my $wantarray = wantarray;
    my (@res, $res);
    my %done;
    my %rpdone;

    my @dirs = _ensure_list $dirs;
    my @queue = map { { filename => $_ } } ($ordered ? sort @dirs : @dirs);

    # we use a clousure instead of an auxiliary method to have access
    # to the state:

    my $task = sub {
	my $entry = shift;
	my $fn = $entry->{filename};
	for (1) {
	    my $follow = $follow_links and S_ISLNK($entry->{a}->perm);

	    if ($follow or $realpath) {
		unless (defined $entry->{realpath}) {
		    my $rp = $entry->{realpath} = $self->realpath($fn)
			or next;
		    $rpdone{$rp}++ and next;
		}
	    }
		
	    if ($follow) {
		$entry->{a} = $self->stat($fn)
		    or next;
		unshift @queue, $entry;
		next;
	    }
		
	    if (!$wanted or $wanted->($self, $entry)) {
		if ($wantarray) {
		    push @res, $entry;
		}
		else {
		    $res++;
		}
	    }
	}
	continue {
	    $self->_call_on_error($on_error, $entry)
	}
    };

    my $try;
    while (@queue) {
	no warnings 'uninitialized';
	$try = shift @queue;
	my $fn = $try->{filename};
	next if $done{$fn}++;

	my $a = $try->{a} ||= $self->lstat($fn)
	    or next;

	$task->($try);

	if (S_ISDIR($a->perm)) {
	    if (!$descend or $descend->($self, $try)) {
		if ($ordered or $atomic_readdir) {
		    my $ls = $self->ls( $fn,
					ordered => $ordered,
					_wanted => sub {
					    my $child = $_[1]->{filename};
					    if ($child !~ /^\.\.?$/) {
						$_[1]->{filename} = $self->join($fn, $child);
						return 1;
					    }
					    undef;
					})
			or next;
		    unshift @queue, @$ls;
		}
		else {
		    $self->ls( $fn,
			       _wanted => sub {
				   my $entry = $_[1];
				   my $child = $entry->{filename};
				   if ($child !~ /^\.\.?$/) {
				       $entry->{filename} = $self->join($fn, $child);

				       if (S_ISDIR($entry->{a}->perm)) {
					   push @queue, $entry;
				       }
				       else {
					   $task->($entry);
				       }
				   }
				   undef } )
			or next;
		}
	    }
	}
    }
    continue {
	$self->_call_on_error($on_error, $try)
    }

    return wantarray ? @res : $res;
}

sub test_d {
    my ($sftp, $name) = @_;
    my $a = $sftp->stat($name);
    $a ? S_ISDIR($a->perm) : undef;
}

1;
