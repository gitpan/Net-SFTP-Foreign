package Net::SFTP::Foreign;

our $VERSION = '0.90_02';

use strict;
use warnings;
use Carp qw(carp croak );
use Scalar::Util qw(dualvar);
use Fcntl qw(:mode);
use IPC::Open2;

my $has_sk;
BEGIN { $has_sk = eval "use Sort::Key; 1" }

use Net::SFTP::Foreign::Constants qw( :fxp :flags :att
				      :status :error
				      SSH2_FILEXFER_VERSION );
use Net::SFTP::Foreign::Attributes;
use Net::SFTP::Foreign::Buffer;

use constant COPY_SIZE => 16384;

sub _debug { print STDERR @_, "\n" };

our $debug;

sub _next_msg_id { shift->{_msg_id}++ }

sub _send_new_msg {
    my $sftp = shift;
    my $code = shift;
    my $id = $sftp->_next_msg_id;
    my $msg = Net::SFTP::Foreign::Buffer->new(int8 => $code, int32 => $id, @_);
    $sftp->_send_msg($msg);
    return $id;
}

sub _send_msg {
    my ($sftp, $buf) = @_;
    my $bytes = $buf->bytes;
    $bytes = pack('N', length($bytes)) . $bytes;
    my $len = length $bytes;
    my $off = 0;
    local $SIG{PIPE} = 'IGNORE';
    while ($len) {
	my $limlen = $len < 8192 ? $len : 8192;
	my $bw = syswrite($sftp->{ssh_out}, $bytes, $limlen,  $off);
	unless (defined $bw) {
	    $sftp->_set_status(SSH2_FX_CONNECTION_LOST);
	    croak "writing to ssh pipe failed ($!)";
	}
	$len-=$bw;
	$off+=$bw;
    }
}

sub _sysread {
    my $sftp = shift;
    my ($in, $len)=@_;
    my $off=0;
    my $bytes;
    local $SIG{PIPE}='IGNORE';
    while ($len) {
	my $limlen = $len < 8192 ? $len : 8192;
	my  $br=sysread($in, $bytes, $limlen, $off);
	unless (defined $br and $br) {
	    $sftp->_set_status(SSH2_FX_CONNECTION_LOST);
	    croak "reading from ssh pipe failed ($!)";
	}
	$len-=$br;
	$off+=$br;
    }
    $bytes
}

sub _get_msg {
    my $sftp=shift;
    my $len = unpack('N', $sftp->_sysread($sftp->{ssh_in}, 4));
    $len > 256*1024 and croak "message too long ($len bytes)";
    Net::SFTP::Foreign::Buffer->make($sftp->_sysread($sftp->{ssh_in}, $len));
}

sub _ensure_list {
    my $l = shift;
    return () unless defined $l;
    return @$l if eval { @$l >= 0};
    return ($l);
}

sub new {
    my $class = shift;
    unshift @_, 'host' if @_ & 1;
    my %opts = @_;

    my $sftp = {_msg_id => 0};
    bless $sftp, $class;

    $sftp->_set_status;
    $sftp->_set_error;

    my @open2_cmd;

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

	push @open2_cmd, _ensure_list(delete $opts{more});

	push @open2_cmd, $host, -s => 'sftp';
    }

    croak "invalid option(s) '".join("', '", keys %opts)."' or bad combination"
	if %opts;

    $sftp->{pid} = open2($sftp->{ssh_in}, $sftp->{ssh_out}, @open2_cmd)
	or croak "running '@_' failed ($!)";

    eval { $sftp->_init };
    if ($@ and $@ =~ /(?:reading from|writing to) ssh pipe failed/) {
	croak "stablishing connection to remote server via an ssh pipe failed";
    }

    $sftp
}

sub DESTROY {
    my $sftp = shift;
    if (defined $sftp->{pid}) {
	close $sftp->{ssh_out} if defined $sftp->{ssh_out};
	close $sftp->{ssh_in} if defined $sftp->{ssh_in};
	if ($^O =~ /Win/) {
	    kill 1, $sftp->{pid}
		and waitpid($sftp->{pid}, 0);
	}
	else {
	    waitpid($sftp->{pid}, 0);
	}
    }
}

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
	return $sftp->{status} = dualvar($code, $str);
    }
    else {
	return $sftp->{status} = 0;
    }
}

sub status { shift->{status} }

sub _set_error {
    my ($sftp, $code, $str) = @_;
    if ($code) {
	unless (defined $str) {
	    $str = $code ? "Unknown error $code" : "OK";
	}
	return $sftp->{error} = dualvar $code, $str;
    }
    else {
	return $sftp->{error} = 0;
    }
}

sub error { shift->{error} }

sub _init {
    my $sftp = shift;

    $debug and _debug("Sending SSH2_FXP_INIT");
    my $msg = Net::SFTP::Foreign::Buffer->new(int8 => SSH2_FXP_INIT,
					      int32 => SSH2_FILEXFER_VERSION);
    $sftp->_send_msg($msg);

    $msg = $sftp->_get_msg;
    my $type = $msg->get_int8;
    if ($type == SSH2_FXP_VERSION) {
	my $version = $msg->get_int32;
	$debug and _debug("Remote version: $version");

	## XXX Check for extensions.

	$sftp->{server_version} = $version;
	return $version;
    }
    else {
	$sftp->_set_error(SFTP_ERR_REMOTE_BAD_PACKET_TYPE,
			  "bad packet type, expecting SSH2_FXP_VERSION, got $type");
    }
    return undef;
}


# helper methods:

sub _get_msg_and_check {
    my ($sftp, $etype, $eid, $err, $errstr) = @_;

    my $msg = $sftp->_get_msg;
    my $type = $msg->get_int8;
    my $id = $msg->get_int32;

    $debug and _debug("Received packet id: $id, type: $type");

    $sftp->_set_status;
    $sftp->_set_error;

    if ($id != $eid) {
	$sftp->_set_error(SFTP_ERR_REMOTE_BAD_PACKET_SEQUENCE,
			  "$errstr: bad packet sequence, expected $eid, got $id");
	return undef;
    }

    if ($type != $etype) {
	if ($type == SSH2_FXP_STATUS) {
	    my $status = $sftp->_set_status($msg->get_int32);
	    $sftp->_set_error($err, "$errstr: $status");
	}
	else {
	    $sftp->_set_error(SFTP_ERR_REMOTE_BAD_PACKET_TYPE,
			      "$errstr: bad packet type, expected $etype packet, got $type");	
	}
	return undef;
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

## Client -> server methods.

sub _send_str_request {
    my($sftp, $code, $str, $attrs) = @_;
    my $id = $sftp->_send_new_msg($code, str => $str, 
				  (defined $attrs ? (attr => $attrs) : ()));
    $debug and _debug("Sent message T:$code I:$id");
    $id;
}

sub _check_status_ok {
    my ($sftp, $eid, $error, $errstr) = @_;
    if (my $msg = $sftp->_get_msg_and_check(SSH2_FXP_STATUS, $eid,
					    $error, $errstr)) {
	
	my $status = $sftp->_set_status($msg->get_int32);

	$debug and _debug("SSH2_FXP_STATUS status: $status");

	return 1 if $status == SSH2_FX_OK;

	$sftp->_set_error($error, "$errstr: $status");
    }
    return undef;
}

## SSH2_FXP_OPEN (3)
# returns handle on success, undef on failure
sub open {
    my $sftp = shift;
    my($path, $flags, $a) = @_;
    $a ||= Net::SFTP::Foreign::Attributes->new;
    my $id = $sftp->_send_new_msg(SSH2_FXP_OPEN, str => $path,
				  int32 => $flags, attr => $a);

    $debug and _debug("Sent SSH2_FXP_OPEN I:$id P:$path");

    return $sftp->_get_handle($id, SFTP_ERR_REMOTE_OPEN_FAILED,
			      "Couldn't open remote file '$path'");
}

## SSH2_FXP_OPENDIR (11)
sub opendir {
    my $sftp = shift;
    my $id = $sftp->_send_str_request(SSH2_FXP_OPENDIR, @_);
    return $sftp->_get_handle($id, SFTP_ERR_REMOTE_OPENDIR_FAILED,
			      "Couldn't open remote dir '$_[0]'");
}

## SSH2_FXP_READ (4)
# returns data on success undef on failure
sub read {
    my ($sftp, $handle, $offset, $size) = @_;
    $size ||= COPY_SIZE;

    my $id = $sftp->_send_new_msg(SSH2_FXP_READ, str=> $handle,
				  int64 => $offset, int32 => $size);

    $debug and _debug("Sent message SSH2_FXP_READ I:$id O:$offset");

    if (my $msg = $sftp->_get_msg_and_check(SSH2_FXP_DATA, $id,
					    SFTP_ERR_REMOTE_READ_FAILED,
					    "Couldn't read from remote file")) {
	return $msg->get_str;
    }
    return undef;
}

## SSH2_FXP_WRITE (6)
# returns true on success, undef on failure
sub write {
    my ($sftp, $handle, $offset, $data) = @_;

    my $id = $sftp->_send_new_msg(SSH2_FXP_WRITE, str => $handle,
				  int64 => $offset, str => $data);

    $debug and _debug("Sent message SSH2_FXP_WRITE I:$id O:$offset");

    if ($sftp->_check_status_ok($id,
				SFTP_ERR_REMOTE_WRITE_FAILED,
				"Couldn't write to remote file")) {
	return 1;
    }
    return undef;
}


sub _gen_stat_method {
    my ($code, $error, $errstr) = @_;
    return sub {
	my $sftp = shift;
	my $id = $sftp->_send_str_request($code, @_);
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

*fstat = _gen_stat_method(SSH2_FXP_FSTAT,
			  SFTP_ERR_REMOTE_FSTAT_FAILED,
			  "Couldn't stat remote file (fstat)");

*stat = _gen_stat_method(SSH2_FXP_STAT,
			 SFTP_ERR_REMOTE_STAT_FAILED,
			 "Couldn't stat remote file (stat)");


sub _gen_simple_method {
    my($code, $error, $errstr) = @_;
    return sub {
        my $sftp = shift;
        my $id = $sftp->_send_str_request($code, @_);
        return $sftp->_check_status_ok($id, $error, $errstr);
    };
}

## SSH2_FXP_CLOSE (4),   SSH2_FXP_REMOVE (13),
## SSH2_FXP_MKDIR (14),  SSH2_FXP_RMDIR (15),
## SSH2_FXP_SETSTAT (9), SSH2_FXP_FSETSTAT (10)
# all of these return true on success, undef on failure

*close = _gen_simple_method(SSH2_FXP_CLOSE,
			       SFTP_ERR_REMOTE_CLOSE_FAILED,
			       "Couldn't close remote file");

*remove = _gen_simple_method(SSH2_FXP_REMOVE,
				SFTP_ERR_REMOTE_REMOVE_FAILED,
				"Couldn't delete remote file");

*mkdir = _gen_simple_method(SSH2_FXP_MKDIR,
			       SFTP_ERR_REMOTE_MKDIR_FAILED,
			       "Couldn't create remote directory");

*rmdir = _gen_simple_method(SSH2_FXP_RMDIR,
			       SFTP_ERR_REMOTE_RMDIR_FAILED,
			       "Couldn't remove remote directory");

*setstat = _gen_simple_method(SSH2_FXP_SETSTAT,
				 SFTP_ERR_REMOTE_SETSTAT_FAILED,
				 "Couldn't setstat remote file (setstat)'");

*fsetstat = _gen_simple_method(SSH2_FXP_FSETSTAT,
				  SFTP_ERR_REMOTE_FSETSTAT_FAILED,
				  "Couldn't setstat remote file (fsetstat)");

sub _close_save_state {
    my $sftp = shift;
    my $oerror = $sftp->{error};
    my $ostate = $sftp->{state};
    $sftp->close(@_);
    if ($oerror) {
	$sftp->{error} = $oerror;
	$sftp->{state} = $ostate;
    }
    undef;
}

## SSH2_FXP_REALPATH (16)
# returns realpath on success, undef on failure
sub realpath {
    my ($sftp, $path) = @_;

    my $id = $sftp->_send_str_request(SSH2_FXP_REALPATH, $path);

    if (my $msg = $sftp->_get_msg_and_check(SSH2_FXP_NAME, $id,
					    SFTP_ERR_REMOTE_REALPATH_FAILED,
					    "Couldn't get real path for remote file")) {
	$msg->get_int32 > 0
	    and return $msg->get_str;

	$sftp->_set_error(SFTP_ERR_REMOTE_REALPATH_FAILED,
			 "Couldn't get real path for remote file, no names on reply")
    }
    return undef;
}

## SSH2_FXP_RENAME (18)
# true on success, undef on failure
sub rename {
    my ($sftp, $old, $new) = @_;
    my $id = $sftp->_send_new_msg(SSH2_FXP_RENAME,
					 str => $old,
					 str => $new);

    $debug and _debug("Sent message SSH2_FXP_RENAME '$old' => '$new'");

    return $sftp->_check_status_ok($id, SFTP_ERR_REMOTE_RENAME_FAILED,
				   "Couldn't rename remote file '$old' to '$new'");
}

## High-level client -> server methods.

# returns true on success, undef on failure
sub get {
    my ($sftp, $remote, $local, %opts) = @_;

    $sftp->_set_error;

    my $cb = delete $opts{callback};
    my $umask = delete $opts{umask};
    my $perm = delete $opts{perm};
    my $copy_perms = delete $opts{copy_perms};
    my $copy_time = delete $opts{copy_time};
    my $overwrite = delete $opts{overwrite};
    my $block_size = delete $opts{block_size} || COPY_SIZE;
    my $queue_size = delete $opts{queue_size} || 10;
    my $dont_save = delete $opts{dont_save};

    my $oldumask = umask;

    %opts and croak "invalid option(s) '".join("', '", keys %opts)."'";

    croak "'perm' and 'umask' options can not be used simultaneously"
	if (defined $perm and $umask);

    croak "'perm' and 'copy_perms' options can not be used simultaneously"
	if (defined $perm and $copy_perms);

    my $numask;

    if (defined $perm) {
	$numask = $perm;
    }
    else {
	$umask = $oldumask unless defined $umask;
	$numask = 0777 & ~$umask;
    }

    $overwrite = 1 unless defined $overwrite;
    $copy_perms = 1 unless (defined $perm or defined $copy_perms);
    $copy_time = 1 unless defined $copy_time;

    my $a = $sftp->stat($remote)
	or return undef;
    my $size = $a->size;

    my $handle = $sftp->open($remote, SSH2_FXF_READ);
    defined $handle or return undef;

    my $fh;
    unless ($dont_save) {
	if (!$overwrite and -e $local) {
	    $sftp->_set_error(SFTP_ERR_LOCAL_ALREADY_EXISTS,
			     "local file $local already exists");
	    return undef;
	}
	
	if ($copy_perms) {
	    my $aperm = $a->perm;
	    $perm = 0666 unless defined $perm;
	    $a->perm =~ /^(\d+)$/ or die "perm is not numeric";
	    $perm = int $1;
	}

	my $lumask = ~$perm & 0666;
	umask $lumask;

	unless (CORE::open $fh, ">", $local) {
	    umask $oldumask;
	    $sftp->_set_error(SFTP_ERR_LOCAL_OPEN_FAILED,
			     "Can't open $local: $!");
	    return undef;
	}
	umask $oldumask;

	binmode $fh;

	if ((0666 & ~$lumask) != $perm) {
	    unless (chmod $perm & $numask, $fh) {
		$sftp->_set_error(SFTP_ERR_LOCAL_CHMOD_FAILED,
				  "Can't chmod $local: $!");
		return undef;
	    }
	}
    }

    my @msgid;
    my @askoff;
    my $askoff = 0;
    my $loff = 0;
    my $rfno = fileno($sftp->{ssh_in});

 OK: do {
	while (1) {
	    # request a new block if queue is not full
	    if (!@msgid or ($size <= $askoff and @msgid < $queue_size)) {
		my $id = $sftp->_send_new_msg(SSH2_FXP_READ, str=> $handle,
					      int64 => $askoff, int32 => $block_size);
		$debug and _debug("Sent message SSH2_FXP_READ I:$id O:$askoff");

		push @msgid, $id;
		push @askoff, $askoff;
		$askoff += $block_size;
	    }

	    # if queue is not full, go sending a new request instead
	    # of waiting for a paquet to arrive
	    if ( $size > $askoff && @msgid < $queue_size ) {
		my $rin = '';
		vec ($rin, $rfno, 1) = 1;
		next unless scalar select($rin, undef, undef, 0);
	    }

	    my $eid = shift @msgid;
	    my $roff = shift @askoff;

	    my $msg = $sftp->_get_msg_and_check(SSH2_FXP_DATA, $eid,
						SFTP_ERR_REMOTE_READ_FAILED,
						"Couldn't read from remote file");

	    unless ($msg) {
		if ($sftp->{status} == SSH2_FX_EOF) {
		    next if $roff != $loff;
		    $sftp->_set_error();
		    last;
		}
		last OK;
	    }

	    my $data = $msg->get_str;
	    my $len = length $data;
	
	    $debug and _debug("In read loop, got $len bytes, offset $roff");

	    if ($roff != $loff or !$len) {
		$sftp->_set_error(SFTP_ERR_REMOTE_BLOCK_TOO_SMALL);
		last OK;
	    }

	    $loff += $len;
	    $askoff = $loff if $len < $block_size;

	    if (defined $cb) {
		$size = $loff if $loff > $size;
		$cb->($sftp, $data, $roff, $size);
	    }

	    unless ($dont_save or print $fh $data) {
		$sftp->_set_error(SFTP_ERR_LOCAL_WRITE_FAILED,
				 "unable to write data to local file $local: $!");
		last OK;
	    }
	}
    };

    $sftp->_get_msg for (@msgid);
	
    $sftp->_close_save_state($handle);

    return undef if $sftp->error;

    unless ($dont_save or close $fh) {
	$sftp->_set_error(SFTP_ERR_LOCAL_WRITE_FAILED,
			  "unable to write data to local file $local: $!");
	return undef;
    }

    # we can be running on taint mode, so some checks are
    # performed to untaint data from the remote side.

    unless ($dont_save) {
	if ($copy_time) {
	    if ($a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
		$a->atime =~ /^(\d+)$/ or die "Bad atime from remote file $remote";
		my $atime = int $1;
		$a->mtime =~ /^(\d+)$/ or die "Bad mtime from remote file $remote";
		my $mtime = int $1;

		unless (utime $atime, $mtime, $local) {
		    $sftp->_set_error(SFTP_ERR_LOCAL_UTIME_FAILED,
				      "Can't utime $local: $!");
		    return undef;
		}
	    }
	}
    };

    return !$sftp->{error}
}

# return file contents on success, undef on failure
sub get_content {
    my ($sftp, $name) = @_;
    my @data;

    if ($sftp->get($name, undef,
		   dont_save => 1,
		   callback => sub { push @data, $_[1] })) {
	return join('', @data);
    }
    return undef;
}

sub put {
    my ($sftp, $local, $remote, %opts) = @_;

    $sftp->_set_error;
    $sftp->_set_status;

    my $cb = delete $opts{callback};

    my $umask = delete $opts{umask};
    my $perm = delete $opts{perm};
    my $copy_perms = delete $opts{copy_perms};
    my $copy_time = delete $opts{copy_time};
    my $overwrite = delete $opts{overwrite};
    my $block_size = delete $opts{block_size} || COPY_SIZE;
    my $queue_size = delete $opts{queue_size} || 10;

    %opts and croak "invalid option(s) '".join("', '", keys %opts)."'";

    croak "'perm' and 'umask' options can not be used simultaneously"
	if (defined $perm and $umask);

    croak "'perm' and 'copy_perms' options can not be used simultaneously"
	if (defined $perm and $copy_perms);

    my $numask;

    if (defined $perm) {
	$numask = $perm;
    }
    else {
	$umask = umask unless defined $umask;
	$numask = 0777 & ~$umask;
    }
    $overwrite = 1 unless defined $overwrite;
    $copy_perms = 1 unless (defined $perm or defined $copy_perms);
    $copy_time = 1 unless defined $copy_time;

    my $fh;
    unless (CORE::open $fh, '<', $local) {
	$sftp->_set_error(SFTP_ERR_LOCAL_OPEN_FAILED,
			 "Unable to open local file '$local': $!");
	return undef;
    }

    my ($lmode, $lsize, $latime, $lmtime);
    unless ((undef, undef, $lmode, undef, undef,
	     undef, undef, $lsize, $latime, $lmtime) = stat $fh) {
	$sftp->_set_error(SFTP_ERR_LOCAL_STAT_FAILED,
			 "Couldn't stat local file '$local': $!");
	return undef;
    }

    $perm = $lmode & $numask if defined $copy_perms;

    my $attrs = Net::SFTP::Foreign::Attributes->new;
    $attrs->set_perm($perm);

    my $handle = $sftp->open($remote,
				SSH2_FXF_WRITE | SSH2_FXF_CREAT |
				($overwrite ? SSH2_FXF_TRUNC : SSH2_FXF_EXCL),
				$attrs)
	or return undef;

    my @msgid;
    my @readoff;
    my $readoff = 0;
    my $rfno = fileno($sftp->{ssh_in});

 OK: do {
	my $eof;
	while (1) {
	    if (!$eof and @msgid < $queue_size) {
		my $len = CORE::read $fh, my ($data), $block_size;
		unless (defined $len) {
		    $sftp->_set_error(SFTP_ERR_LOCAL_READ_ERROR,
				     "Couldn't read from local file '$local': $!");
		    last OK;
		}
		
		my $nextoff = $readoff + $len;

		if (defined $cb) {
		    $lsize = $nextoff if $nextoff > $lsize;
		    $cb->($sftp, $data, $readoff, $lsize);
		    $len = length $data;
		    $nextoff = $readoff + $len;
		}

		if ($len) {
		    my $id = $sftp->_send_new_msg(SSH2_FXP_WRITE, str => $handle,
						  int64 => $readoff, str => $data);
		
		    $debug and _debug("In write loop, sent block id: $id, offset: $readoff, len: $len");


		    push @msgid, $id;
		    push @readoff, $readoff;
		    $readoff = $nextoff;
		}
		else {
		    $eof = 1;
		}
	    }

	    last if ($eof and !@msgid);

	    if ( !$eof and @msgid < $queue_size) {
		my $rin = '';
		vec ($rin, $rfno, 1) = 1;
		next unless scalar select($rin, undef, undef, 0);
	    }

	    my $id = shift @msgid;
	    my $loff = shift @readoff;
	    unless ($sftp->_check_status_ok($id,
					    SFTP_ERR_REMOTE_WRITE_FAILED,
					    "Couldn't write to remote file")) {
		last OK;
	    }
	}
    };

    close $fh;

    $sftp->_get_msg for (@msgid);

    $sftp->_close_save_state($handle);

    return undef if $sftp->error;

    if ($copy_time) {
	$attrs = Net::SFTP::Foreign::Attributes->new;
	$attrs->set_amtime($latime, $lmtime);
	$sftp->setstat($remote, $attrs);
    }
	
    return $sftp->{error} == 0;
}

sub _sort_entries {
    my $e = shift;
    if ($has_sk) {
	&Sort::Key::keysort_inplace(sub { $_->{filename} }, $e);
    }
    else {
	@$e = sort { $a->{filename} cmp $b->{filename} } @$e;
    }
}

sub _gen_wanted {
    my ($ow, $onw) = my ($w, $nw) = @_;
    if (ref $w eq 'Regexp') {
	$w = sub { $_[1]->{filename} =~ $ow }
    }

    if (ref $nw eq 'Regexp') {
	$nw = sub { $_[1]->{filename} !~ $onw }
    }
    elsif (defined $nw) {
	$nw = sub { !&$onw };
    }

    if (defined $w and defined $nw) {
	return sub { &$nw and &$w }
    }

    return $w || $nw;
}

sub ls {
    my ($sftp, $remote, %opts) = @_;

    my $ordered = delete $opts{ordered};

    my $wanted = delete $opts{_wanted} ||
	_gen_wanted(delete $opts{wanted},
		    delete $opts{no_wanted});

    %opts and croak "invalid option(s) '".join("', '", keys %opts)."'";

    my $handle = $sftp->opendir($remote);
    return unless defined $handle;

    my @dir;
    while (1) {
        my $id = $sftp->_send_str_request(SSH2_FXP_READDIR, $handle);

	if (my $msg = $sftp->_get_msg_and_check(SSH2_FXP_NAME, $id,
						SFTP_ERR_REMOTE_READDIR_FAILED,
						"Couldn't read directory '$remote'" )) {

	    my $count = $msg->get_int32 or last;

	    for (1..$count) {
		my $entry =  { filename => $msg->get_str,
			       longname => $msg->get_str,
			       a => $msg->get_attributes };
		if (!$wanted or $wanted->($sftp, $entry)) {
		    push @dir, $entry;
		}
            }
	}
	else {
	    $sftp->_set_error if $sftp->{status} == SSH2_FX_EOF;
	    last;
	}
    }

    $sftp->_close_save_state($handle);

    _sort_entries \@dir if $ordered;

    return $sftp->{error} == 0 ? \@dir : undef;
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
    my ($sftp, $dirs, %opts) = @_;

    $sftp->_set_error;
    $sftp->_set_status;

    my $follow_links = delete $opts{follow_links};
    my $on_error = delete $opts{on_error};
    my $realpath = delete $opts{realpath};
    my $ordered = delete $opts{ordered};
    my $wanted = _gen_wanted( delete $opts{wanted},
			      delete $opts{no_wanted} );
    my $descend = _gen_wanted( delete $opts{descend},
			       delete $opts{no_descend} );

    %opts and croak "invalid option(s) '".join("', '", keys %opts)."'";

    my $wantarray = wantarray;
    my (@res, $res);
    my %done;
    my %rpdone;

    my @dirs = _ensure_list $dirs;
    my @queue = map { { filename => $_ } } ($ordered ? sort @dirs : @dirs);

    my $try;
    while (@queue) {
	no warnings 'uninitialized';
	$try = shift @queue;
	my $fn = $try->{filename};
	next if $done{$fn}++;

	my $a = $try->{a} || $sftp->lstat($fn)
	    or next;

	my $task = sub {
	    my $entry = shift;
	    my $fn = $entry->{filename};
	    for (1) {
		my $follow = $follow_links and S_ISLNK($entry->{a}->perm);
		
		if ($follow or $realpath) {
		    unless (defined $entry->{realpath}) {
			my $rp = $entry->{realpath} = $sftp->realpath($fn)
			    or next;
			$rpdone{$rp}++ and next;
		    }
		}
		
		if ($follow) {
		    $entry->{a} = $sftp->stat($fn)
			or next;
		    unshift @queue, $entry;
		    next;
		}
		
		if (!$wanted or $wanted->($sftp, $entry)) {
		    if ($wantarray) {
			push @res, $entry;
		    }
		    else {
			$res++;
		    }
		}

	    }
	    continue {
		$sftp->_call_on_error($on_error, $entry)
	    }
	};

	$task->($try);

	if (S_ISDIR($a->perm)) {
	    if (!$descend or $descend->($sftp, $try)) {
		if ($ordered) {
		    my $ls = $sftp->ls( $fn,
					ordered => 1,
					_wanted => sub {
					    my $child = $_[1]->{filename};
					    if ($child !~ /^\.\.?$/) {
						$_[1]->{filename} = "$fn/$child";
						return 1;
					    }
					    undef;
					})
			or next;
		    unshift @queue, @$ls;
		}
		else {
		    $sftp->ls( $fn,
			       _wanted => sub {
				   my $entry = $_[1];
				   my $child = $entry->{filename};
				   if ($child !~ /^\.\.?$/) {
				       $entry->{filename} = "$fn/$child";

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
	$sftp->_call_on_error($on_error, $try)
    }

    return wantarray ? @res : $res;
}

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

  WARNING: This is a development version, expect bugs on it!!!

  WARNING: This package API is not compatible with Net::SFTP anymore!!!

SFTP stands for Secure File Transfer Protocol and is a method of
transferring files between machines over a secure, encrypted
connection (as opposed to regular FTP, which functions over an
insecure connection). The security in SFTP comes through its
integration with SSH, which provides an encrypted transport layer over
which the SFTP commands are executed.

Net::SFTP::Foreign is a Perl client for the SFTP. It provides a subset
of the commands listed in the SSH File Transfer Protocol IETF draft,
which can be found at
L<http://www.openssh.org/txt/draft-ietf-secsh-filexfer-02.txt> (also
included on this package distribution, on the C<rfc> directory).

Net::SFTP::Foreign uses any compatible C<ssh> command installed on
your system (for instance, OpenSSH) to establish the secure connection
to the remote server.

Formelly Net::SFTP::Foreign was a hacked version of Net::SFTP, but
from version 0.90 it has been almost completelly rewritten from
scratch and a new much improved and incompatible API introduced (an
adaptor module, Net::SFTP::Foreign::Compat, is also provided for
backward compatibility).


=head2 Net::SFTP::Foreign Vs. Net::SFTP

Why should I prefer Net::SFTP::Foreign over Net::SFTP?

Well, both modules have their pros and cons:

Net::SFTP::Foreign does not requiere a bunch of additional modules and
external libraries to work, just the OpenBSD ssh client (or any other
client compatible enough).

I trust OpenSSH ssh client more than Net::SSH::Perl, there are lots of
paranoid people ensuring that OpenSSH doesn't have security holes!!!

If you have an ssh infrastructure already deployed, by using the
binary ssh client, Net::SFTP::Foreign ensures a seamless integration
within your environment (ssh configuration files, keys, etc.).

Net::SFTP::Foreign is much faster transferring files, specially over
networks with high (relative) latency.

Net::SFTP::Foreign provides several high level methods not available
from Net::SFTP as for instance, C<find> or C<mirror>.

On the other hand, using the external command means an additional
proccess being launched and running, depending on your OS this could
eat more resources than the in process pure perl implementation
provided by Net::SSH::Perl.

Net::SFTP::Foreign supports version 2 of the SSH protocol only.

Finally B<Net::SFTP::Foreign does not (and will never) allow to use
passwords for authentication>. Net::SFTP does.


=head2 USAGE

Most of the methods available from this package return undef on
failure and a true value or the requested data on
success. C<$sftp-E<gt>error> can be used to check explicitly for an
error after every method call.

Inside any method, a low-level network error (for instance, a broken ssh
connection) will cause the method to die.

=over 4

=item Net::SFTP::Foreign->new($host, %args)

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

port number where the remote ssh server is listening

=item more =E<gt> [@more_ssh_args]

additional args passed to ssh command.

=item ssh_cmd =E<gt> $sshcmd

name of the external ssh client.

=item open2_cmd =E<gt> [@cmd]

=item open2_cmd =E<gt> $cmd;

allows to completely redefine how C<ssh> is called. Its arguments are
passed to L<IPC::Open2::open2> to open a pipe to the remote
server.

=back

If stablishing the connection fails, an exception is raised, you can
use C<eval> to catch it:

  my $sftp = eval { Net::SFTP::Foreign->new(foo) };
  if ($@) {
      print STDERR "something went wrong ($@)"
  }

The exit code for the C<ssh> command is available in C<$?>, though
OpenSSH C<ssh> does not return meaningful codes. For debugging
purposes you can run C<ssh> in verbose mode passing it the C<-v>
option via the C<more> option.

  my $sftp = Net::SFTP::Foreign->new($host, more => '-v');

=item $sftp-E<gt>error

Returns the error code from the last executed command. The value
returned is similar to C<$!>, when used as a string it yields the
corresponding error string.

See L<Net::SFTP::Constants> for a list of possible error codes and how
to import them on your scripts.

=item $sftp-E<gt>status

Returns the code from the last SSH2_FXP_STATUS response. It is also a
dualvar that yields the status string when used as a string.

Usually C<$sftp-E<gt>error> should be checked first to see if there was
any error and then C<$sftp-E<gt>status> to find out its low level cause.

=item $sftp-E<gt>get($remote, $local, %options)

Copies remote file C<$remote> to local $local. By default file
attributes are also copied (permissions, atime and mtime).

The method accepts several options (not all combinations are
possible):

=over 4

=item copy_time =E<gt> $bool

determines if access and modification time attributes have to be
copied from remote file. Default is to copy them.

=item copy_perms =E<gt> $bool

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

=item copy_perms =E<gt> $bool

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

=back

=item $sftp-E<gt>ls($remote, %opts)

Fetches a directory listing of the remote B<directory> C<$remote>.

Returns a reference to a list of entries. Every entry is a reference
to a hash with three keys: C<filename>, the name of the entry;
C<longname>, an entry in a "long" listing like C<ls -l>; and C<a>, a
Net::SFTP::Foreign::Attributes object containing file atime, mtime,
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

=back

=item $sftp-E<gt>find($path, %opts)

=item $sftp-E<gt>find(\@paths, %opts)

Does a recursive seach over the given directory C<$path> (or
directories C<@path>) and returns a list of the entries found or the
total number of them on scalar context.

Every entry is a reference to a hash with two keys: C<filename>, the
full path of the entry; and C<a>, a Net::SFTP::Foreign::Attributes
object containing file atime, mtime, permissions and size.

This method tries to recover and continue under error conditions.

The options accepted by this method are:

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
filter out unwanted entries (note than filename keys contain full
paths here).

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

These options, similar to the C<wanted> ones allow to prune the
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

=back

=item $sftp-E<gt>open($path, $flags [, $attrs ])

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

=item $sftp-E<gt>read($handle, $offset, $length)

Sends the C<SSH_FXP_READ> command to read from an open file
handle C<$handle>, starting at C<$offset>, and reading at most
C<$length> bytes.

On success returns the data read from the remote file and undef on
failure.

You can test if the end of file has been reached through $sftp-E<gt>status:

  my $data = $sftp->read($handle, $offset, $length)
  if (!defined $data) {
    if ($sftp->status == SSH2_FX_EOF) {
      # end of file
      ...
    }
    else {
      # other error
    }
  }

Some servers (for instance OpenSSH SFTP server) limit the size of the
read requests and so the length of data returned can be smaller than
the requested.

=item $sftp-E<gt>write($handle, $offset, $data)

Sends the C<SSH_FXP_WRITE> command to write to an open file handle
C<$handle>, starting at C<$offset>, and where the data to be
written is in C<$data>.

Returns true on success and undef on failure.

=item $sftp-E<gt>close($handle)

Sends the C<SSH_FXP_CLOSE> command to close either an open
file or open directory, identified by C<$handle> (the handle
returned from either C<open> or C<opendir>).

Returns true on success and undef on failure.

=item $sftp-E<gt>stat($path)

performs a C<stat> on the remote file C<$path> and returns a
Net::SFTP::Foreign::Attributes object with the result values.

Returns undef on failure.

=item $sftp-E<gt>fstat($handle)

is similar to the previous method but is argument has to be a handle
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

=item $sftp-E<gt>opendir($path)

Sends a C<SSH_FXP_OPENDIR> command to open the remote
directory C<$path>, and returns an open handle on success.
On failure returns C<undef>.

=item $sftp-E<gt>remove($path)

Sends a C<SSH_FXP_REMOVE> command to remove the remote file
C<$path>. Returns a true value on success and undef on failure.

=item $sftp-E<gt>mkdir($path, $attrs)

Sends a C<SSH_FXP_MKDIR> command to create a remote directory C<$path>
whose attributes should be initialized to C<$attrs>, a
Net::SFTP::Foreign::Attributes object. Returns a true value on success
and undef on failure.

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

=back

=head1 BUGS

This is development version, expect bugs!!!


=head1 SEE ALSO

Information about the constants used on this module is available from
L<Net::SFTP::Foreign::Constants>. Information about attribute objects
is available from L<Net::SFTP::Foreign::Attributes>.

General information about ssh and the OpenSSH implementation is
available from the OpenSSH web site at L<www.openssh.org> and on the
L<sftp(1)> and L<sftp-server(8)> manual pages.

=head1 COPYRIGHT

Copyright (c) 2005, 2006 Salvador FandiE<ntilde>o.

Copyright (c) 2001 Benjamin Trott, Copyright (c) 2003 David Rolsky.

All rights reserved.  This program is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the LICENSE file included
with this module.

=cut
