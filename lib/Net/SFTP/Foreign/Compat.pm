package Net::SFTP::Foreign::Compat;

our $VERSION = '0.01';

use Net::SFTP::Foreign;
our @ISA = qw(Net::SFTP::Foreign);

sub new {
    my ($class, $host, %opts) = @_;

    my $warn;
    if (exists $opts{warn}) {
	$warn = delete($opts{warn}) || sub {};
    }
    else {
	$warn = sub { warn(join '', @_, "\n") };
    }

    my $sftp = $class->SUPER::new($host, %opts);

    $sftp->{compat_warn} = $warn;

    return $sftp;

}

sub _warn {
    my $sftp = shift;
    if (my $w = $sftp->{compat_warn}) {
	$w->(@_);
    }
}

sub _warn_error {
    my $sftp = shift;
    if (my $e = $sftp->error) {
	$sftp->_warn($e);
    }
}

sub status {
    my $status = shift->SUPER::status;
    return wantarray ? ($status + 0, "$status") : $status + 0;
}

sub get {
    my ($sftp, $remote, $local, $cb) = @_;

    my $save = defined(wantarray);
    my @content;

    $sftp->SUPER::get($remote, $local,
		      dontsave => !defined($remote),
		      callback => sub {
			  my ($sftp, $data, $off, $size) = @_;
			  $cb->($sftp, $data, $off, $size) if $cb;
			  push @content, $data if $save
		      } )
	or return undef;

    if ($save) {
	return join('', @content);
    }
}

sub put {
    my ($sftp, $local, $remote, $cb) = @_;

    $sftp->SUPER::put($local, $remote,
		      (defined $cb ? (callback => $cb) : ()));
    $sftp->_warn_error;
    !$sftp->error;
}

sub ls {
    my ($sftp, $path, $cb) = @_;
    my $ls = $sftp->SUPER::ls($path)
	or return ();

    if ($cb) {
	$cb->($_) for (@$ls);
    }
    else {
	return @$ls;
    }
}

sub do_open { shift->open(@_) }

sub do_opendir { shift->opendir(@_) }

sub do_realpath { shift->realpath(@_) }

sub do_read {
    my $sftp = shift;
    if (wantarray) {
	return ($sftp->read(@_), $sftp->status);
    }
    else {
	return $sftp->read(@_);
    }
}

sub _gen_do_and_status {
    my $method = shift;
    return sub {
	my $sftp = shift;
	$sftp->$method(@_);
	$sftp->_warn_error;
	$sftp->status;
    }
}

*do_write = _gen_do_and_status('write');
*do_close = _gen_do_and_status('close');
*do_setstat = _gen_do_and_status('setstat');
*do_fsetstat = _gen_do_and_status('fsetstat');
*do_remove = _gen_do_and_status('remove');
*do_rename = _gen_do_and_status('rename');
*do_mkdir = _gen_do_and_status('mkdir');
*do_rmdir = _gen_do_and_status('rmdir');


sub _gen_do_stat {
    my $method = shift;
    return sub {
	my $sftp = shift;
	if (my $a = $sftp->$method(@_)) {
	    return bless $a, "Net::SFTP::Foreign::Attributes::Compat";
	}
	else {
	    $sftp->_warn_error;
	    return undef;
	}
    }
}

*do_lstat = _gen_do_stat('lstat');
*do_fstat = _gen_do_stat('fstat');
*do_stat = _gen_do_stat('stat');




1;

__END__

=head1 NAME

Net::SFTP::Foreign::Compat - Adaptor for Net::SFTP compatibility

=head1 SYNOPSIS

    use Net::SFTP::Foreign::Compat;
    my $sftp = Net::SFTP::Foreign::Compat->new($host);
    $sftp->get("foo", "bar");
    $sftp->put("bar", "baz");

=head1 DESCRIPTION

This package is a wrapper around L<Net::SFTP::Foreign> that provides
an API (mostly) compatible with that of L<Net::SFTP>.

Methods on this package are identical to those in L<Net::SFTP> except
that L<Net::SFTP::Foreign::Attributes::Compat> objects have to be used
instead of L<Net::SFTP::Attributes>.

=head1 COPYRIGHT

Copyright (c) 2006 Salvador FandiE<ntilde>o

All rights reserved.  This program is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=cut

