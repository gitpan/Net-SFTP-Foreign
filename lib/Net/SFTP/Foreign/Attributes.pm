package Net::SFTP::Foreign::Attributes;

our $VERSION = '0.90_01';

use strict;
use warnings;
use Carp;

use Net::SFTP::Foreign::Constants qw( :att );
use Net::SFTP::Foreign::Buffer;

sub new {
    my $class = shift;
    return bless { flags => 0}, $class;
}

sub new_from_buffer {
    my ($class, $buf) = @_;
    my $self = $class->new;

    $self->{flags} = $buf->get_int32;

    if ($self->{flags} & SSH2_FILEXFER_ATTR_SIZE) {
	$self->{size} = $buf->get_int64;
    }

    if ($self->{flags} & SSH2_FILEXFER_ATTR_UIDGID) {
	$self->{uid} = $buf->get_int32;
	$self->{gid} = $buf->get_int32;
    }

    if ($self->{flags} & SSH2_FILEXFER_ATTR_PERMISSIONS) {
	$self->{perm} = $buf->get_int32;
    }

    if ($self->{flags} & SSH2_FILEXFER_ATTR_ACMODTIME) {
	$self->{atime} = $buf->get_int32;
	$self->{mtime} = $buf->get_int32;
    }

    $self;
}

sub as_buffer {
    my $a = shift;
    my $buf = Net::SFTP::Foreign::Buffer->new(int32 => $a->{flags});

    if ($a->{flags} & SSH2_FILEXFER_ATTR_SIZE) {
        $buf->put_int64(int $a->{size});
    }
    if ($a->{flags} & SSH2_FILEXFER_ATTR_UIDGID) {
        $buf->put(int32 => $a->{uid}, int32 => $a->{gid});
    }
    if ($a->{flags} & SSH2_FILEXFER_ATTR_PERMISSIONS) {
        $buf->put_int32($a->{perm});
    }
    if ($a->{flags} & SSH2_FILEXFER_ATTR_ACMODTIME) {
        $buf->put(int32 => $a->{atime}, int32 => $a->{mtime});
    }
    $buf;
}

sub flags { shift->{flags} }

sub size { shift->{size} }

sub set_size {
    my ($self, $size) = @_;
    if (defined $size) {
	$self->{flags} |= SSH2_FILEXFER_ATTR_SIZE;
	$self->{size} = $size;
    }
    else {
	$self->{flags} &= ~SSH2_FILEXFER_ATTR_SIZE;
	delete $self->{size}
    }
}

sub uid { shift->{uid} }

sub gid { shift->{gid} }

sub set_ugid {
    my ($self, $uid, $gid) = @_;
    if (defined $uid and defined $gid) {
	$self->{flags} |= SSH2_FILEXFER_ATTR_UIDGID;
	$self->{uid} = $uid;
	$self->{gid} = $gid;
    }
    elsif (!defined $uid and !defined $gid) {
	$self->{flags} &= ~SSH2_FILEXFER_ATTR_UIDGID;
	delete $self->{uid};
	delete $self->{gid};
    }
    else {
	croak "wrong arguments for set_ugid"
    }
}

sub perm { shift->{perm} }

sub set_perm {
    my ($self, $perm) = @_;
    if (defined $perm) {
	$self->{flags} |= SSH2_FILEXFER_ATTR_PERMISSIONS;
	$self->{perm} = $perm;
    }
    else {
	$self->{flags} &= ~SSH2_FILEXFER_ATTR_PERMISSIONS;
	delete $self->{perm}
    }
}

sub atime { shift->{atime} }

sub mtime { shift->{mtime} }

sub set_amtime {
    my ($self, $atime, $mtime) = @_;
    if (defined $atime and defined $mtime) {
	$self->{flags} |= SSH2_FILEXFER_ATTR_ACMODTIME;
	$self->{atime} = $atime;
	$self->{mtime} = $mtime;
    }
    elsif (!defined $atime and !defined $mtime) {
	$self->{flags} &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	delete $self->{atime};
	delete $self->{mtime};
    }
    else {
	croak "wrong arguments for set_amtime"
    }
}

1;
__END__

=head1 NAME

Net::SFTP::Foreign::Attributes - File/directory attribute container

=head1 SYNOPSIS

    use Net::SFTP::Foreign;

    my $a1 = Net::SFTP::Foreign::Attributes->new();
    $a1->set_size($size);
    $a1->set_ugid($uid, $gid);

    my $a2 = $sftp->stat($file)
        or die "remote stat command failed: ".$sftp->status;

    my $size = $a2->size;
    my $mtime = $a2->mtime;

=head1 DESCRIPTION

I<Net::SFTP::Foreign::Attributes> encapsulates file/directory
attributes for I<Net::SFTP::Foreign>. It also provides serialization
and deserialization methods to encode/decode attributes into
I<Net::SFTP::Foreign::Buffer> objects.

=head1 USAGE

=over 4

=item Net::SFTP::Foreign::Attributes-E<gt>new()

Returns a new C<Net::SFTP::Foreign::Attributes> object.

=item Net::SFTP::Foreign::Attributes-E<gt>new_from_buffer($buffer)

Creates a new attributes object and populates it with information read
from C<$buffer>.

=item $attrs-E<gt>as_buffer

Serializes the I<Attributes> object I<$attrs> into a buffer object.

=item $attrs-E<gt>flags

returns the value of the flags field.

=item $attrs-E<gt>size

returns the values of the size field or undef if it is not set.

=item $attrs-E<gt>uid

returns the value of the uid field or undef if it is not set.

=item $attrs-E<gt>gid

returns the value of the gid field or undef if it is not set.

=item $attrs-E<gt>perm

returns the value of the permissions field or undef if it is not set.

=item $attrs-E<gt>atime

returns the value of the atime field or undef if it is not set.

=item $attrs-E<gt>mtime

returns the value of the mtime field or undef if it is not set.

=item $attrs-E<gt>set_size($size)

sets the value of the size field, or if $size is undef removes the
field. The flags field is adjusted accordingly.

=item $attrs-E<gt>set_perm($perm)

sets the value of the permsissions field or removes it if the value is
undefined. The flags field is also adjusted.

=item $attr-E<gt>set_ugid($uid, $gid)

sets the values of the uid and gid fields, or removes them if they are
undefined values. The flags field is adjusted.

This pair of fields can not be set separatelly because they share the
same bit on the flags field and so both have to be set or not.

=item $attr-E<gt>set_amtime($atime, $mtime)

sets the values of the atime and mtime fields or remove them if they
are undefined values. The flags field is also adjusted.

=back

=head1 COPYRIGHT

Copyright (c) 2006 Salvador FandiE<ntilde>o.

All rights reserved.  This program is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=cut
