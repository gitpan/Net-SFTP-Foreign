package Net::SFTP::Foreign::Buffer;

our $VERSION = '0.53';

use strict;
use warnings;
no warnings 'uninitialized';

use Carp;

use constant HAS_QUADS => eval { no warnings; pack(Q => 1); 1 } ? 1 : 0;


sub new {
    my $class = shift;
    my $data = '';
    @_ and put(\$data, @_);
    bless \$data, $class;
}

sub make { bless \$_[1], $_[0] }

sub bytes { ${$_[0]} }

sub get_int8 {
    length ${$_[0]} >=1 or croak "buffer too small";
    unpack(C => substr(${$_[0]}, 0, 1, ''));
}

sub get_int32 {
    length ${$_[0]} >=4 or croak "buffer too small";
    unpack(N => substr(${$_[0]}, 0, 4, ''));
}

sub get_int64 {
    length ${$_[0]} >=8 or croak "buffer too small";
    if (HAS_QUADS) {
	return unpack(Q => substr(${$_[0]}, 0, 8, ''))
    }
    else {
	my ($int, $zero);
	($zero, $int) = unpack(NN => substr(${$_[0]}, 0, 8, ''));
	if ($zero) {
	    # too big for an integer, try to handle it as a float:
	    my $high = $zero * 4294967296;
	    my $result = $high + $int;
	    return $result if ($result - $high == $int);
	    croak "unsupported 64bit value in buffer";
	}
	return $int;
    }

}

sub get_str {
    length ${$_[0]} >=4 or croak "buffer too small";
    my $len = unpack(N => substr(${$_[0]}, 0, 4, ''));
    length ${$_[0]} >=$len or croak "buffer too small";
    substr(${$_[0]}, 0, $len, '');
}


sub get_attributes { Net::SFTP::Foreign::Attributes->new(Buffer => $_[0]) }


sub put_int8 { ${$_[0]} .= pack(C => $_[1]) }

sub put_int32 { ${$_[0]} .= pack(N => $_[1]) }

sub put_int64 {
    if (HAS_QUADS) {
	${$_[0]} .= pack(Q => $_[1])
    }
    else {
	if ($_[1] >= 4294967296) {
	    my $high = int ( $_[1] / 4294967296);
	    my $low = int ($_[1] - $high * 4294967296);
	    ${$_[0]} .= pack(NN => $high, $low)
	}
	else {
	    ${$_[0]} .= pack(NN => 0, $_[1])
	}
    }
}

sub put_str { ${$_[0]} .= pack(N => length($_[1])) . $_[1] }

sub put_char { ${$_[0]} .= $_[1] }

sub put_attributes { ${$_[0]} .= ${$_[0]->as_buffer} }

my %unpack = ( int8 => \&get_int8,
	       int32 => \&get_int32,
	       int64 => \&get_int64,
	       str => \&get_str,
	       attr => \&get_attributtes );

sub get {
    my $buf = shift;
    map { $unpack{$_}->($buf) } @_;
}

my %pack = ( int8 => sub { pack C => $_[0] },
	     int32 => sub { pack N => $_[0] },
	     int64 => sub {
		 if (HAS_QUADS) {
		     return pack(Q => $_[0])
		 }
		 else {
		     if ($_[0] >= 4294967296) {
			 my $high = int ( $_[0] / 4294967296);
			 my $low = int ($_[0] - $high * 4294967296);
			 return pack(NN => $high, $low)
		     }
		     else {
			 return pack(NN => 0, $_[0])
		     }
		 }
	     },
	     str => sub { pack(N => length($_[0])), $_[0] },
	     char => sub { $_[0] },
	     attr => sub { ${$_[0]->as_buffer} } );

sub put {
    my $buf =shift;
    @_ & 1 and croak "bad number of arguments for put (@_)";
    my @parts;
    while (@_) {
	my $type = shift;
	my $value = shift;
	push @parts, $pack{$type}->($value)
    }
    $$buf.=join('', @parts);
}

1;
__END__

=head1 NAME

Net::SFTP::Foreign::Buffer - Read/write buffer class

=head1 SYNOPSIS

    use Net::SFTP::Foreign::Buffer;
    my $buffer = Net::SFTP::Foreign::Buffer->new;

=head1 DESCRIPTION

I<Net::SFTP::Foreign::Buffer> provides read/write buffer functionality for
SFTP.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SFTP::Foreign manpage for author, copyright, and
license information.

=cut
