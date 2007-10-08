package Net::SFTP::Foreign::Buffer;

our $VERSION = '1.31';

use strict;
use warnings;
no warnings 'uninitialized';

use Carp;

use constant HAS_QUADS => do {
    local $@;
    local $SIG{__DIE__};
    eval {
        no warnings;
        pack(Q => 0x1122334455667788) eq "\x11\x22\x33\x44\x55\x66\x77\x88"
    };
};

sub new {
    my $class = shift;
    my $data = '';
    @_ and put(\$data, @_);
    bless \$data, $class;
}

sub make { bless \$_[1], $_[0] }

sub bytes { ${$_[0]} }

sub get_int8 {
    length ${$_[0]} >=1 or return undef;
    unpack(C => substr(${$_[0]}, 0, 1, ''));
}

sub get_int32 {
    length ${$_[0]} >=4 or return undef;
    unpack(N => substr(${$_[0]}, 0, 4, ''));
}

sub get_int64 {
    my $self = shift;
    length $$self >=8 or return undef;
    if (HAS_QUADS) {
	return unpack(Q => substr($$self, 0, 8, ''))
    }
    else {
	my ($big, $small) = unpack(NN => substr($$self, 0, 8, ''));
	if ($big) {
	    # too big for an integer, try to handle it as a float:
	    my $high = $big * 4294967296;
	    my $result = $high + $small;
            unless ($result - $high == $small) {
                # too big event for a float, use a BigInt;
                require Math::BigInt;
                $result = Math::BigInt->new($big);
                $result <<= 32;
                $result += $small;
            }
	    return $result;
	}
	return $small;
    }
}

sub get_str {
    my $self = shift;
    length $$self >=4 or return undef;
    my $len = unpack(N => substr($$self, 0, 4, ''));
    length $$self >=$len or return undef;
    substr($$self, 0, $len, '');
}


sub get_attributes { Net::SFTP::Foreign::Attributes->new_from_buffer($_[0]) }


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
