package Net::SFTP::Foreign::Helpers;

our $VERSION = '0.01';

use strict;
use warnings;
use Carp;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw( _do_nothing
		  _sort_entries
		  _gen_wanted
		  _ensure_list
		  _glob_to_regex );

sub _do_nothing {}

{
    my $has_sk;
    sub _has_sk {
	unless (defined $has_sk) {
	    eval { require Sort::Key };
	    $has_sk = ($@ ne '');
	}
	return $has_sk;
    }
}

sub _sort_entries {
    my $e = shift;
    if (_has_sk) {
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

sub _ensure_list {
    my $l = shift;
    return () unless defined $l;
    return @$l if eval { @$l >= 0};
    return ($l);
}

sub _glob_to_regex {
    my ($glob, $strict_leading_dot, $ignore_case) = @_;

    my ($regex, $in_curlies, $escaping);

    my $first_byte = 1;
    while ($glob =~ /\G(.)/g) {
	my $char = $1;
	# print "char: $char\n";
	if ($char eq '\\') {
	    $escaping = 1;
	}
	else {
	    if ($first_byte) {
		if ($strict_leading_dot) {
		    $regex .= '(?=[^\.])' unless $char eq '.';
		}
		$first_byte = 0;
	    }
	    if ($char eq '/') {
		$first_byte = 1;
	    }
	    if ($escaping) {
		$regex .= quotemeta $char;
	    }
	    else {
		if ($char eq '*') {
		    $regex .= ".*";
		}
		elsif ($char eq '?') {
		    $regex .= '.'
		}
		elsif ($char eq '{') {
		    $regex .= '(?:(?:';
		    ++$in_curlies;
		}
		elsif ($char eq '}') {
		    $regex .= "))";
		    --$in_curlies;
		    $in_curlies < 0
			and croak "invalid glob pattern";
		}
		elsif ($char eq ',' && $in_curlies) {
		    $regex .= ")|(?:";
		}
		elsif ($char eq '[') {
		    if ($glob =~ /\G((?:\\.|[^\]])+)\]/g) {
			$regex .= "[$1]"
		    }
		    else {
			croak "invalid glob pattern";
		    }
				
		}
		else {
		    $regex .= quotemeta $char;
		}
	    }

	    $escaping = 0;
	}
    }

    croak "invalid glob pattern" if $in_curlies;

    $ignore_case ? qr/^$regex$/i : qr/^$regex$/;
}

1;
