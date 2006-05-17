package Net::SFTP::Foreign::Compat;

our $VERSION = '0.01';

use Net::SFTP::Foreign;
our @ISA = qw(Net::SFTP::Foreign);

sub new {
    my $class = shift;
    $class->SUPER::new(@_, _compat => 1);
}

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

This package is a wrapper around Net::SFTP::Foreign that provides an
API (mostly) compatible with that of Net::SFTP.

=head1 SEE ALSO

L<Net::SFTP::Foreign> and L<Net::SFTP>.

=head1 COPYRIGHT

Copyright (c) 2006 Salvador FandiE<ntilde>o

All rights reserved.  This program is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the LICENSE file included
with this module.

=cut

