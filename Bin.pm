package Net::IP::Match::Bin;

use 5.005;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Net::IP::Match::Bin ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	match_ip
);

our $VERSION = '0.02';

*import = \&Exporter::import;

eval {
    require XSLoader;
    XSLoader::load('Net::IP::Match::Bin', $VERSION);
};
if ($@) {
    my $olderr = $@;
    eval {
	# Try to load the pure perl version
	#require Net::IP::Match::Bin::Perl;

	Net::IP::Match::Bin::Perl->import(qw(new add match_ip));
	push(@ISA, "Net::IP::Match::Bin::Perl");
    };
    if ($@) {
	# restore the original error
	die $olderr;
    }
}

package Net::IP::Match::Bin::Perl;
require Exporter;

our @ISA = qw(Exporter);

sub new {
    my $this = shift;
    my $class = ref($this) || $this;
    my $self = {};
    bless $self => $class;

    my $tree = {};
    $self->{Tree} = $tree;
    return $self;
}

sub add {
    my $self = shift;
    my @ipranges = @_;

   # If an argument is a hash or array ref, flatten it
   # If an argument is a scalar, make it a key and give it a value of 1
   my @map
       = map {   ! ref $_            ? ( $_ => 1 )
               :   ref $_ eq 'ARRAY' ? @{$_}
               :                       %{$_}         } @ipranges;

   # The tree is a temporary construct.  It has three possible
   # properties: 0, 1, and code.  The code is the return value for a
   # match.

IPRANGE:
   for ( my $i = 0; $i < @map; $i += 2 ) {
      my $range = $map[ $i ];
      my $match = $map[ $i + 1 ];

      my ( $ip, $mask ) = split m/\//xms, $range;
      if (! defined $mask) {
         $mask = 32;          ## no critic(MagicNumbers)
      }

      my $tree = $self->{Tree}; # root
      my @bits = split m//xms, unpack 'B32', pack 'C4', split m/[.]/xms, $ip;

      for my $bit ( @bits[ 0 .. $mask - 1 ] ) {

	  unless (exists $tree->{$bit}) {
	      $tree->{$bit} ||= {};
	  }
	  $tree = $tree->{$bit};   # Follow one branch
      }

      # Our $tree is now a leaf node of %tree.  Set its value
      # If the code is already set, it's a non-fatal error (redundant data)
      $tree->{code} ||= $match;
   }
   return $self;
}

sub match_ip {
    my ($self, $ip) = @_;

    my $tree = $self->{Tree};
    my @bits = split m//xms, unpack 'B32', pack 'C4', split m/[.]/xms, $ip;

    for my $bit ( @bits[ 0 .. 31 ] ) {
        return $tree->{code} if exists $tree->{code};
	return undef unless exists $tree->{$bit};
        $tree = $tree->{$bit};   # Follow one branch
    }
    return undef;
}

sub _dump {
    my ($tree, $bits, $lvl) = @_;

    if (exists $tree->{code}) {
	for (my $i=$lvl; $i<32; $i++) {
	    $bits->[$i] = 0;
	}
	print join(".", unpack("C4", pack("B32", join('',@$bits)))) . "/$lvl\n";
    }
    if (exists $tree->{0}) {
	$bits->[$lvl] = 0;
	_dump($tree->{0}, $bits, $lvl+1);
    }
    if (exists $tree->{1}) {
	$bits->[$lvl] = 1;
	_dump($tree->{1}, $bits, $lvl+1);
    }
}

sub dump {
    my $self = shift;
    my @bits;
    _dump($self->{Tree}, \@bits, 0);
}

# Preloaded methods go here.


1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Net::IP::Match::Bin - Perl extension for match IP addresses against Net ranges

=head1 SYNOPSIS

  use Net::IP::Match::Bin;

  my $ipm = Net::IP::Match::Bin->new();
  $ipm->add("10.1.1.0/25", ...);
  ...
  $ipm->add("192.168.2.128/26", ...);

  $cidr = $ipm->match_ip("192.168.2.131");


=head1 DESCRIPTION

This module is XS implementation of matching IP addresses against Net ranges.
Using similar method to Net::IP::Match::Regexp in storing Net ranges into
memory. By implementing in XS C-code, and does not use regexp, more fast setup
time and less using memory.
This module is useful when Net ranges change often or reusing range data
won't be suitable.


=head1 METHODS

=over

=cut

=item new()

Create IP range object and initialize it.

=item $ipm->add( $net )

Add an Network address (xxx.xxx.xxx.xxx/mask) into the object. mask is 1 .. 32 CIDR mask bit value.

=item $cidr = $ipm->match_ip( $ip )

Searches matching $ip against previously setup networks. Returns matched
Network in CIDR format (xxx.xxx.xxx.xxx/mask). or undef unless matched.


=back

=head1 SEE ALSO

=head2 L<Net::IP::Match::Regexp>


=head1 AUTHOR

Tomo, E<lt>tomo at c-wind comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Tomo

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


=cut
