
use Test::More tests => 3;
use Net::IP::Match::Bin;

my $ipm = Net::IP::Match::Bin->new();

my $rv = $ipm->add("10.200.1.0/25");
ok($rv, "add scalar");

$rv = $ipm->add("10.100.0.0/16", "100.1.1.0/24");
ok($rv, "add multi");

my %ent = ("222.222.222.0/16" => "Spam",
		"202.202.202.0/16" => "another spam");

$rv = $ipm->add(\%ent);
ok($rv, "add map");
