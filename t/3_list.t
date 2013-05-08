
use Test::More tests => 1;
use Net::IP::Match::Bin;

my $ipm = Net::IP::Match::Bin->new();

my %ent = ("222.222.222.0/25" => "Spam",
		"202.202.202.0/16" => "another spam");
my $rv = $ipm->add(\%ent);

$ipm->add("10.1.0.0/17");

$ipm->add_range("100.200.40.23- 100.200.50.1");

my @a = sort $ipm->list;
my $res = pop(@a);
ok(($res eq "222.222.222.0/25"), "list");

