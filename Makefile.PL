use 5.005;
use ExtUtils::MakeMaker;

my $DEFS = '';
if ($^O =~ /solaris/i) {
    $DEFS .= " -DSOLARIS";
}
my $pv = $] * 1000000;
$DEFS .= " -DPVER=$pv";

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Net::IP::Match::Bin',
    VERSION_FROM      => 'lib/Net/IP/Match/Bin.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Net/IP/Match/Bin.pm', # retrieve abstract from module
       AUTHOR         => 'Tomo <tomo_at_c-wind.com>') : ()),
    LIBS              => [''], # e.g., '-lm'
    DEFINE            => "$DEFS", # e.g., '-DHAVE_SOMETHING'
    INC               => '-I.', # e.g., '-I. -I/usr/include/other'
	# Un-comment this if you add C files to link with later:
    # OBJECT            => '$(O_FILES)', # link all the C files too
);
