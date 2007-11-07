use 5.008;
use ExtUtils::MakeMaker;
use Data::Dumper;

my $PERL_CRYPT_LIB_HEADER = undef;
while ( !($PERL_CRYPT_LIB_HEADER = `cat ./.cl_h 2>/dev/null`) ) {
	die "Installation aborted!\n\n" if system("./configure");
};

WriteMakefile(
	 'NAME'				=>	'PerlCryptLib'
	,'DISTNAME'			=>	'PerlCryptLib'
	,'VERSION_FROM'		=>	'PerlCryptLib.pm'
	,'PREREQ_PM'		=>	{ }
    ,'PM'            	=>	{ 
								 'PerlCryptLib.pm' => '$(INST_LIBDIR)/PerlCryptLib.pm'
								,'PerlCryptLib.ph' => '$(INST_LIBDIR)/PerlCryptLib.ph'
							}
 	,(
		$] >= 5.005 ?
							(
								 ABSTRACT	=> 'PerlCryptLib - Perl interface to Peter Guttman\'s cryptlib API'
								,AUTHOR		=> 'Alvaro Livraghi <perlcryptlib@gmail.com>'
							) : 
							()
	 ),
	,'LIBS'				=>	[ join(" ", map { "-L$_" } split ":", $ENV{LD_LIBRARY_PATH}) . ' -lresolv -lpthread -lcl' ]
	,'DEFINE'			=>	"-DCRYPTLIB_H=\\\"$PERL_CRYPT_LIB_HEADER\\\""
	,'INC'				=>	'-I.'
	,'clean'			=>	{
								FILE	=> '*.ph .*_h'
							}
	,'realclean'		=>	{
								FILES	=> '*.ph .*_h *.inc'
							}
);

if  (eval {require ExtUtils::Constant; 1}) {

	my @names = ();
	ExtUtils::Constant::WriteConstants	(
											 NAME         => 'PerlCryptLib'
											,NAMES        => \@names
											,DEFAULT_TYPE => 'IV'
											,C_FILE       => 'const-c.inc'
											,XS_FILE      => 'const-xs.inc'
										);
	print join("\n", @names), "\n";

} else {

	use File::Copy;
	use File::Spec;
	foreach my $file ('const-c.inc', 'const-xs.inc') {
		my $fallback = File::Spec->catfile('fallback', $file);
		copy ($fallback, $file) or die "Can't copy $fallback to $file: $!";
	}

}
