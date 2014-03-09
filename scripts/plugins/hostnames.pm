#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
#

package hostnames;

use warnings;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %hostnames = ();

# -----------------------------------------------------------------------------
# Plugin core
# -----------------------------------------------------------------------------

main::register_plugin();

sub new {
        return bless {};
}

sub init {
        my $self = shift;
        my $cfg_dir = shift;

        _load_config($cfg_dir);

        return;
}

sub list {
        return qw(direction host);
}

sub main {
        my $self = shift;
        my $record = shift;
        my $hostname;

        return unless $record->{"direction"} eq '>';

        $hostname = $record->{"host"};
        $hostname =~ s/[^\-\.:0-9A-Za-z]//g;

        # Eliminate invalid hostnames and online services
        return if ($hostname eq "");
        return if ($hostname eq "-");
        return if ($hostname =~ /^ads?\d*?\./);
        return if ($hostname =~ /^proxy/);
        return if ($hostname =~ /^redir/);
        return if ($hostname =~ /^liveupdate/);
        return if ($hostname =~ /^anti-phishing/);
        return if ($hostname =~ /^stats/);
        return if ($hostname =~ /^photos/);
        return if ($hostname =~ /^images/);
        return if ($hostname =~ /^myspace/);

        # Only allow hostnames of the forms: a.b, a.b.c, a.b.c.d (with optional port)
        return unless ($hostname =~ /^([\-\w]+?\.){1,3}[\-\w]+?(:\d+?)??$/);

        $hostnames{$hostname}++;

        return;
}

sub end {
        my $host;

        open OUTFILE, ">$output_file" or die "Cannot open $output_file: $!\n";

        foreach $host (keys %hostnames) {
                print OUTFILE "$hostnames{$host}\t$host\n";
        }

        close OUTFILE or die "Cannot close $output_file: $!\n";

        return;
}

# -----------------------------------------------------------------------------
# Load config file and check for required options
# -----------------------------------------------------------------------------
sub _load_config {
        my $cfg_dir = shift;

        # Load config file; by default in same directory as plugin
        if (-e "$cfg_dir/" . __PACKAGE__ . ".cfg") {
                require "$cfg_dir/" . __PACKAGE__ . ".cfg";
        } else {
                die "No config file found\n";
        }

        # Check for required options and combinations
        if (!$output_file) {
                die "No output file provided\n";
        }

        return;
}

1;
