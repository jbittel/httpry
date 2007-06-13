#!/usr/bin/perl -w

#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2007 Jason Bittel <jason.bittel@gmail.edu>
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

&main::register_plugin(__PACKAGE__);

sub new {
        return bless {};
}

sub init {
        my $self = shift;
        my $plugin_dir = shift;

        if (&load_config($plugin_dir) == 0) {
                return 0;
        }

        return 1;
}

sub main {
        my $self   = shift;
        my $record = shift;
        my $hostname;

        # Make sure we really want to be here
        return unless (exists $record->{"direction"} && ($record->{"direction"} eq '>'));
        return unless exists $record->{"host"};

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

        $hostnames{$hostname} = "" unless exists($hostnames{$hostname});

        return;
}

sub end {
        my $host;

        open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";
        
        foreach $host (keys %hostnames) {
                print OUTFILE "$host\n";
        }

        close(OUTFILE);

        return;
}

# -----------------------------------------------------------------------------
# Load config file and check for required options
# -----------------------------------------------------------------------------
sub load_config {
        my $plugin_dir = shift;

        # Load config file; by default in same directory as plugin
        if (-e "$plugin_dir/" . __PACKAGE__ . ".cfg") {
                require "$plugin_dir/" . __PACKAGE__ . ".cfg";
        }

        # Check for required options and combinations
        if (!$output_file) {
                print "Error: No output file provided\n";
                return 0;
        }

        return 1;
}

1;
