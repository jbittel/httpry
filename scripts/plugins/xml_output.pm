#!/usr/bin/perl -w

#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2008 Jason Bittel <jason.bittel@gmail.com>
#

package xml_output;

use warnings;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my $fh;

# -----------------------------------------------------------------------------
# Plugin core
# -----------------------------------------------------------------------------

&main::register_plugin(__PACKAGE__);

sub new {
        return bless {};
}

sub init {
        my $self = shift;
        my $cfg_dir = shift;

        if (&load_config($cfg_dir) == 0) {
                return 0;
        }

        if (-e $output_file) {
                open(OUTFILE, ">>$output_file") or die "Error: Cannot open $output_file: $!\n";
                print OUTFILE "<flow version=\"$flow_version\" xmlversion=\"$xml_version\">\n";
        } else {
                open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";
                print OUTFILE "<?xml version=\"1.0\"?>\n";
                print OUTFILE "<?xml-stylesheet href=\"xml_output.css\" type=\"text/css\"?>\n";
                print OUTFILE "<flow version=\"$flow_version\" xmlversion=\"$xml_version\">\n";
        }

        $fh = *OUTFILE;

        return 1;
}

sub main {
        my $self   = shift;
        my $record = shift;
        my $direction;
        my $request_uri;

	print $fh "<record>";
        foreach my $field (keys %$record) {
                my $data = $record->{$field};

                $data =~ s/&/\&amp\;/g;
                $data =~ s/</\&lt\;/g;
                $data =~ s/>/\&gt\;/g;
                $data =~ s/\'/\&apos\;/g;
                $data =~ s/\"/\&quot\;/g;

                print $fh "<$field>$data</$field>";
        }
        print $fh "</record>\n";

        return;
}

sub end {
        print $fh "</flow>\n";
        close($fh);

        return;
}

# -----------------------------------------------------------------------------
# Load config file and check for required options
# -----------------------------------------------------------------------------
sub load_config {
        my $cfg_dir = shift;

        # Load config file; by default in same directory as plugin
        if (-e "$cfg_dir/" . __PACKAGE__ . ".cfg") {
                require "$cfg_dir/" . __PACKAGE__ . ".cfg";
        } else {
                print "Error: No config file found\n";
                return 0;
        }

        # Check for required options and combinations
        if (!$output_file) {
                print "Error: No output file provided\n";
                return 0;
        }

        return 1;
}

1;
