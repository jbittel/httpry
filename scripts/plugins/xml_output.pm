#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
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

main::register_plugin();

sub new {
        return bless {};
}

sub init {
        my $self = shift;
        my $cfg_dir = shift;

        _load_config($cfg_dir);

        if (-e $output_file) {
                open OUTFILE, ">>$output_file" or die "Cannot open $output_file: $!\n";
                print OUTFILE "<flow version=\"$flow_version\" xmlversion=\"$xml_version\">\n";
        } else {
                open OUTFILE, ">$output_file" or die "Cannot open $output_file: $!\n";
                print OUTFILE "<?xml version=\"1.0\"?>\n";
                print OUTFILE "<?xml-stylesheet href=\"xml_output.css\" type=\"text/css\"?>\n";
                print OUTFILE "<flow version=\"$flow_version\" xmlversion=\"$xml_version\">\n";
        }

        $fh = *OUTFILE;

        return;
}

sub main {
        my $self = shift;
        my $record = shift;
        my $field;
        my $data;

	print $fh "<record>";
        foreach $field (keys %$record) {
                $data = $record->{$field};

                $data =~ s/^\s+//;
                $data =~ s/\s+$//;
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
        close $fh or die "Cannot close $fh: $!\n";

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
