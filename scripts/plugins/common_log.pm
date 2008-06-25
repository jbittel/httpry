#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2008 Jason Bittel <jason.bittel@gmail.com>
#

package common_log;

use POSIX qw(strftime);

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
%requests = ();
$request_num = 0;

my @months = (qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec)); 

# -----------------------------------------------------------------------------
# Plugin core
# -----------------------------------------------------------------------------

&main::register_plugin();

sub new {
        return bless {};
}

sub init {
        my $self = shift;
        my $cfg_dir = shift;

        if (&load_config($cfg_dir)) {
                return 1;
        }

        # TODO: write output information to a log file

        return 0;
}

sub main {
        my $self = shift;
        my $record = shift;
        my $line;

        return unless exists $record->{'direction'};
        return unless exists $record->{'source-ip'};
        return unless exists $record->{'dest-ip'};

        if ($record->{'direction'} eq '>') {
                $request_num++;
                $line = "";

                # Build host field
                if (exists $record->{'host'}) {
                        $line .= $record->{'host'};
                } else {
                        $line .= $record->{'dest-ip'};
                }

                # Append ident and authuser fields
                $line .= " - - ";

                # Append date field
                # TODO: actually pull these dates from the log
                my ($sec, $min, $hour, $mday, $mon, $year) = localtime(time);
                my $tz_offset = strftime("%z",localtime(time));
                $line .= sprintf("[%02d/%3s/%04d:%02d:%02d:%02d %5s]", $mday, $months[$mon], $year+1900, $hour, $min, $sec, $tz_offset);

                # Append request field
                $line .= " \"$record->{'method'} $record->{'request-uri'} $record->{'http-version'}\"";

                # Append status code and byte count
                $line .= " - -";

                print "$line\n";
#                $requests{$requests->{'source-ip'}_$requests->{'dest-ip'}}->{$request_num} = 

        # TODO: match requests with responses to add the response code
        } elsif ($record->{'direction'} eq '<') {

        }

        return;
}

sub end {

        return;
}

sub start_request {

        return;
}

sub find_request {

        return;
}

sub finish_request {

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
                warn "Error: No config file found\n";
                return 1;
        }

        $output_dir = "." if (!$output_dir);
        $output_dir =~ s/\/$//; # Remove trailing slash

        return 0;
}

1;
