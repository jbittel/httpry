#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
#

package common_log;

use POSIX qw(strftime mktime);

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %requests = ();
my $fh;

my @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);

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

        open OUTFILE, ">$output_file" or die "Cannot open $output_file: $!\n";
        $fh = *OUTFILE;

        return;
}

sub list {
        return qw(direction source-ip dest-ip);
}

sub main {
        my $self = shift;
        my $record = shift;
        my $line = "";
        my $line_suffix;
        my ($sec, $min, $hour, $mday, $mon, $year);
        my $tz_offset;

        if ($record->{'direction'} eq '>') {
                return unless exists $record->{'timestamp'};
                return unless exists $record->{'method'};
                return unless exists $record->{'request-uri'};
                return unless exists $record->{'http-version'};

                # Build the output line: begin with client (remote host) address
                $line .= $record->{'source-ip'};

                # Append ident and authuser fields
                # NOTE: we use the ident field to display the
                # hostname/ip of the destination site
                if (exists $record->{'host'}) {
                        $line .= " $record->{'host'} - ";
                } else {
                        $line .= " $record->{'dest-ip'} - ";
                }

                # Append date field
                $record->{'timestamp'} =~ /(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})/;
                ($sec, $min, $hour, $mday, $mon, $year) = ($6, $5, $4, $3, $2-1, $1-1900);
                # NOTE: We assume the current timezone here; that may not always be accurate, but
                # timezone data is not stored in the httpry log files
                $tz_offset = strftime("%z", localtime(mktime($sec, $min, $hour, $mday, $mon, $year)));
                $line .= sprintf("[%02d/%3s/%04d:%02d:%02d:%02d %5s]", $mday, $months[$mon], $year+1900, $hour, $min, $sec, $tz_offset);

                # Append request fields
                $line .= " \"$record->{'method'} $record->{'request-uri'} $record->{'http-version'}\"";

                if ($combined_format) {
                        # Append referer
                        if (exists $record->{'referer'}) {
                                $line .= "\t \"$record->{'referer'}\"";
                        } else {
                                $line .= "\t \"-\"";
                        }

                        # Append user agent string
                        if (exists $record->{'user-agent'}) {
                                $line .= " \"$record->{'user-agent'}\"";
                        } else {
                                $line .= " \"-\"";
                        }
                }

                if ($ignore_response) {
                        print $fh "$line - -\n";
                } else {
                        push(@{ $requests{"$record->{'source-ip'}$record->{'dest-ip'}"} }, $line);
                }
        } elsif ($record->{'direction'} eq '<') {
                # NOTE: This is a bit naive, but functional. Basically we match a request with the
                # next response from that IP pair in the log file. This means that under busy
                # conditions the response could be matched to the wrong request but currently there
                # isn't a more accurate way to tie them together.
                if (exists $requests{"$record->{'dest-ip'}$record->{'source-ip'}"}) {
                        $line = shift(@{ $requests{"$record->{'dest-ip'}$record->{'source-ip'}"} });
                        return unless $line;

                        if (! @{ $requests{"$record->{'dest-ip'}$record->{'source-ip'}"} }) {
                                delete $requests{"$record->{'dest-ip'}$record->{'source-ip'}"};
                        }
                } else {
                        return;
                }

                ($line, $line_suffix) = split /\t/, $line, 2 if $combined_format;

                # Append status code
                if (exists $record->{'status-code'}) {
                        $line .= " $record->{'status-code'}";
                } else {
                        $line .= " -";
                }

                # Append byte count
                if (exists $record->{'content-length'}) {
                        $line .= " $record->{'content-length'}";
                } else {
                        $line .= " -";
                }

                $line .= $line_suffix if $combined_format;

                print $fh "$line\n";
        }

        return;
}

sub end {
        # TODO: Print lines that don't have a matching response?

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

        $output_dir = "." if (!$output_dir);
        $output_dir =~ s/\/$//; # Remove trailing slash

        return;
}

1;
