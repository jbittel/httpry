#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
#

package find_proxies;

use warnings;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my $PRUNE_LIMIT = 20;
my %proxy_lines = ();

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
        return qw(direction source-ip host request-uri);
}

sub main {
        my $self = shift;
        my $record = shift;
        my $word;
        my $len;
        my $encoded_uri;
        my $decoded_uri = "";
        my $request_uri;

        return unless $record->{"direction"} eq '>';

        $request_uri = $record->{"request-uri"};
        $request_uri =~ s/%(?:25)+/%/g;
        $request_uri =~ s/%([a-fA-F0-9][a-fA-F0-9])/chr(hex($1))/eg;

        # Perform hostname and URI keyword search
        foreach $word (@proxy_keywords) {
                if ($record->{"host"} =~ /$word/i) {
                        $proxy_lines{$record->{"source-ip"}}->{$record->{"host"}}++;
                        return;
                }

                if ($request_uri =~ /$word/i) {
                        $proxy_lines{$record->{"source-ip"}}->{$record->{"host"}}++;
                        return;
                }
        }

        # Perform URI embedded request search; this works, but appears
        # to generate too many false positives to be useful as is
        if ($request_uri =~ /(\.pl|\.php|\.asp).*http:\/\/[^\/:]+/) {
                $proxy_lines{$record->{"source-ip"}}->{$record->{"host"}}++;
                return;
        }

        # Third time's the charm; do a base 64 decode of the URI and
        # search again for an embedded request
        if ($request_uri =~ /(\.pl|\.php|\.asp).*=(.+?)(?:\&|\Z)/) {
                $encoded_uri = $2;

                $encoded_uri =~ tr|A-Za-z0-9+=/||cd;
                return if (length($encoded_uri) % 4);

                $encoded_uri =~ s/=+$//;
                $encoded_uri =~ tr|A-Za-z0-9+/| -_|;

                while ($encoded_uri =~ /(.{1,60})/gs) {
                	$len = chr(32 + length($1)*3/4);
                 	$decoded_uri .= unpack("u", $len . $1);
                }

                if ($decoded_uri =~ /http:\/\/[^\/:]+/) {
                        $proxy_lines{$record->{"source-ip"}}->{$record->{"host"}}++;
                        return;
                }
        }

        return;
}

sub end {
        _prune_hits();
        _write_output_file();

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
        $prune_limit = $PRUNE_LIMIT unless ($prune_limit > 0);

        return;
}

# -----------------------------------------------------------------------------
# Remove hits from results tree that are below our level of interest
# -----------------------------------------------------------------------------
sub _prune_hits {
        my $ip;
        my $hostname;

        foreach $ip (keys %proxy_lines) {
                # Delete individual hostnames/counts that are below the limit
                foreach $hostname (keys %{$proxy_lines{$ip}}) {
                        if ($proxy_lines{$ip}->{$hostname} < $prune_limit) {
                                delete $proxy_lines{$ip}->{$hostname};
                        }
                }

                # If all hostnames were deleted, remove the empty IP
                unless (keys %{$proxy_lines{$ip}}) {
                        delete $proxy_lines{$ip};
                }
        }

        return;
}

# -----------------------------------------------------------------------------
# Write collected information to specified output file
# -----------------------------------------------------------------------------
sub _write_output_file {
        my $ip;
        my $hostname;
        my $domain;
        my %counts;
        my %output;

        open OUTFILE, ">$output_file" or die "Cannot open $output_file: $!\n";

        print OUTFILE "\n\nPOTENTIAL PROXIES\n\n";
        print OUTFILE "Generated: " . localtime() . "\n\n\n";

        if ((keys %proxy_lines) == 0) {
                print OUTFILE "*** No potential proxies found\n";
                close OUTFILE or die "Cannot close $output_file: $!\n";

                return;
        }

        # Reformat data hash into a formatted output hash, clustering by domain name
        foreach $ip (keys %proxy_lines) {
                foreach $hostname (keys %{$proxy_lines{$ip}}) {
                        # Attempt to cluster data by domain
                        if (($hostname =~ /\.([^\.]+?\.[^\.]+?)$/) && !($hostname =~ /\d+\.\d+\.\d+\.\d+/)) {
                                $domain = $1;
                        } else {
                                $domain = $hostname;
                        }

                        push @{$output{$domain}->{$hostname}}, $ip;
                        $counts{$hostname} += $proxy_lines{$ip}->{$hostname};
                }
        }

        # Print output hash data to file
        foreach $domain (sort keys %output) {
                foreach $hostname (sort keys %{$output{$domain}}) {
                        print OUTFILE "($counts{$hostname}) $hostname\n\t[ ";

                        foreach $ip (@{$output{$domain}->{$hostname}}) {
                                print OUTFILE "$ip ";
                        }
                        print OUTFILE "]\n";
                }
                print OUTFILE "\n";
        }

        close OUTFILE or die "Cannot close $output_file: $!\n";

        return;
}

1;
