#!/usr/bin/perl -w

#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2007 Jason Bittel <jason.bittel@gmail.com>
#

package find_proxies;

use warnings;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $PRUNE_LIMIT = 20;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %proxy_lines = ();

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

        &process_data($record);

        return;
}

sub end {
        &prune_hits();
        &write_output_file();

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
        $prune_limit = $PRUNE_LIMIT unless ($prune_limit > 0);

        return 1;
}

# -----------------------------------------------------------------------------
# Handle each line of data
# -----------------------------------------------------------------------------
sub process_data {
        my $record = shift;
        my $word;
        my $len;
        my $encoded_uri;
        my $decoded_uri = "";
        my $request_uri;

        # Make sure we really want to be here
        return unless (exists $record->{"direction"} && ($record->{"direction"} eq '>'));
        return unless exists $record->{"request-uri"};
        return unless exists $record->{"source-ip"};
        return unless exists $record->{"host"};

        $request_uri = $record->{"request-uri"};
        $request_uri =~ s/%25/%/g; # Sometimes '%' chars are double encoded
        $request_uri =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;

        # Perform hostname and uri keyword search
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

# -----------------------------------------------------------------------------
# Remove hits from results tree that are below our level of interest
# -----------------------------------------------------------------------------
sub prune_hits {
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
sub write_output_file {
        my $ip;
        my $hostname;
        my $domain;
        my %counts;
        my %output;

        open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";

        print OUTFILE "\n\nPOTENTIAL PROXIES\n\n";
        print OUTFILE "Generated: " . localtime() . "\n\n\n";

        if ((keys %proxy_lines) == 0) {
                print OUTFILE "*** No potential proxies found\n";
                close(OUTFILE);

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

                        push(@{$output{$domain}->{$hostname}}, $ip);
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
                print OUTFILE "\n\n";
        }

        close(OUTFILE);

        return;
}

1;
