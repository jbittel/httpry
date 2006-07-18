#!/usr/bin/perl -w

#
# find_proxies.pm | created: 4/3/2006
#
# Copyright (c) 2006, Jason Bittel <jbittel@corban.edu>. All rights reserved.
# See included LICENSE file for specific licensing information
#

package find_proxies;

use File::Basename;
use MIME::Lite;
use Socket qw(inet_ntoa inet_aton);

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $SENDMAIL    = "/usr/lib/sendmail -i -t";
my $PATTERN     = "\t";
my $PRUNE_LIMIT = 15;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my ($timestamp, $src_ip, $dst_ip, $hostname, $uri);
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
        my $self = shift;
        my $data = shift;

        &process_data($data);

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
                print "Error: no output file provided\n";
                return 0;
        }
        $prune_limit = $PRUNE_LIMIT unless ($prune_limit > 0);

        return 1;
}

# -----------------------------------------------------------------------------
# Handle each line of data
# -----------------------------------------------------------------------------
sub process_data {
        my $curr_line = shift;
        my ($timestamp, $src_ip, $dst_ip, $direction, $method, $hostname, $uri);
        my $word;

        # Strip non-printable chars
        $curr_line =~ tr/\x80-\xFF//d;

        # Convert hex characters to ASCII
        $curr_line =~ s/%25/%/g; # Sometimes '%' chars are double encoded
        $curr_line =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;

        ($timestamp, $src_ip, $dst_ip, $direction, $method, $hostname, $uri) = split(/$PATTERN/, $curr_line);
        return if $direction ne '>';
        return if (!$src_ip or !$hostname or !$uri); # Malformed line

        # Perform hostname and uri keyword search
        foreach $word (@proxy_keywords) {
                if ($hostname =~ /$word/i) {
                        $proxy_lines{$src_ip}->{$hostname}++;
                        return;
                }

                if ($uri =~ /$word/i) {
                        $proxy_lines{$src_ip}->{$hostname}++;
                        return;
                }
        }

        # Perform uri embedded request search; this works, but appears
        # to generate too many false positives to be useful as is
        if ($uri =~ /(\.pl|\.php|\.asp).*http:\/\/[^\/:]+/) {
                $proxy_lines{$src_ip}->{$hostname}++;
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
        my $count = 0;

        open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";

        print OUTFILE "\n\nPOTENTIAL PROXIES\n\n";
        print OUTFILE "Generated:\t" . localtime() . "\n";
        print OUTFILE "\n\n";

        if ((keys %proxy_lines) == 0) {
                print OUTFILE "No potential proxies found\n";
        } else {
                foreach $ip (map { inet_ntoa $_ }
                             sort
                             map { inet_aton $_ } keys %proxy_lines) {
                        print OUTFILE "$ip\n";

                        foreach $hostname (sort keys %{$proxy_lines{$ip}}) {
                                print OUTFILE "\t$hostname\t$proxy_lines{$ip}->{$hostname}\n";
                        }
                        print OUTFILE "\n";
                }
        }

        close(OUTFILE);

        return;
}

1;
