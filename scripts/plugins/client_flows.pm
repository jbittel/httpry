#!/usr/bin/perl -w

#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2007 Jason Bittel <jason.bittel@gmail.edu>
#

package client_flows;

use warnings;
use File::Basename;
use MIME::Lite;
use Socket qw(inet_ntoa inet_aton);
use Time::Local qw(timelocal);

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------
my $SENDMAIL     = "/usr/lib/sendmail -i -t";
my $FLOW_TIMEOUT = 300;
my $TAGGED_LIMIT = 15;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
# Counter variables
my $flow_cnt = 0;
my $flow_line_cnt = 0;
my $flow_min_len = 999999;
my $flow_max_len = 0;
my $tagged_flows_cnt = 0;
my $total_tagged_lines_cnt = 0;
my $max_concurrent = 0;

# Data structures
my %flow_info = ();       # Holds metadata about each flow
my %flow_data_lines = (); # Holds actual log file lines for each flow
my %tagged_lines = ();    # IP/flow/hostname information for tagged flows
my %tagged_flows = ();    # Pruned and cleaned tagged flows for display
my %history = ();         # Holds history of content checks to avoid matching
my @hitlist = ();         # List of content check keywords

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

        &delete_text_files();

        return 1;
}

sub main {
        my $self = shift;
        my $record = shift;
        my $curr_line;
        my $decoded_uri;

        # Make sure we really want to be here
        return unless (exists $record->{"direction"} && ($record->{"direction"} eq '>'));
        return unless exists $record->{"timestamp"};
        return unless exists $record->{"source-ip"};
        return unless exists $record->{"dest-ip"};
        return unless exists $record->{"host"};
        return unless exists $record->{"request-uri"};

        $decoded_uri = $record->{"request-uri"};
        $decoded_uri =~ s/%25/%/g; # Sometimes '%' chars are double encoded
        $decoded_uri =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;

        if ((keys %flow_info) > $max_concurrent) {
                $max_concurrent = keys %flow_info;
        }

        $curr_line = "$record->{'timestamp'}\t$record->{'source-ip'}\t$record->{'dest-ip'}\t$record->{'host'}\t$decoded_uri";

        # Convert timestamp of current record to epoch seconds
        $record->{"timestamp"} =~ /(\d\d)\/(\d\d)\/(\d\d\d\d) (\d\d)\:(\d\d)\:(\d\d)/;
        $epochstamp = timelocal($6, $5, $4, $2, $1 - 1, $3);

        &timeout_flows($epochstamp);

        # Begin a new flow if one doesn't exist
        if (!exists $flow_info{$record->{"source-ip"}}) {
                $flow_cnt++;

                $flow_info{$record->{"source-ip"}}->{"src_ip"} = $record->{"source-ip"};
                $flow_info{$record->{"source-ip"}}->{"start_time"} = $record->{"timestamp"};
                $flow_info{$record->{"source-ip"}}->{"length"} = 0;
                $flow_info{$record->{"source-ip"}}->{"tagged_lines"} = 0;
        }

        $flow_line_cnt++;

        $flow_info{$record->{"source-ip"}}->{"end_time"} = $record->{"timestamp"};
        $flow_info{$record->{"source-ip"}}->{"end_epoch"} = $epochstamp;
        $flow_info{$record->{"source-ip"}}->{"length"}++;

        push(@{$flow_data_lines{$record->{"source-ip"}}}, $curr_line);

        if ($hitlist_file && &content_check($record->{"host"}, $decoded_uri)) {
                $tagged_lines{$record->{"source-ip"}}->{$record->{"host"}}++;
                $flow_info{$record->{"source-ip"}}->{"tagged_lines"}++;
        }

        return;
}

sub end {
        &timeout_flows(0);
        &write_summary_file();
        &send_email() if $email_addr;

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
        if ($tagged_dir && !$hitlist_file) {
                print "Warning: -t requires -l, ignoring\n";
                $tagged_dir = 0;
        }

        # Read in option files
        if ($hitlist_file) {
                open(HITLIST, "$hitlist_file") or die "Error: Cannot open $hitlist_file: $!\n";
                        foreach (<HITLIST>) {
                                chomp;
                                next if /^#/; # Skip comments
                                push @hitlist, $_;
                        }
                close(HITLIST);
        }

        return 1;
}

# -----------------------------------------------------------------------------
# Remove text detail files to ensure they don't append between runs
# -----------------------------------------------------------------------------
sub delete_text_files {
        $tagged_dir =~ s/\/$//; # Remove trailing slash
        $all_dir =~ s/\/$//;    # ...

        if ($tagged_dir) {
                opendir(DIR, $tagged_dir) or die "Error: Cannot open directory $tagged_dir: $!\n";
                        foreach (grep /^tagged_.+\.txt$/, readdir(DIR)) {
                                unlink;
                        }
                closedir(DIR);
        }

        if ($all_dir) {
                opendir(DIR, $all_dir) or die "Error: Cannot open directory $all_dir: $!\n";
                        foreach (grep /^detail_.+\.txt$/, readdir(DIR)) {
                                unlink;
                        }
                closedir(DIR);
        }


        return;
}

# -----------------------------------------------------------------------------
# Search for specified content in the hostname and URI and return true if
# match occurs; store results of search in a (rudimentary) cache so we don't
# have to match the same text twice
#
# Potential hash values: -1 unmatched / 1 matched / 0 no match
# -----------------------------------------------------------------------------
sub content_check {
        my $hostname = shift;
        my $uri = shift;
        my $word;

        $hostname = quotemeta($hostname);
        $uri = quotemeta($uri);

        $history{$hostname} = -1 if (!defined $history{$hostname});
        $history{$uri} = -1 if (!defined $history{$uri});

        return 1 if (($history{$hostname} == 1) || ($history{$uri} == 1));
        return 0 if (($history{$hostname} == 0) && ($history{$uri} == 0));

        foreach $word (@hitlist) {
                if ($hostname =~ /$word/i) {
                        $history{$hostname} = 1;
                        return 1;
                }

                if ($uri =~ /$word/i) {
                        $history{$uri} = 1;
                        return 1;
                }
        }

        $history{$hostname} = 0;
        $history{$uri} = 0;

        return 0;
}

# -----------------------------------------------------------------------------
# Handle end of flow duties: flush to disk and delete hash entries; passing an
# epochstamp value causes all flows inactive longer than $FLOW_TIMEOUT to be
# flushed, while passing a zero forces all active flows to be flushed
# -----------------------------------------------------------------------------
sub timeout_flows {
        my $epochstamp = shift;
        my $flow_str;
        my $ip;
        my $hostname;

        foreach $ip (keys %flow_info) {
                if ($epochstamp) {
                        next unless (($epochstamp - $flow_info{$ip}->{"end_epoch"}) > $FLOW_TIMEOUT);
                }

                # Update minimum/maximum flow length as necessary
                $flow_min_len = $flow_info{$ip}->{"length"} if ($flow_info{$ip}->{"length"} < $flow_min_len);
                $flow_max_len = $flow_info{$ip}->{"length"} if ($flow_info{$ip}->{"length"} > $flow_max_len);

                &append_host_subfile("$all_dir/detail_$ip.txt", $ip) if $all_dir;

                # Check if we have enough hits to be interested in the flow
                if ($flow_info{$ip}->{"tagged_lines"} > $TAGGED_LIMIT) {
                        $tagged_flows_cnt++;
                        $total_tagged_lines_cnt += $flow_info{$ip}->{"tagged_lines"};

                        # Copy data to output hash so we can prune and reformat
                        $flow_str = "[$flow_info{$ip}->{'start_time'}]->[$flow_info{$ip}->{'end_time'}]";
                        $tagged_flows{$ip}->{$flow_str} = $tagged_lines{$ip};

                        &append_host_subfile("$tagged_dir/tagged_$ip.txt", $ip) if $tagged_dir;
                }

                delete $tagged_lines{$ip};
                delete $flow_info{$ip};
                delete $flow_data_lines{$ip};
        }

        return;
}

# -----------------------------------------------------------------------------
# Write detail subfile for specified client IP
# -----------------------------------------------------------------------------
sub append_host_subfile {
        my $path = shift;
        my $ip = shift;
        my $line;

        open(HOSTFILE, ">>$path") or die "Error: Cannot open $path: $!\n";

        print HOSTFILE '>' x 80 . "\n";
        foreach $line (@{$flow_data_lines{$ip}}) {
                print HOSTFILE $line, "\n";
        }
        print HOSTFILE '<' x 80 . "\n";

        close(HOSTFILE);

        return;
}

# -----------------------------------------------------------------------------
# Write summary information to specified output file
# -----------------------------------------------------------------------------
sub write_summary_file {
        my $ip;
        my $flow;
        my $hostname;

        open(OUTFILE, ">$output_file") or die "Error: Cannot open $output_file: $!\n";

        print OUTFILE "\n\nCLIENT FLOWS SUMMARY\n\n";
        print OUTFILE "Generated:      " . localtime() . "\n";
        print OUTFILE "Flow count:     $flow_cnt\n";
        print OUTFILE "Flow lines:     $flow_line_cnt\n";
        if ($flow_cnt > 0) {
                print OUTFILE "Max Concurrent: $max_concurrent\n";
                print OUTFILE "Min/Max/Avg:    $flow_min_len/$flow_max_len/" . sprintf("%d", $flow_line_cnt / $flow_cnt) . "\n";
        }

        if ($hitlist_file) {
                print OUTFILE "Tagged IPs:     " . (keys %tagged_flows) . "\n";
                print OUTFILE "Tagged flows:   $tagged_flows_cnt\n";
                print OUTFILE "Tagged lines:   $total_tagged_lines_cnt\n";
                print OUTFILE "\n\nCLIENT FLOWS CONTENT CHECKS\n";
                print OUTFILE "FILTER FILE: $hitlist_file\n\n";

                if ($tagged_flows_cnt == 0) {
                        print OUTFILE "*** No tagged flows found\n";
                        close(OUTFILE);
                        
                        return;
                }

                foreach $ip (map { inet_ntoa $_ }
                             sort
                             map { inet_aton $_ } keys %tagged_flows) {
                        print OUTFILE "$ip\n";

                        foreach $flow (sort keys %{$tagged_flows{$ip}}) {
                                print OUTFILE "\t$flow\n";

                                foreach $hostname (sort keys %{$tagged_flows{$ip}->{$flow}}) {
                                        print OUTFILE "\t\t($tagged_flows{$ip}->{$flow}->{$hostname})\t$hostname\n";
                                }
                        }
                        print OUTFILE "\n";
                }
        }

        close(OUTFILE);

        return;
}

# -----------------------------------------------------------------------------
# Send email to specified address and attach output file
# -----------------------------------------------------------------------------
sub send_email {
        my $msg;
        my $output_filename = basename($output_file);

        $msg = MIME::Lite->new(
                From    => 'noreply@example.com',
                To      => "$email_addr",
                Subject => 'httpry Content Check Report - ' . localtime(),
                Type    => 'multipart/mixed'
        );

        $msg->attach(
                Type => 'TEXT',
                Data => 'httpry content check report for ' . localtime()
        );

        $msg->attach(
                Type        => 'TEXT',
                Path        => "$output_file",
                Filename    => "$output_filename",
                Disposition => 'attachment'
        );

        $msg->send('sendmail', $SENDMAIL) or die "Error: Cannot send mail: $!\n";

        return;
}

1;
