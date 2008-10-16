#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2008 Jason Bittel <jason.bittel@gmail.com>
#

package tokenize;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %terms = ();

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

        return 0;
}

sub main {
        my $self = shift;
        my $record = shift;
        my $line;
        my $decoded_uri;

        return unless exists $record->{"host"};
        return unless exists $record->{"request-uri"};
        return unless (exists $record->{"source-ip"} && ($record->{'source-ip'} =~ /^(?:\d+)(?:\.\d+){3}$/));

        $decoded_uri = $record->{"request-uri"};
        $decoded_uri =~ s/%25/%/g; # Sometimes '%' chars are double encoded
        $decoded_uri =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;

        $line = "$record->{'host'}$decoded_uri";

        foreach my $term (split /[^A-Za-z0-9]/, $line) {
                next if !$term;
                next if (length($term) <= 2);
                next if $term =~ /^\d+$/; # Ignore numbers
                next if (exists $stopwords{$term});

                $terms{$record->{'source-ip'}}->{$term}++;
        }

        return;
}

sub end {
        my $ip;
        my $term;
        my $i;

        # TODO: This could use more control over the output style and format
        foreach $ip (keys %terms) {
                open(OUT, ">$output_dir/terms_$ip.txt") or
                        die "Error: Cannot open $output_dir/terms_$ip.txt: $!\n";

                foreach $term (keys %{ $terms{$ip} }) {
                        for ($i = 0; $i < $terms{$ip}->{$term}; $i++) {
                                print OUT "$term ";
                        }

                        print OUT "\n";
                }

                close(OUT);
        }

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
