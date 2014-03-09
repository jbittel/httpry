#
#  ----------------------------------------------------
#  httpry - HTTP logging and information retrieval tool
#  ----------------------------------------------------
#
#  Copyright (c) 2005-2014 Jason Bittel <jason.bittel@gmail.com>
#

package tokenize;

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------
my %terms = ();

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
        return qw(source-ip host request-uri);
}

sub main {
        my $self = shift;
        my $record = shift;
        my $decoded_uri;

        return unless $record->{'source-ip'} =~ /^(?:\d+)(?:\.\d+){3}$/;

        $decoded_uri = $record->{"request-uri"};
        $decoded_uri =~ s/%(?:25)+/%/g;
        $decoded_uri =~ s/%([a-fA-F0-9][a-fA-F0-9])/chr(hex($1))/eg;

        foreach my $term (split /[^A-Za-z0-9]/, "$record->{'host'}$decoded_uri") {
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
                open OUTFILE, ">$output_dir/terms_$ip.txt" or
                        die "Cannot open $output_dir/terms_$ip.txt: $!\n";

                foreach $term (keys %{ $terms{$ip} }) {
                        for ($i = 0; $i < $terms{$ip}->{$term}; $i++) {
                                print OUTFILE "$term ";
                        }

                        print OUTFILE "\n";
                }

                close OUTFILE or die "Cannot close $output_dir/terms_$ip.txt: $!\n";
        }

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

        $output_dir = "." if (!$output_dir);
        $output_dir =~ s/\/$//; # Remove trailing slash

        return;
}

1;
