#!/usr/bin/perl -w

#
# sample_plugin.pm | created: 4/3/2006
#
# Copyright (c) 2006, Jason Bittel <jbittel@corban.edu>. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the author nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

#
# This is an example plugin for the perl parse script parse_log.pl.  It shows
# the basic structure of a simple plugin and provides a good starting point for
# writing a custom plugin. Some of the other included plugins will also provide
# a good idea of how the different pieces work.
#

package sample_plugin;

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# GLOBAL VARIABLES
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Plugin core
# -----------------------------------------------------------------------------

# On initialization, this call registers the plugin with the core
&main::register_plugin(__PACKAGE__);

# This sub is called once at initialization to create the plugin object
sub new {
        return bless {};
}

# This sub is called once at initialization; all startup code should be
# included here. Currently this sub only loads the configuration file, but
# any startup specific code or subs are handled here.
sub init {
        my $self = shift;
        my $plugin_dir = shift;

        # Call our load configuration sub; this can be good to break out
        # into a separate sub like this, particularly if you end up with
        # many checks on the config variables.
        if (&load_config($plugin_dir) == 0) {
                return 0;
        }

        return 1;
}

# This sub is called once for each data line in the input file(s). Note
# that the data is sent here as a single line and so must be parsed (if
# necessary) to act on individual components of the line.
sub main {
        my $self   = shift;
        my $record = shift; # Reference to hash containing record data

        # Simple processing can be handled here; more complex processing
        # would probably be better handled in a different sub.

        return;
}

# This sub is called once at program termination; all shutdown code (i.e.
# closing files, deleting temp files, sending email, etc) should be
# included here.
sub end {

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

        # Check for required options and combinations from the configuration
        # file variables. This can also be a good place to do file reads for
        # initializing run time data structures.

        return 1;
}

1;
