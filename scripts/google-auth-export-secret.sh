#!/bin/sh
exec perl -x "$0" "$@"
#!perl
use strict;
use warnings;

use Getopt::Long qw(GetOptions);
use JSON::PP qw(encode_json);
use MIME::Base64 qw(decode_base64);
use URI::Escape qw(uri_unescape);

sub usage {
    return <<'EOF';
Usage:
  ./scripts/google-auth-export-secret.sh [--list|--json] [--index N] [--issuer NAME] [--account NAME] <source>
  echo '<source>' | ./scripts/google-auth-export-secret.sh

Source can be one of:
  - full otpauth-migration://offline?... URL
  - raw data=... fragment
  - raw URL-encoded base64 payload
EOF
}

sub read_varint {
    my ($buf, $offset_ref) = @_;
    my $value = 0;
    my $shift = 0;

    while (1) {
        die "unexpected end of protobuf while reading varint\n"
          if $$offset_ref >= length($buf);
        my $byte = ord(substr($buf, $$offset_ref, 1));
        $$offset_ref += 1;
        $value |= (($byte & 0x7f) << $shift);
        return $value if !($byte & 0x80);
        $shift += 7;
    }
}

sub read_length_delimited {
    my ($buf, $offset_ref) = @_;
    my $size = read_varint($buf, $offset_ref);
    my $end = $$offset_ref + $size;
    die "unexpected end of protobuf while reading length-delimited field\n"
      if $end > length($buf);
    my $value = substr($buf, $$offset_ref, $size);
    $$offset_ref = $end;
    return $value;
}

sub encode_base32 {
    my ($buf) = @_;
    my $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    my $out = '';
    my $accumulator = 0;
    my $bits = 0;

    foreach my $byte (unpack('C*', $buf)) {
        $accumulator = ($accumulator << 8) | $byte;
        $bits += 8;
        while ($bits >= 5) {
            $bits -= 5;
            $out .= substr($alphabet, ($accumulator >> $bits) & 0x1f, 1);
        }
    }

    if ($bits > 0) {
        $out .= substr($alphabet, ($accumulator << (5 - $bits)) & 0x1f, 1);
    }

    return $out;
}

sub parse_otp_parameters {
    my ($buf) = @_;
    my %entry = (
        issuer        => '',
        account       => '',
        secret_base32 => '',
        algorithm     => undef,
        digits        => undef,
        otp_type      => undef,
    );

    my $offset = 0;
    while ($offset < length($buf)) {
        my $tag = ord(substr($buf, $offset, 1));
        $offset += 1;
        my $field = $tag >> 3;
        my $wire = $tag & 0x07;

        if ($wire == 2) {
            my $value = read_length_delimited($buf, \$offset);
            if ($field == 1) {
                $entry{secret_base32} = encode_base32($value);
            } elsif ($field == 2) {
                $entry{account} = $value;
            } elsif ($field == 3) {
                $entry{issuer} = $value;
            }
        } elsif ($wire == 0) {
            my $value = read_varint($buf, \$offset);
            if ($field == 4) {
                $entry{algorithm} = $value;
            } elsif ($field == 5) {
                $entry{digits} = $value;
            } elsif ($field == 6) {
                $entry{otp_type} = $value;
            }
        } else {
            die "unsupported protobuf wire type: $wire\n";
        }
    }

    return \%entry;
}

sub normalize_source {
    my ($source) = @_;
    $source =~ s/^\s+//;
    $source =~ s/\s+$//;
    die "input is empty\n" if $source eq '';

    if ($source =~ m{^otpauth-migration://}) {
        my ($data) = $source =~ /(?:\?|&)data=([^&]+)/;
        die "migration URL does not contain data=...\n" if !defined $data || $data eq '';
        return $data;
    }

    if ($source =~ /^data=(.*)$/s) {
        return $1;
    }

    return $source;
}

sub parse_migration_entries {
    my ($source) = @_;
    my $data = normalize_source($source);
    my $raw = decode_base64(uri_unescape($data));
    die "failed to decode migration payload\n" if $raw eq '';

    my @entries;
    my $offset = 0;
    while ($offset < length($raw)) {
        my $tag = ord(substr($raw, $offset, 1));
        $offset += 1;
        my $field = $tag >> 3;
        my $wire = $tag & 0x07;

        if ($wire == 2) {
            my $value = read_length_delimited($raw, \$offset);
            push @entries, parse_otp_parameters($value) if $field == 1;
        } elsif ($wire == 0) {
            read_varint($raw, \$offset);
        } else {
            die "unsupported protobuf wire type: $wire\n";
        }
    }

    die "no OTP entries found in migration payload\n" if !@entries;
    return \@entries;
}

my $list = 0;
my $json = 0;
my $index;
my $issuer;
my $account;
my $help = 0;

GetOptions(
    'list'      => \$list,
    'json'      => \$json,
    'index=i'   => \$index,
    'issuer=s'  => \$issuer,
    'account=s' => \$account,
    'help'      => \$help,
) or do {
    print STDERR usage();
    exit 2;
};

if ($help) {
    print usage();
    exit 0;
}

if (@ARGV > 1) {
    print STDERR "error: expected a single source argument\n";
    print STDERR usage();
    exit 2;
}

my $source;
if (@ARGV == 1) {
    $source = $ARGV[0];
} else {
    local $/;
    $source = <STDIN>;
}

my $entries;
eval {
    $entries = parse_migration_entries($source // '');
    if (defined $issuer) {
        @$entries = grep { $_->{issuer} eq $issuer } @$entries;
    }
    if (defined $account) {
        @$entries = grep { $_->{account} eq $account } @$entries;
    }
    if (defined $index) {
        die "--index must be at least 1\n" if $index < 1;
        die "--index must be between 1 and " . scalar(@$entries) . "\n"
          if $index > scalar(@$entries);
        @$entries = ($entries->[$index - 1]);
    }
    1;
} or do {
    my $error = $@ || "unknown error\n";
    $error .= "\n" if $error !~ /\n\z/;
    print STDERR "error: $error";
    exit 2;
};

if (!@$entries) {
    print STDERR "error: no entries matched the requested filters\n";
    exit 2;
}

if ($json) {
    print encode_json($entries), "\n";
    exit 0;
}

if ($list) {
    my $i = 1;
    foreach my $entry (@$entries) {
        print join("\t", $i, $entry->{issuer}, $entry->{account}, $entry->{secret_base32}), "\n";
        $i += 1;
    }
    exit 0;
}

if (@$entries != 1) {
    print STDERR "error: multiple entries found; rerun with --list, --index, --issuer, or --account\n";
    exit 2;
}

print $entries->[0]{secret_base32}, "\n";
exit 0;
