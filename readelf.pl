#!/usr/bin/perl -w

#
# Read ELF in perl.
#
# TODOs:
#  - Parse .relo section
#  - Support 32-bit OS
#  - Only support Linux for now, support others

use warnings;
use strict;
use autodie;
use Getopt::Long;
Getopt::Long::Configure("bundling");

my %os_abis = (
	0x00 => 'System V',
	0x01 => 'HP-UX',
	0x02 => 'NetBSD',
	0x03 => 'Linux',
	0x04 => 'GNU Hurd',
	0x06 => 'Solaris',
	0x07 => 'AIX',
	0x08 => 'IRIX',
	0x09 => 'FreeBSD',
	0x0A => 'Tru64',
	0x0B => 'Novell Modesto',
	0x0C => 'OpenBSD',
	0x0D => 'OpenVMS',
	0x0E => 'NonStop Kernel',
	0x0F => 'AROS',
	0x10 => 'Fenix OS',
	0x11 => 'CloudABI',
	0x53 => 'Sortix'
);

my @filetyps = ('', 'relocatable', 'executable', 'shared', 'core');

my %machines = (
	0x0  => 'No specific instruction set',
	0x02 => 'SPARC',
	0x03 => 'x86',
	0x08 => 'MIPS',
	0x14 => 'PowerPC',
	0x16 => 'S390',
	0x28 => 'ARM',
	0x2a => 'SuperH',
	0x32 => 'IA-64',
	0x3e => 'x86-64',
	0xB7 => 'AArch64',
	0xF3 => 'RISC-Vn'
);

my %prom_types = (
	0x00000000 => 'NULL',
	0x00000001 => 'LOAD',
	0x00000002 => 'DYNAMIC',
	0x00000003 => 'INTERP',
	0x00000004 => 'NOTE',
	0x00000005 => 'SHLIB',
	0x00000006 => 'PHDR',
	0x60000000 => 'LOOS',
	0x6474e550 => 'GNU_EH_FRAME',
	0x6474e551 => 'GNU_STACK',
	0x6474e552 => 'GNU_RELRO',
	0x6FFFFFFF => 'HIOS',
	0x70000000 => 'LOPROC',
	0x7FFFFFFF => 'HIPROC'
);

my %pflags = (
	1 => '  E',
	2 => ' W',
	3 => ' WE',
	4 => 'R',
	5 => 'R E',
	6 => 'RW'
);

my %shtypes = (
	0          => 'NULL',        # No associated section (inactive entry).
	1          => 'PROGBITS',    # Program-defined contents.
	2          => 'SYMTAB',      # Symbol table.
	3          => 'STRTAB',      # String table.
	4          => 'RELA',        # Relocation entries; explicit addends.
	5          => 'HASH',        # Symbol hash table.
	6          => 'DYNAMIC',     # Information for dynamic linking.
	7          => 'NOTE',        # Information about the file.
	8          => 'NOBITS',      # Data occupies no space in the file.
	9          => 'REL',         # Relocation entries; no explicit addends.
	10         => 'SHLIB',       # Reserved.
	11         => 'DYNSYM',      # Symbol table.
	14         => 'INIT_ARRAY',  # Pointers to initialization functions.
	15         => 'FINI_ARRAY',  # Pointers to termination functions.
	16         => 'PREINIT_ARRAY',  # Pointers to pre-init functions.
	17         => 'GROUP',          # Section group.
	18         => 'SYMTAB_SHNDX',   # Indices for SHN_XINDEX entries.
	0x60000000 => 'LOOS',           # Lowest operating system-specific type.
	0x6ffffff5 => 'GNU_ATTRIBUTES', # Object attributes.
	0x6ffffff6 => 'GNU_HASH',       # GNU-style hash table.
	0x6ffffffd => 'GNU_verdef',     # GNU version definitions.
	0x6ffffffe => 'GNU_verneed',    # GNU version references.
	0x6fffffff => 'GNU_versym',     # GNU symbol versions table.
	0x6fffffff => 'HIOS',           # Highest operating system-specific type.
	0x70000000 => 'LOPROC',         # Lowest processor arch-specific type.
	0x70000001 => 'X86_64_UNWIND',  # Unwind information
	0x7fffffff => 'HIPROC',         # Highest processor arch-specific type.
	0x80000000 => 'LOUSER',         # Lowest type reserved for applications.
	0xffffffff => 'HIUSER'          # Highest type reserved for applications.
);

my %shflags = (
	# NULL
	0x0 => '0',

	# Section data should be writable during execution.
	# SHF_WRITE
	0x1 => 'W',,

	# Section occupies memory during program execution.
	# SHF_ALLOC
	0x2 => 'A',

	# SHF_WRITE + SSH_ALLOC
	0x3 => 'WA',

	# Section contains executable machine instructions.
	# SHF_EXECINSTR
	0x4 => 'X',

	0x6 => 'AX',

	# The data in this section may be merged.
	# SHF_MERGE
	0x10 => 'M',

	# The data in this section is null-terminated strings.
	# SHF_STRINGS
	0x20 => 'S',

	# SHF_MERGE + SHF_STRINGS
	0x30 => 'MS',

	# A field in this section holds a section header table index.
	# 'SHF_INFO_LINK'
	0x40 => 'I',

	# SHF_ALLOC + SHF_INFO_LINK
	0x42 => 'AI',

	# Adds special ordering requirements for link editors.
	# SHF_LINK_ORDER
	0x80 => 'L',

	# This section requires special OS-specific processing to avoid incorrect
	# behavior.
	# SHF_OS_NONCONFORMING
	0x100 => 'o',

	# This section is a member of a section group.
	# SHF_GROUP
	0x200 => 'G',

	# This section holds Thread-Local Storage.
	# SHF_TLS
	0x400 => 'T',

	#
	0x403 => 'WAT',

	# Identifies a section containing compressed data.
	0x800 => 'SHF_COMPRESSED',

	# This section is excluded from the final executable or shared library.
	# SHF_EXCLUDE
	0x80000000 => 'E',

	# Start of target-specific flags.
	0x0ff00000 => 'SHF_MASKOS',

	# Bits indicating processor-specific flags.
	# SHF_MASKPROC
	0xf0000000 => 'p',

	# If an object file section does not have this flag set, then it may not hold
	# more than 2GB and can be freely referred to in objects using smaller code
	# models. Otherwise, only objects using larger code models can refer to them.
	# For example, a medium code model object can refer to data in a section that
	# sets this flag besides being able to refer to data in a section that does
	# not set it; likewise, a small code model object can refer only to code in a
	# section that does not set this flag.
	# SHF_X86_64_LARGE
	0x10000000 => 'l'
);

my %stts = (
	0 => 'NOTYPE',
	1 => 'OBJECT',
	2 => 'FUNC',
	3 => 'SECTION',
	4 => 'FILE'
);

my %stbs = (
	0 => 'LOCAL',
	1 => 'GLOBAL',
	2 => 'WEAK',
	10 => 'LOOS',
	12 => 'HIOS',
	13 => 'LOPROC',
	15 => 'HIPROC'
);

my %viss = (
	0 => 'DEFAULT',
	1 => 'INTERVAL',
	2 => 'HIDDEN',
	3 => 'PROTECTED'
);


my ($ei_mag0, $ei_mag1, $ei_mag2, $ei_mag3, $ei_class, $ei_data, $ei_version, $ei_osabi, $e_type, $e_machine, $e_version);
my ($e_entry, $e_phoff, $e_shoff, $e_flags, $e_ehsize, $e_phentsize, $e_phnum, $e_shentsize, $e_shnum, $e_shstrndx);
my %program_headers;
my %sections;
my %string_tbls;

my %options;
GetOptions(\%options, 'H', 'a', 'l', 'v', 'h', 's', 'S');
my $in = pop (@ARGV);
open my $fh, '<:raw', "$in";


sub usage {
	print "Usage: perl readelf.pl options elf-file\n";
	print " Display information about the contents of ELF format files\n";
	print " Opotions are:\n";
	print "  -a            Display all informations\n";
	print "  -h            Display the ELF file header\n";
	print "  -H            Display this information\n";
	print "  -v            Display the version number of readelf.pl\n";
	print "  -s            Display the symbol tabl\n";
	print "  -S            Display the sections' header\n";
}

sub version {
	print "readelf in perl 0.0.2\n";
	print "Copyright (C) Lampman Yao\n";
}

sub elf_header_parser {
	read $fh, my $buff, 0x18;
	($ei_mag0, $ei_mag1, $ei_mag2, $ei_mag3, $ei_class, $ei_data, $ei_version,
		$ei_osabi, $e_type, $e_machine, $e_version) = unpack("C a a a C C C C x8 S S I", $buff);

	if ($ei_mag0 != 127 && $ei_mag1 !~ "E" and $ei_mag2 !~ "L" && $ei_mag3 !~ "F") {
		die "not elf file\n";
	}
	if ($ei_class == 1) {
		read $fh, $buff, 0x0c;
		($e_entry, $e_phoff, $e_shoff) = unpack("I I I", $buff);
	} elsif ($ei_class == 2) {
		read $fh, $buff, 0x18;
		($e_entry, $e_phoff, $e_shoff) = unpack("q q q", $buff);	
	}

	read $fh, $buff, 0x10;
	($e_flags, $e_ehsize, $e_phentsize, $e_phnum, $e_shentsize, $e_shnum, $e_shstrndx) = unpack("I S S S S S S", $buff);	
}

sub display_elf_header {
	print "ELF header:\n";
	print " File format: ELF ";
	if ($ei_class == 1) {
		print "32-bit ";
	} elsif ($ei_class == 2) {
		print "64-bit ";
	}
	if ($ei_data == 1) {
		print "little-endian\n";
	} elsif ($ei_data == 2) {
		print "big-endian\n";
	}

	print " ELF header version: $ei_version\n";
	print " OS ABI: $os_abis{$ei_osabi}\n";
	print " Type: $filetyps[$e_type]\n";
	print " Machine: $machines{$e_machine}\n";
	print " File Version: $e_version\n";
	printf " Entry point address: 0x%x\n", $e_entry;
	printf " Start of program header: 0x%x\n", $e_phoff;
	printf " Start of section header: 0x%x\n", $e_shoff;
	print " Size of this header: $e_ehsize\n";
	print " Size of program headers: $e_phentsize\n";
	print " Number of program headers: $e_phnum\n";
	print " Size of section headers: $e_shentsize\n";
	print " Number of section headers: $e_shnum\n";
	print " Section header string table index: $e_shstrndx\n";
}

sub program_header_tbl_parser {
	seek $fh, $e_phoff, "SEEK_SET";	
	for (my $i = 0; $i < $e_phnum; $i++) {
		my $buff;
		read $fh, $buff, $e_phentsize;
		my ($p_type, $p_flags, $p_offset, $p_vaddr, $p_paddr, $p_filesz, $p_memsz, $p_align) = unpack("I I q q q q q q", $buff);
		$program_headers{$i} = [$p_type, $p_flags, $p_offset, $p_vaddr, $p_paddr, $p_filesz, $p_memsz, $p_align];
	}
}

sub display_program_header_tbl {
	if ($e_phnum <= 0) {
		return;
	}

	print "There are $e_phnum program headers, start at offset $e_phoff\n",
	      "Program headers:\n",
	      " Type           Offset    VirtAddr  PhysAddr  FileSize  MemSize   Flags   Align\n";
	foreach my $key (sort {$a <=> $b} keys %program_headers) {
		if (exists $prom_types{$program_headers{$key}[0]}) {
			printf " %-12s   0x%06x  0x%06x  0x%06x  0x%06x  0x%06x  %-6s  0x%-0x\n",
				$prom_types{$program_headers{$key}[0]},
				$program_headers{$key}[2],
				$program_headers{$key}[3],
				$program_headers{$key}[4],
				$program_headers{$key}[5],
				$program_headers{$key}[6],
				$pflags{$program_headers{$key}[1]},
				$program_headers{$key}[7];
		}
	}
}

sub sec_name {
	my $idx = shift;
	my $str = shift;
	my $s = substr $str, $idx;
	my $char = "\0";
	my $pos = index($s, $char);
	my $r = substr($s, 0, $pos);
}

sub section_header_tbl_parser {
	seek $fh, $e_shoff, "SEEK_SET";	

	for (my $i = 0; $i < $e_shnum; $i++) {
		my $buff;
		read $fh, $buff, $e_shentsize;
		my ($sh_name, $sh_type, $sh_flags, $sh_addr, $sh_offset, $sh_size,
			$sh_link, $sh_info, $sh_addralign, $sh_entsize) = unpack("I I q q q q I I q q", $buff);

		$sections{$i}{'sh_name'}      = $sh_name;
		$sections{$i}{'sh_type'}      = $sh_type;
		$sections{$i}{'sh_flags'}     = $sh_flags;
		$sections{$i}{'sh_addr'}      = $sh_addr;
		$sections{$i}{'sh_offset'}    = $sh_offset;
		$sections{$i}{'sh_size'}      = $sh_size;	
		$sections{$i}{'sh_link'}      = $sh_link;
		$sections{$i}{'sh_info'}      = $sh_info;
		$sections{$i}{'sh_addralign'} = $sh_addralign;
		$sections{$i}{'sh_entsize'}   = $sh_entsize;

		if ($sh_type == 3) {
			my $curr_offset = tell $fh;
			seek $fh, $sh_offset, "SEEK_SET";
			my $str;
			read $fh, $str, $sh_size;
			seek $fh, $curr_offset, "SEEK_SET";
			$string_tbls{$sh_offset} = $str;
		}
	}
}

sub display_section_header_tbl {
	printf "There are %d section headers, starting at offset 0x%x\n", $e_shnum, $e_shoff;
	print "Section Headers:\n",
	      "[Nr]   Name                Type          Address    Offset     Size       EntSize    Flags  Link  Info  Align\n";

	my $i = 0;
	foreach my $key (sort {$a <=> $b} keys %sections) {
		printf "[%03d] %-20s %-12s  0x%06x   0x%06x   0x%06x   0x%06x   %-4s   %-4d  %-4d  %-4d\n",
			$i,
			sec_name($sections{$key}{'sh_name'}, $string_tbls{$sections{$e_shstrndx}{'sh_offset'}}),
			$shtypes{$sections{$key}{'sh_type'}},
			$sections{$key}{'sh_addr'},
			$sections{$key}{'sh_offset'},
			$sections{$key}{'sh_size'},
			$sections{$key}{'sh_entsize'},
			$shflags{$sections{$key}{'sh_flags'}},
			$sections{$key}{'sh_link'},
			$sections{$key}{'sh_info'},
			$sections{$key}{'sh_addralign'};
		$i++;
	}

	print "Key to Flags:\n",
	      " W (write), A (alloc), X (execute), M (merge), S (strings), l (large)\n",
	      " I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)\n",
	      " O (extra OS processing required) o (OS specific), p (processor specific)\n";
}

sub display_sections {
	foreach my $key (sort {$a <=> $b} keys %sections) {
		if ($sections{$key}{'sh_type'} == 2) {
			my $symtab_offset = $sections{$key}{'sh_offset'};
			my $symtab_size   = $sections{$key}{'sh_size'};
			my $syment_size   = $sections{$key}{'sh_entsize'};
			my $entry_num = $symtab_size / $syment_size;

			print "Symbol table '.symtab' contains $entry_num entries:\n",
			      "Value      Size   Type     Bind    Vis        Ndx    Name\n";

			my $curr_file_offset = tell $fh;
			my $sym_entry;
			seek $fh, $symtab_offset, "SEEK_SET";
			for (my $i = 0; $i < $entry_num; $i++) {
				read $fh, $sym_entry, $syment_size;
				my ($st_name, $st_info, $st_other, $st_shndx, $st_value, $st_size) = unpack("I C C S q q", $sym_entry);
				my $bind = ($st_info & 0xf0) >> 4;  # high-order four bits
				my $type = $st_info & 0x0f;         # low-order four bits
				my $Ndx = '';
				if ($st_shndx == 0) {
					$Ndx = 'UND';
				} elsif ($st_shndx > $entry_num) {
					$Ndx = "ABS";
				} else {
					$Ndx = $st_shndx;
				}
				printf "0x%06x   %-4d   %-7s  %-6s  %-9s  %-4s   %-4s\n",
					$st_value,
					$st_size,
					$stts{$type},
					$stbs{$bind},
					$viss{$st_other},
					$Ndx,
					sec_name($st_name, $string_tbls{$sections{$sections{$key}{'sh_link'}}{'sh_offset'}});
			}
			seek $fh, $curr_file_offset, "SEEK_SET";
			print "\n";
		} elsif ($sections{$key}{'sh_type'} == 11) {
			my $symtab_offset = $sections{$key}{'sh_offset'};
			my $symtab_size   = $sections{$key}{'sh_size'};
			my $syment_size   = $sections{$key}{'sh_entsize'};
			my $entry_num = $symtab_size / $syment_size;
			print "Symbol table '.dynsym' contains $entry_num entries:\n",
			      "Value      Size   Type     Bind    Vis        Ndx    Name\n";
			my $curr_file_offset = tell $fh;
			my $sym_entry;
			seek $fh, $symtab_offset, "SEEK_SET";
			for (my $i = 0; $i < $entry_num; $i++) {
				read $fh, $sym_entry, $syment_size;
				my ($st_name, $st_info, $st_other, $st_shndx, $st_value, $st_size) = unpack("I C C S q q", $sym_entry);
				my $bind = ($st_info & 0xf0) >> 4;  # high-order four bits
				my $type = $st_info & 0x0f;         # low-order four bits
				my $Ndx = '';
				if ($st_shndx == 0) {
					$Ndx = 'UND';
				} elsif ($st_shndx > $entry_num) {
					$Ndx = "ABS";
				} else {
					$Ndx = $st_shndx;
				}
				printf "0x%06x   %-4d   %-7s  %-6s  %-9s  %-4s   %s\n",
					$st_value, $st_size, $stts{$type}, $stbs{$bind}, $viss{$st_other}, $Ndx,
					sec_name($st_name, $string_tbls{$sections{$sections{$key}{'sh_link'}}{'sh_offset'}});
			}
			seek $fh, $curr_file_offset, "SEEK_SET";
			print "\n";
		}
	}
}


if ($options{'H'}) {
	usage();
	exit 0;
}

if ($options{'v'}) {
	version();
	exit 0;
}

elf_header_parser();
program_header_tbl_parser();
section_header_tbl_parser();

if ($options{'a'}) {
	display_elf_header();
	print "\n";
	display_program_header_tbl();
	print "\n";
	display_section_header_tbl();
	print "\n";
	display_sections();
	close $fh;
	exit 0;
}

if ($options{'S'}) {
	display_section_header_tbl();
	close $fh;
	exit 0;
}

if ($options{'h'}) {
	display_elf_header();
	close $fh;
	exit 0;
}

if ($options{'l'}) {
	display_program_header_tbl();
	close $fh;
	exit 0;
}

if ($options{'s'}) {
	display_sections();
	close $fh;
	exit 0;
}

