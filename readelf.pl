#!/usr/bin/perl -w

#
# Read ELF in perl.
#
# TODOs:
#  - Parse symbols table
#  - Support 32-bit OS
#  - Only support Linux for now, support others

use warnings;
use strict;
use autodie;

if (scalar @ARGV != 1) {
	die "Usage: ./readelf.pl file\n";
}

my $in = shift;

my ($ei_mag0, $ei_mag1, $ei_mag2, $ei_mag3, $ei_class, $ei_data, $ei_version, $ei_osabi, $e_type, $e_machine, $e_version);
my ($e_entry, $e_phoff, $e_shoff, $e_flags, $e_ehsize, $e_phentsize, $e_phnum, $e_shentsize, $e_shnum, $e_shstrndx);

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
	
open my $fh, '<:raw', "$in";

sub elf_header_parser {
	read $fh, my $bytes, 0x18;
	($ei_mag0, $ei_mag1, $ei_mag2, $ei_mag3, $ei_class, $ei_data, $ei_version,
		$ei_osabi, $e_type, $e_machine, $e_version) = unpack("C a a a C C C C x8 S S I", $bytes);

	if ($ei_mag0 != 127 && $ei_mag1 !~ "E" and $ei_mag2 !~ "L" && $ei_mag3 !~ "F") {
		die "not elf file\n";
	}
	print "File format: ELF ";
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
	print "ELF header version: $ei_version\n";
	print "OS ABI: $os_abis{$ei_osabi}\n";
	print "Type: $filetyps[$e_type]\n";
	print "Machine: $machines{$e_machine}\n";
	print "File Version: $e_version\n";

	if ($ei_class == 1) {
		read $fh, $bytes, 0x0c;
		($e_entry, $e_phoff, $e_shoff) = unpack("I I I", $bytes);
		printf "Entry point: 0x%x\n", $e_entry;
		printf "Start of program header table: 0x%x\n", $e_phoff;
	} elsif ($ei_class == 2) {
		read $fh, $bytes, 0x18;
		($e_entry, $e_phoff, $e_shoff) = unpack("q q q", $bytes);
		printf "Entry point: 0x%x\n", $e_entry;
		printf "Start of program header table: 0x%x\n", $e_phoff;
	}

	read $fh, $bytes, 0x10;
	($e_flags, $e_ehsize, $e_phentsize, $e_phnum, $e_shentsize, $e_shnum, $e_shstrndx) = unpack("I S S S S S S", $bytes);
	print "Header size: $e_ehsize\n";
	print "Size of a program header table entry: $e_phentsize\n";
	print "Number of entries in the program header table: $e_phnum\n";
	print "Size of a section header table entry: $e_shentsize\n";
	print "Number of entries in the section header table: $e_shnum\n";
	print "Index of the section header table entry that contains the section names: $e_shstrndx\n";
	print "\n";
}

my %prom_type_hash = (
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

sub program_header_parser {
	print "There are $e_phnum program headers, start at offset $e_phoff\n";
	print "Program headers:\n";
	seek $fh, $e_phoff, "SEEK_SET";
	print "  Type          Flags        Offset        VirtAddr        PhysAddr        FileSize        MemSize        Align\n";
	for (my $i = 0; $i < $e_phnum; $i++) {
		my $bytes;
		read $fh, $bytes, $e_phentsize;
		my ($p_type, $p_flags, $p_offset, $p_vaddr, $p_paddr, $p_filesz, $p_memsz, $p_align) = unpack("I I q q q q q q", $bytes);
		if (exists $prom_type_hash{$p_type}) {
			print "  $prom_type_hash{$p_type}";
			for (my $j = 0; $j < length("Type") + 10 - length($prom_type_hash{$p_type}); $j++) {
				print " ";
			}

			print "$pflags{$p_flags}";
			for (my $j = 0; $j < length("Flags") + 8 - length($pflags{$p_flags}); $j++) {
				print " ";
			}

			printf "0x%x", $p_offset;
			for (my $j = 0; $j < length("Offset") + 8 - length(sprintf("0x%x", $p_offset)); $j++) {
				print " ";
			}

			printf "0x%x", $p_vaddr;
			for (my $j = 0; $j < length("VirtAddr") + 8 - length(sprintf("0x%x", $p_vaddr)); $j++) {
				print " ";
			}

			printf "0x%x", $p_paddr;
			for (my $j = 0; $j < length("PhysAddr") + 8 - length(sprintf("0x%x", $p_paddr)); $j++) {
				print " ";
			}

			printf "0x%x", $p_filesz;
			for (my $j = 0; $j < length("FileSize") + 8 - length(sprintf("0x%x", $p_filesz)); $j++) {
				print " ";
			}

			printf "0x%x", $p_memsz;
			for (my $j = 0; $j < length("MemSize") + 8 - length(sprintf("0x%x", $p_memsz)); $j++) {
				print " ";
			}
			printf "0x%x\n", $p_align;
		}
	}
	print "\n";
}

my %sh_types_hash = (
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

my %sh_flags_hash = (
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

sub get_name {
	my $idx = shift;
	my $str = shift;
	my $strlen = length($str);
	my $s = substr $str, $idx;
	my $char = "\0";
	my $pos = index($s, $char);
	my $r = substr($s, 0, $pos);
}

sub section_header_parser {
	printf "There are %d section headers, starting at offset 0x%x\n", $e_shnum, $e_shoff;
	print "Section Headers:\n";

	seek $fh, $e_shoff, "SEEK_SET";

	my %sections;

	my $symtab_offset;
	my $symtab_size;
	my @strtabs;
	my $strtab_idx = 0;

	for (my $i = 0; $i < $e_shnum; $i++) {
		my $bytes;
		read $fh, $bytes, $e_shentsize;
		my ($sh_name, $sh_type, $sh_flags, $sh_addr, $sh_offset, $sh_size,
			$sh_link, $sh_info, $sh_addralign, $sh_entsize) = unpack("I I q q q q I I q q", $bytes);

		$sections{$sh_name}{'sh_name'} = $sh_name;
		$sections{$sh_name}{'sh_type'} = $sh_types_hash{$sh_type};
		$sections{$sh_name}{'sh_flags'} = $sh_flags_hash{$sh_flags};
		$sections{$sh_name}{'sh_addr'} = $sh_addr;
		$sections{$sh_name}{'sh_offset'} = $sh_offset;
		$sections{$sh_name}{'sh_size'} = $sh_size;	
		$sections{$sh_name}{'sh_link'} = $sh_link;
		$sections{$sh_name}{'sh_info'} = $sh_info;
		$sections{$sh_name}{'sh_addralign'} = $sh_addralign;
		$sections{$sh_name}{'sh_entsize'} = $sh_entsize;

		# symbol table
		if ($sh_type == 2) {
			$symtab_offset = $sh_offset;
			$symtab_size = $sh_size;
		} elsif ($sh_type == 3) {
			my $curr_file_offset = tell $fh;
			seek $fh, $sh_offset, "SEEK_SET";
			read $fh, $strtabs[$strtab_idx], $sh_size;
			seek $fh, $curr_file_offset, "SEEK_SET";
			$strtab_idx++;
		}
	}

	my $strtable;
	foreach (@strtabs) {
		if ($_ =~ 'symtab') {
			$strtable = $_;
		}
	}

	print "[Nr]    Name                Type        Address        Offset        Size        EntSize        Flags    Link    Info    Align\n";
	my $i = 0;
	foreach my $key (sort {$a <=> $b} keys %sections) {
		print "[$i]";
		for (my $j = 0; $j < length("[Nr]") + 4 - length(sprintf("[%d]", $i)); $j++) {
			print " ";
		}

		my $name = get_name($sections{$key}{'sh_name'}, $strtable);
		print "$name";
		for (my $j = 0; $j < length("Name") + 16 - length($name); $j++) {
			print " ";
		}

		print "$sections{$key}{'sh_type'}";
		for (my $j = 0; $j < length("Type") + 8 - length($sections{$key}{'sh_type'}); $j++) {
			print " ";
		}

		printf "0x%x", $sections{$key}{'sh_addr'};
		for (my $j = 0; $j < length("Address") + 8 - length(sprintf("0x%x", $sections{$key}{'sh_addr'})); $j++) {
			print " ";
		}

		printf "0x%x", $sections{$key}{'sh_offset'};
		for (my $j = 0; $j < length("Offset") + 8 - length(sprintf("0x%x", $sections{$key}{'sh_offset'})); $j++) {
			print " ";
		}

		printf "0x%x", $sections{$key}{'sh_size'};
		for (my $j = 0; $j < length("Size") + 8 - length(sprintf("0x%x", $sections{$key}{'sh_size'})); $j++) {
			print " ";
		}

		printf "0x%x", $sections{$key}{'sh_entsize'};
		for (my $j = 0; $j < length("EntSize") + 8 - length(sprintf("0x%x", $sections{$key}{'sh_entsize'})); $j++) {
			print " ";
		}

		print "$sections{$key}{'sh_flags'}";
		for (my $j = 0; $j < length("Flags") + 4 - length($sections{$key}{'sh_flags'}); $j++) {
			print " ";
		}

		print "$sections{$key}{'sh_link'}";
		for (my $j = 0; $j < length("Link") + 4 - length($sections{$key}{'sh_link'}); $j++) {
			print " ";
		}

		print "$sections{$key}{'sh_info'}";
		for (my $j = 0; $j < length("Info") + 4 - length($sections{$key}{'sh_info'}); $j++) {
			print " ";
		}

		print "$sections{$key}{'sh_addralign'}\n";
		$i++;
	}

	#print "\n---- handle symbol table ----\n";
	#seek $fh, $symtab_offset, "SEEK_SET";
	#read $fh, my $symtab_, $symtab_size;
	#print "$symtab_\n";
}

elf_header_parser();
program_header_parser();
section_header_parser();

close $fh;

