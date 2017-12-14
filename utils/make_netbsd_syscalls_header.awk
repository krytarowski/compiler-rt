#!/usr/bin/awk -f

BEGIN {
	# harcode the script name
	script_name = "make_netbsd_syscalls_header.awk"
	output = "../include/sanitizer/netbsd_syscall_hooks.h"

	# assert that we are in the directory with scripts
	in_utils = system("test -f " script_name " && exit 1 || exit 0")
	if (in_utils == 0) {
		usage()
	}

	# assert 1 argument passed
	if (ARGC != 2) {
		usage()
	}

	# assert argument is a valid file path to syscall.master
	if (system("test -f " ARGV[1]) != 0) {
		usage()
	}

	# sanity check that the path ends with "syscall.master"
	if (ARGV[1] !~ /syscalls\.master$/) {
		usage()
	}
}

function usage()
{
	print "Usage: " script_name " syscalls.master"
	exit 1
}
