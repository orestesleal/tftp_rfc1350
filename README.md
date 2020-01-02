# An implementation of The TFTP Protocol (v2) rfc1350, http://tools.ietf.org/html/rfc1350

This code was a one-time write of a tftp client. In the future I would improve it by adding 
support for other `request for comments` (rfcs), I will start by the block size option, right 
now it uses `512` byte blocks (standard tftp) and do not negotiate block sizes, the following 
output shows that this client used 512 bytes blocks (shown as 516 plus the tftp overhead). 
Therefore not taking advantage of the network bandwidth and OS capabilities to transfer data, 
and since `TFTP` is a request-ack protocol for each block, a 512 byte block size on transfers
of several megabytes it can be slower:

    10:43:37.078316 IP (tos 0x0, ttl 64, id 1988, offset 0, flags [none], proto UDP (17), length 544)
        172.31.43.161.47961 > 172.31.41.98.36855: UDP, length 516

To build the `tftp` client just do:

`cc -std=c99 tftp.c -o tftp`

 NOTE: This client was coded on Unix-like systems, however it can be built and linkled with cygwin https://www.cygwin.com/ to make it work on windows, just use the gcc package and built the program.

# Usage examples

Write the local file `gawk.pdf` to the tftp server `172.255.0.4`:

     ./tftp -w gawk.pdf -s 172.255.0.1

Read the remote file `vmlinuz` from the tftp server `172.255.0.4`:

     ./tftp -t vmlinuz -s 172.255.0.1


Read in `octet mode` a linux kernel file from a tftp server:

    $ ./tftp -o -r /images/ubuntu-bionic-x86-64/linux -s 172.31.43.161
    stats: 8544088 bytes recv (8343.8 kbytes) (16688 blocks) (0 retr)

    $ file linux 
    linux: Linux kernel x86 boot executable bzImage, version 4.18.0-10-generic (buildd@lgw01-amd64-060) #11-Ubuntu SMP Thu Oct 11 15:13:55 UTC 2018, RO-rootFS, swap_dev 0x8, Normal VGA
