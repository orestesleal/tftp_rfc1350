# An implementation of The TFTP Protocol (v2) rfc1350, http://tools.ietf.org/html/rfc1350

This code is a one-time write of a tftp client, I would improve it by adding support for 
other request for comments. To build the client just do:

`cc -std=c99 tftp.c -o tftp`

 NOTE: This client was coded on Unix-like systems, however it can be built and linkled with cygwin https://www.cygwin.com/ to make it work on windows, just use the gcc package and built the program.

# Usage examples

Write the local file `gawk.pdf` to the tftp server `172.255.0.4`:

     ./tftp -w gawk.pdf -s 172.255.0.1

Reac the remote file `vmlinuz` from the tftp server `172.255.0.4`:

     ./tftp -t vmlinuz -s 172.255.0.1
