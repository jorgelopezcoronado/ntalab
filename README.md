Network Trace Analysis
======================

The goal of this "laboratory" is to introduce you to the concepts of
passive testing using network traces. In this laboratory, we will be
only using the principles learned and implementations of our own. Your
implementations will be using the library which is the holy grail of
packet inspection programming -- libpcap. You will be making your
network monitors. All the methods can be applied to larger (and more
complex) network monitors, but given our restrictions in time we will
not.

Passive Testing -- Network Monitoring
-------------------------------------

For this purpose you are given a compressed archive runmon.tgz or the
contents of the git repo https://github.com/jorgelopezcoronado/ntalab.
The contents are as follows:

-   VSNP: The VSNP implementation that can inject errors

-   runmon: The passive testing network monitoring code

Within the VSNP forlder, the contents of the files are as described in
the Laboratory 1. You have already the executable files for both the
VSNPServer and VSNPClient from C source files. In case your architecture
is not compatible with these executables, re-compile them
(`make server.c; make client.c`).

The VSNP server has a hidden parameter, -e that takes a binary encoded
error code. The error codes are as following (represented from the least
significant bit at the right to the most significant bit at the left):

-   bit 1: Do not check the odd/even, even/odd reply property, i.e.,
    generate a random number from the ID and reply this number,
    independently if the ID is even or odd.

-   bit 2: Insert bugs in the ID number, reading not the correct ID

-   bit 3: Insert bugs not replying randomly to client requests.

If the previous was not clear enough, you can run the VSNPServer
(`sudo ./VSNPServer -s 127.0.0.1 -e NUM`) to inject errors into your
code, here is a brief summary of the different NUM possibilities:

-   1 = bit 1 on (insert the errors as described above in bit 1)

-   2 = bit 2 on (insert the errors as described above in bit 2)

-   3 = bit 1 + bit 2 (insert both errors as described above in bit 1
    and bit 2)

-   4 = bit 3 on (insert the errors as described above in bit 3)

-   5 = bit 1 + bit 3

-   6 = bit 2 + bit 3

-   7 = bit 1 + bit 2 + bit 3

Try the VSNP server injecting different bugs. For example, injecting ID
bugs and non checking of the odd/even, even/odd property can be done
like this: `sudo ./VSNPServer -s 127.0.0.1 -e 3`.

Moving on, the contents of the runmon directory are the following:

-   ethernet.h: Header file which contains the Ethernet packet data
    structure (take a look at this file, most probably you won't need to
    use this, but, it's a good way to get familiar with the data
    structures involved in the process)

-   dns.h: The header file containing the DNS data structure (take a
    look at this file, most probably you won't need to use this, but,
    it's a good way to get familiar with the data structures involved in
    the process)

-   helpers.c: Implementation of some functions that provide some
    functionality. Do not worry about this one

-   helpers.h: The header file of the previous. Do not worry about this
    also.

-   ip4.h: Header file containing the IPv4 header data structure

-   linked\_list.c: My linked list implementation, most probably you
    won't use this

-   linked\_list.h: The header file for the linked lits

-   linked\_list\_node.h: The linked list node data structure

-   Makefile: used to compile the runmon program

-   runmon\_Linux\_x86\_64: The program that perform the passive testing
    or network monitoring pre-comipled for a linux 64 bit architecture

-   runmon\_Mac\_OSX: The program that perform the passive testing or
    network monitoring pre-comipled for a Mac OS X architecture

-   runmon.c: The source code for runmon in C

-   runmon.h: The header file for runmon, this file is particularly
    important since it contains the data `packet` data structure, the
    data structure for a network packet representation

-   sip.h: Header file containing the data structure for SIP packets

-   tcp.h: Header file for the TCP protocol header

-   udp.h: Header file for the UDP protocol header

-   vsnp.h: Header file for the VSNP protocol header, it is important to
    check this data structure

As usual, to compile your C file, you execute `make`.

To execute the runmon you do not need admin privileges since the
compiling process does it for you. When you execute the runmon, you pass
as the first argument the interface that you want to capture packets
from, and as the second argument a filter enclosed with quotes, for
instance "port 53" or "por 1010".

Try runmon with the interface in which you have an IP address that can
route to other computers, if you are using the VM, the interface is
enp0s3. The filter can be set to "", for example:
``` runmon enp0s3 ``'' 1000000 ``` When you generate some traffic (go to
a web page or something) from your computer you might see the first
checking properties already implemented.

You'll be working on your runmon.c file. Take a look at how the libpcap
library functions work, the most important part is the `pcap_loop`
function, and the specified function for a callback. In our case, we
specified that each time a new captured packet comes, the function
`process_packet` should be called.

Take a look at the `process_packet` function. It in fact places the raw
data bytes into the `runmon_packet` data structure and sends the packet
for property checking. If you need to add another. In the same function,
take a look at how the DNS packets are processed. If the source of
destination port is 53, then we consider this is a SIP packet. For the
VSNP protocol we consider it the port 1010.

Take a look at `process_vsnp` and related functions, in fact, this are
the functions that map from the raw data bytes to the data structures as
discussed in class.

Finally, take a look at the `check_properties` function. In here you can
define functions that inspect the packets.

The task of this lab is to check the VNSP server replies. Check that the
packet replies respect the even/odd odd/even constraint. For this you
will make your VSNP data structures, your mapping functions, and the
checking of your property. Have fun!

P.S. Please note that, if the VSNP server replies with different IDs for
the connection you would need to store the request on a queue and check
against the replies. For this lab, you won't make it, but an example
checking that the DNS replies arrive within a specificed timeout is
shown in the `check_properties` function.
