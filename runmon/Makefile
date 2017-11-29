CFLAGS=-lpcap -pthread
BINDIR=/usr/local/bin

all: runmon 

runmon: ethernet.h helpers.c helpers.h ip4.h linked_list.c linked_list.h linked_list_node.h runmon.c runmon.h sip.h tcp.h udp.h vsnp.h
	gcc -o3 -o runmon ${CFLAGS} helpers.c linked_list.c runmon.c 
	sudo chown root runmon
	sudo chmod u+s runmon

clean:
	rm -f runmon

install: runmon
	sudo rsync -aH runmon ${BINDIR}/  
uninstall: 
	sudo rm -f ${BINDIR}/runmon
