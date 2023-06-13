arch:=
CC=$(arch)gcc
server_objs = nb-server.o nb.o
client_objs = nb-client.o nb.o
all_objs = nb-server.o nb-client.o nb.o

all: nb-server nb-client

nb-server: $(server_objs)
	$(CC) $^ -o $@

nb-client: $(client_objs)
	$(CC) $^ -o $@

install:
	install -m 0755 nb-server /usr/bin/nb-server
	install -m 0755 nb-client /usr/bin/nb-client

uninstall:
	rm /usr/bin/nb-server /usr/bin/nb-clients

clean:
	rm *.o nb-server nb-client

$(all_objs): %.o: %.c
	$(CC) -c -g $< -o $@

.PHONY: all