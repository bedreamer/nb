# -*- coding: utf-8 -*-
import socket
import struct
import codecs
import sys
import select

conn = socket.socket()
conn.connect(("127.0.0.1", 9999))


# login
mac = codecs.decode(sys.argv[1], 'hex')
group =    b"test\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
username = b"test\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
password = b"test\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
pdu = b''.join([mac, group, username, password])
ss = struct.pack("<HB", len(pdu) + 1, 2)
data = ss + pdu
print('tx', codecs.encode(data, 'hex'))
conn.send(data)
ack = conn.recv(1000)
print('rx', codecs.encode(ack, 'hex'))

# pack
while True:
    readable, _, _ = select.select([conn], [], [], 10)

    if readable:
        data = conn.recv(1024)
        if not data:
            break

        if data and len(data):
            print('rx', codecs.encode(data, 'hex'))

    mac_dst, mac_src = b'\xff\xff\xff\xff\xff\xff', mac
    pdu = b''.join([mac_dst, mac_src])
    ss = struct.pack("<HB", len(pdu) + 1, 129)
    data = ss + pdu

    print('tx', codecs.encode(data, 'hex'))
    conn.send(data)

conn.close()
