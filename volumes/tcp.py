#!/usr/bin/env python3
from scapy.all import *
import socket

TCP_IP = '10.9.0.5'
TCP_PORT = 23
BUFFER_SIZE = 1024
MESSAGE = "Hello, World!"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
s.send(MESSAGE)
s.close()
