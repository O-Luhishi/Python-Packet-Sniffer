# Python-Packet-Sniffer

## Overview

Packet Sniffer created in Python 3. Allows you to monitor traffic running through local network. Allows the user to be able to view Source of the packets, Target host and the type of protocol used e.g. UDP/TCP.

## Requirement
  - Python 3.x
  - Privileged/Administrative Rights
  - Linux Operating System
  
## Suport
	- Suport IPv6 : ICMP ,UDP, TCP
	
## Can filter
	- That is possible filter the data from the follow packets:
		- TCP ( V4 and V6)
		- UDP ( V4 and V6)
		- ICMP( V4 and V6)
	
## Run
	-sudo python3 Packet-Sniffer.py
	-sudo python3 Packet-Sniffer.py UDP
	-sudo python3 Packet-Sniffer.py ICMP
	-sudo python3 Packet-Sniffer.py TCP
