# Razbery Pi Spoofing Device
Authors: Mateusz Furgała, Maciej Dawczak

The packet_saver program is an already running program that checks the arp table and finds the IP addresses of devices connected to it. Starts saving packets from each newly connected device.
If necessary, change the name of the interface on which our access point is located.

Detailed documentation can be found in this repository.

Compilation:

sudo g++ packet_saver.cpp -o packet_saver -lpcap
sudo ./packet_saver
