# Generating 802.11 Beacons
This example shows the reader how to generate an 802.11 Beacon, with an SSID and Channel element. It also adds a tagged parameter with the string "libwifi-tag" inside.

# Building and Using
```
>> cd examples/generate_beacon/
>> make
clang -Wall -Werror -O3 -o generate_beacon   -c -o generate_beacon.o generate_beacon.c
clang -Wall -Werror -O3 -o generate_beacon generate_beacon.c -lpcap -lwifi
>> ./generate_beacon --file beacon.pcap
[+] Setup Complete
[*] Creating Beacon Frame
[*] Writing Beacon Frame to pcap
>> tshark -r beacon.pcap 
    1   0.000000 ca:38:6d:6d:3f:bd → Broadcast    802.11 78 Beacon frame, SN=1383, FN=0, Flags=........, BI=100, SSID=libwifi-beacon
>>
```
# Output
![image](https://user-images.githubusercontent.com/4153572/143600844-ce7dee11-46b0-40a5-a12c-881d79bd584d.png)
