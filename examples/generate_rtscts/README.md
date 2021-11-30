# Generating 802.11 RTS and CTS Frames
This example shows the reader how to generate an RTS and a CTS Frame, with a random transmitter and a 32ms duration.

# Building and Using
```
>> cd examples/generate_rtscts/
>> make
clang -Wall -Werror -O3 -o generate_rtscts   -c -o generate_rtscts.o generate_rtscts.c
clang -Wall -Werror -O3 -o generate_rtscts generate_rtscts.c -lpcap -lwifi
>> ./generate_rtscts --file rtscts.pcap
[+] Setup Complete
[*] Creating RTS Frame
[*] Writing RTS Frame to pcap
[*] Creating CTS Frame
[*] Writing CTS Frame to pcap
>> tshark -r rtscts.pcap
    1   0.000000 J125Nati_aa:bb:cc (00:20:91:aa:bb:cc) (TA) → Broadcast (ff:ff:ff:ff:ff:ff) (RA) 802.11 16 Request-to-send, Flags=........
    2   0.000008              → Broadcast (ff:ff:ff:ff:ff:ff) (RA) 802.11 10 Clear-to-send, Flags=........
>>
```

# Output
![image](https://user-images.githubusercontent.com/4153572/143601868-da7e9c99-2534-4fe6-9608-68f5af1ad882.png)
