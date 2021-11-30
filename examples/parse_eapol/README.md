# Parsing 802.11 Handshake / EAPOL Frames
This example shows the reader how to parse 802.11 Handshakes from a pcap, outputting the EAPOL version, type, length, and data such as Nonce, IV, MIC and EAPOL Key Data.

# Building and Using
```
>> cd examples/parse_eapol/
>> make
clang -Wall -Werror -O3 -o parse_eapol   -c -o parse_eapol.o parse_eapol.c
clang -Wall -Werror -O3 -o parse_eapol parse_eapol.c -lpcap -lwifi
>> ./parse_eapol --file ~/libwifi-handshake.pcap
[+] Setup Complete
WPA Handshake Message: 1 (Message 1)
EAPOL: Version: 2
EAPOL: Type: 3
EAPOL: Length: 95
EAPOL: Descriptor: 2
EAPOL: Key Info: Information: 0x008a
EAPOL: Key Info: Key Length: 16
EAPOL: Key Info: Replay Counter: 1
EAPOL: Key Info: Nonce: 43 79 98 09 6a 0e dc 73 8d 44 3b 55 ce b5 47 2c fd 39 0c 87 51 e4 f0 77 d9 5b 5c e1 dc 59 bd 75 
EAPOL: Key Info: IV: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
EAPOL: Key Info: RSC: 00 00 00 00 00 00 00 00 
EAPOL: Key Info: ID: 00 00 00 00 00 00 00 00 
EAPOL: Key Info: MIC: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
EAPOL: Key Info: Key Data Length: 0

WPA Handshake Message: 2 (Message 2)
EAPOL: Version: 1
EAPOL: Type: 3
EAPOL: Length: 123
EAPOL: Descriptor: 2
EAPOL: Key Info: Information: 0x010a
EAPOL: Key Info: Key Length: 0
EAPOL: Key Info: Replay Counter: 1
EAPOL: Key Info: Nonce: de ed a2 79 e3 c4 96 ba 25 8b ba 84 76 0a 00 69 2e 2c 10 41 24 1a f3 6f 70 9a 4b db 5f 93 47 80 
EAPOL: Key Info: IV: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
EAPOL: Key Info: RSC: 00 00 00 00 00 00 00 00 
EAPOL: Key Info: ID: 00 00 00 00 00 00 00 00 
EAPOL: Key Info: MIC: 6c 23 fe 8d 68 35 c9 5a 77 82 25 4b 56 41 70 71 
EAPOL: Key Info: Key Data Length: 28
EAPOL: Key Info: Key Data: 30 1a 01 00 00 0f ac 04 01 00 00 0f ac 04 01 00 00 0f ac 02 80 00 00 00 00 0f ac 06 

WPA Handshake Message: 4 (Message 3)
EAPOL: Version: 2
EAPOL: Type: 3
EAPOL: Length: 183
EAPOL: Descriptor: 2
EAPOL: Key Info: Information: 0x13ca
EAPOL: Key Info: Key Length: 16
EAPOL: Key Info: Replay Counter: 2
EAPOL: Key Info: Nonce: 43 79 98 09 6a 0e dc 73 8d 44 3b 55 ce b5 47 2c fd 39 0c 87 51 e4 f0 77 d9 5b 5c e1 dc 59 bd 75 
EAPOL: Key Info: IV: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
EAPOL: Key Info: RSC: 00 00 00 00 00 00 00 00 
EAPOL: Key Info: ID: 00 00 00 00 00 00 00 00 
EAPOL: Key Info: MIC: b7 e7 f1 60 f8 cf 3f ec 8f b3 c5 29 e4 a1 d0 05 
EAPOL: Key Info: Key Data Length: 88
EAPOL: Key Info: Key Data: 5e b1 a7 ef db 8d 55 06 d5 c8 89 e7 ca 55 ea cf f5 fa 08 18 ef 4e 46 6e b6 3e 62 d1 30 e7 e5 38 ef 2b 37 61 55 03 9e 84 31 75 3e 44 bd 87 12 9c 94 52 db fb 6a 58 4e 1f 94 e0 16 a9 e9 cb 36 48 c8 ed 20 d3 ff 37 a6 7e 12 3f 0b fc 2c a6 cb 72 c3 6a bf 01 32 b1 6e 1b 

WPA Handshake Message: 8 (Message 4)
EAPOL: Version: 1
EAPOL: Type: 3
EAPOL: Length: 95
EAPOL: Descriptor: 2
EAPOL: Key Info: Information: 0x030a
EAPOL: Key Info: Key Length: 0
EAPOL: Key Info: Replay Counter: 2
EAPOL: Key Info: Nonce: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
EAPOL: Key Info: IV: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
EAPOL: Key Info: RSC: 00 00 00 00 00 00 00 00 
EAPOL: Key Info: ID: 00 00 00 00 00 00 00 00 
EAPOL: Key Info: MIC: 13 6e 07 be 17 51 01 e2 03 5d 4c b1 43 e1 4b c7 
EAPOL: Key Info: Key Data Length: 0
>>
```
