# Parsing 802.11 Beacon Frames
This example shows the reader how to parse 802.11 Beacons from a pcap, outputting the SSID, BSSID, Channel, Security Information, and more to the terminal.

# Building and Using
```
>> cd examples/parse_beacon/
>> make
clang -Wall -Werror -O3 -o parse_beacon   -c -o parse_beacon.o parse_beacon.c
clang -Wall -Werror -O3 -o parse_beacon parse_beacon.c -lpcap -lwifi
>> ./parse_beacon --file ~/beacon.pcap                                                                                                                                                                                                                      [1/789]
[+] Setup Complete                                                                                                                                                                                                                                                               
ESSID: libwifi-wpa2/3
BSSID: 7e:fc:5e:51:93:31
Receiver: ff:ff:ff:ff:ff:ff
Transmitter: 7e:fc:5e:51:93:31
Channel: 11
WPS: No
Encryption: WPA3, WPA2
        Group Ciphers: CCMP128
        Pairwise Ciphers: CCMP128
        Auth Key Suites: PSK, SAE
        MFP Capable: Yes
Tagged Parameters:
	Tag: 0 (TAG_SSID) (Size: 14)
		14 bytes of Tag Data: 6c 69 62 77 69 66 69 2d 77 70 61 32 2f 33
	Tag: 1 (TAG_SUPP_RATES) (Size: 8)
		8 bytes of Tag Data: 82 84 8b 96 24 30 48 6c
	Tag: 3 (TAG_DS_PARAMETER) (Size: 1)
		1 bytes of Tag Data: 0b
	Tag: 5 (TAG_TIM) (Size: 4)
		4 bytes of Tag Data: 00 02 00 00
	Tag: 7 (TAG_COUNTRY) (Size: 6)
		6 bytes of Tag Data: 47 42 20 01 0d 80
	Tag: 32 (TAG_POWER_CONSTRAINT) (Size: 1)
		1 bytes of Tag Data: 00
	Tag: 35 (TAG_TPC_REPORT) (Size: 2)
		2 bytes of Tag Data: 10 00
	Tag: 42 (TAG_ERP) (Size: 1)
		1 bytes of Tag Data: 00
	Tag: 50 (TAG_EXTENDED_SUPPORTED_RATES) (Size: 4)
		4 bytes of Tag Data: 0c 12 18 60
	Tag: 48 (TAG_RSN) (Size: 24)
		16 bytes of Tag Data: 01 00 00 0f ac 04 01 00 00 0f ac 04 02 00 00 0f
	Tag: 45 (TAG_HT_CAPABILITIES) (Size: 26)
		16 bytes of Tag Data: 2d 00 1b ff ff 00 00 00 00 00 00 00 00 00 00 00
	Tag: 61 (TAG_HT_OPERATION) (Size: 22)
		16 bytes of Tag Data: 0b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	Tag: 127 (TAG_EXTENDED_CAPABILITIES) (Size: 8)
		8 bytes of Tag Data: 04 00 08 00 00 00 00 40
	Tag: 255 (Unknown Tag) (Size: 28)
		16 bytes of Tag Data: 23 01 08 00 1a 00 80 20 20 02 00 0d 00 9e 00 0c
	Tag: 255 (Unknown Tag) (Size: 7)
		7 bytes of Tag Data: 24 04 00 00 00 fc ff
	Tag: 255 (Unknown Tag) (Size: 14)
		14 bytes of Tag Data: 26 00 03 a4 ff 27 a4 ff 42 43 ff 62 32 ff
	Tag: 255 (Unknown Tag) (Size: 4)
		4 bytes of Tag Data: 27 00 00 00
	Tag: 221 (TAG_VENDOR_SPECIFIC) (Size: 30)
		16 bytes of Tag Data: 00 90 4c 04 08 bf 0c 32 70 81 0f fa ff 00 00 fa
	Tag: 221 (TAG_VENDOR_SPECIFIC) (Size: 10)
		10 bytes of Tag Data: 00 10 18 02 00 00 1c 00 00 00
	Tag: 221 (TAG_VENDOR_SPECIFIC) (Size: 24)
		16 bytes of Tag Data: 00 50 f2 02 01 01 00 00 03 a4 00 00 27 a4 00 00
>>
```
