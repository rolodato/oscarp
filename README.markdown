# oscarp

Performs a continuous [ARP (Address Resolution Protocol)](https://en.wikipedia.org/wiki/Address_Resolution_Protocol) scan of the entire local network and forwards any received ARP packets via [OSC (Open Sound Control)](http://opensoundcontrol.org/introduction-osc).

## Installation

```
npm install
```

## Usage

```
IFACE=network_interface npm run start
```

For example, if you're using a MacBook over WiFi, this would most likely be `IFACE=en0 npm run start`.

Once the application is running, it will start sending OSC data over UDP port 27016 on the following addresses:

* `/source_mac`: Source MAC address, extracted from Ethernet frame
* `/dest_mac`: Destination MAC address, extracted from Ethernet frame (can be broadcast, i.e. `ff:ff:ff:ff:ff:ff`)
* `/sender_mac`: Sender MAC address, extracted from ARP packet
* `/sender_ip`: Sender IP address, extracted from ARP packet
* `/target_mac`: Target MAC address, extracted from ARP packet
* `/target_ip`: Target IP address, extracted from ARP packet
* `/source_oui`: Organizationally Unique Identifier (i.e. manufacturer name) of source network interface
* `/dest_oui`: OUI of destination's network interface, or empty string if broadcast address
* `/sender_oui`: OUI of ARP sender's network interface
* `/target_oui`: OUI of target network interface

If the application crashes for whatever reason, such as hitting [this libnmap bug](https://github.com/jas-/node-libnmap/issues/41), it will automatically restart and lose any buffered unsent packets.

## Development

```
IFACE=network_interface npm run dev
```

This will continuously watch for changes with nodemon, but will not automatically restart if the application crashes.