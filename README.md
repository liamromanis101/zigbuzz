# zigbuzz
Currently a simple tool to identify ZigBee packet types and extract some data from pcap files. 

## purpose
No particular purpose as yet, just part of my learning cycle..
It seems that ZBEE_ZCL leak network keys and ZBEE_APF packets leak security keys.. so next bit of dev will be to grab those and use them for eavedropping etc
See Crypto section

## requirements
python3
Uses pyshark and lxml.objectify
You will need tshark install. 

## crypto

In Zigbee networks, there are two types of keys: Zigbee Security Keys and Network Keys:

### Zigbee Security Keys:
Zigbee Security Keys are used for securing the application layer of Zigbee communication. They are primarily associated with Zigbee devices and are used to encrypt and decrypt application-level data payloads. The security keys ensure confidentiality, integrity, and authentication of data exchanged between devices within a Zigbee network. These keys are used to protect sensitive information and prevent unauthorized access and tampering of application data.

#### Zigbee Security Keys include:

    Link Key: A key shared between two Zigbee devices for secure communication between them.
    Master Key: A key used for securely joining devices to a Zigbee network and for key establishment.
    Trust Center Link Key: A key shared between a device and the Trust Center (a central authority in a Zigbee network) for secure communication and network management.

### Network Key:
A Network Key, also known as a Network Encryption Key (NEK), is used for securing the network layer of Zigbee communication. It is shared among all devices in a Zigbee network and is used to encrypt and decrypt network-level data payloads. The network key ensures the confidentiality and integrity of network-related information, such as routing messages and network management frames.

#### The Network Key is primarily used for the following purposes:

    Securing communication between devices in the network.
    Establishing trust and authenticity within the network.
    Maintaining network integrity and preventing unauthorized devices from joining.

## usage

python3 zigbuzz.py <path to pcap>
  
Some sample ZigBee pcap file here: https://tshark.dev/search/pcaptable/
Search for "zbee"
  
  
  
