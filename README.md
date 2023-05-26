# zigbuzz
Currently a simple tool to identify ZigBee packet types and extract some data from pcap files. 

## purpose
No particular purpose as yet, just part of my learning cycle..
It seems that ZBEE_ZCL leak network keys and ZBEE_APF packets leak security keys.. so next bit of dev will be to grab those and use them for eavedropping etc

## requirements
python3
Uses pyshark and lxml.objectify
You will need tshark install. 

## usage

python3 zigbuzz.py <path to pcap>
  
Some sample ZigBee pcap file here: https://tshark.dev/search/pcaptable/
Search for "zbee"

