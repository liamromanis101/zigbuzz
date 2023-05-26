import sys
import pyshark
import lxml.objectify

def process_packet(packet):
    if 'zbee_nwk' in dir(packet):
        print ('\n *** NWK ***')
        nwk_layer = packet['zbee_nwk']
        print(nwk_layer)
        print(dir(nwk_layer))
        if hasattr(nwk_layer, 'zbee_nwk_security_level'):
            security_level = nwk_layer.zbee_nwk_security_level
            print(f"Network Security Level: {security_level}")

        if hasattr(nwk_layer, 'zbee_nwk_security_key_type'):
            key_type = nwk_layer.zbee_nwk_security_key_type
            print(f"Network Security Key Type: {key_type}")

    if 'zbee_aps' in dir(packet):
        print ('\n *** APS ***')
        app_layer = packet['zbee_aps']
        print(app_layer)
        print(dir(app_layer))
        if hasattr(app_layer, 'zbee_aps_link_key_type'):
            key_type = app_layer.zbee_aps_link_key_type
            print(f"Application Link Key Type: {key_type}")

    if 'zbee_zdp' in dir(packet):
        zb=packet['zbee_zdp']
        print ('\n *** ZDP ***')
        print(zb)


    if 'zbee_apf' in dir(packet):
        zb=packet['zbee_apf']
        print('\n *** APF ***')
        print(zb)


    if 'zbee_zcl' in dir(packet):
        zb=packet['zbee_zcl']
        print('\n *** ZCL ***')
        print(zb)


    if 'zbee_zcl_general.gp' in dir(packet):
        zb=packet['zbee_zcl_general.gp']
        print('\n *** ZCL GENERAL ***')
        print(zb)


    if 'zbee_nwk_gp' in dir(packet):
        zb=packet['zbee_nwk_gp']
        print('\n *** NWK GP ***')
        print(zb)


    if 'zbee_beacon' in dir(packet):
        zb=packet['zbee_beacon']
        print('\n *** BEACON ***')
        print(zb)


# Check if the pcap file path is provided as a command-line argument
if len(sys.argv) < 2:
    print("Please provide the path to the pcap file as a command-line argument.")
    sys.exit(1)

pcap_file = sys.argv[1]

# Create a FileCapture object with the provided pcap file path
capture = pyshark.FileCapture(pcap_file)

# Set the callback function to process each captured packet
capture.apply_on_packets(process_packet)
