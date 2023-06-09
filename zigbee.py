import sys
import pyshark
import lxml.objectify

def process_packet(packet):
    if 'zbee' in dir(packet):
        print("zbee found")
    if 'zbee_nwk' in dir(packet):
        print ('\n *** NWK ***')
        nwk_layer = packet['zbee_nwk']
        if hasattr(nwk_layer, 'end_device_initiator'):
            end_device = nwk_layer.end_device_initiator
            print(f"End Device: {end_device}")        
            
        if hasattr(nwk_layer, 'dst'):
            dst = nwk_layer.dst
            print(f"Destination: {dst}")                    
        
        if hasattr(nwk_layer, 'src'):
            src = nwk_layer.src
            print(f"Source: {src}")      
            
        if hasattr(nwk_layer, 'zbee_sec_field'):
            security_field = nwk_layer.zbee_sec_field
            print(f"Security Field: {security_field}")               
        
        if hasattr(nwk_layer, 'zbee_nwk_security_level'):
            security_level = nwk_layer.zbee_nwk_security_level
            print(f"Network Security Level: {security_level}")

        if hasattr(nwk_layer, 'zbee_nwk_security_key_type'):
            key_type = nwk_layer.zbee_nwk_security_key_type
            print(f"Network Security Key Type: {key_type}")

        if hasattr(nwk_layer, 'zbee_sec_key_id'):
            key_id = nwk_layer.zbee_sec_key_id
            print(f"Key ID: {key_id}")

        if hasattr(nwk_layer, 'zbee_sec_key_seqno'):
            key_seqno = nwk_layer.zbee_sec_key_seqno
            print(f"Key Sequence Number: {key_seqno}")

        if hasattr(nwk_layer, 'zbee_sec_counter'): 
            sec_count = nwk_layer.zbee_sec_counter 
            print(f"Security Counter: {sec_count}")

        if hasattr(nwk_layer, 'zbee_sec_encrypted_payload'): 
            enc_payload = nwk_layer.zbee_sec_encrypted_payload
            print(f"Encrypted Payload: {enc_payload}") 

        if hasattr(nwk_layer, 'data'): 
            data = nwk_layer.data
            print(f"Data: {data}") 
 
        if hasattr(nwk_layer, 'data_data'): 
           data2 = nwk_layer.data_data
           print(f"Data: {data2}") 
            
        if hasattr(nwk_layer, 'zbee_sec_ext_nonce'): 
            sec_ext_nonce = nwk_layer.zbee_sec_ext_nonce
            print(f"Security Extended Nonce: {sec_ext_nonce}") 

        if hasattr(nwk_layer, 'zbee_sec_mic'): 
            sec_mic = nwk_layer.zbee_sec_mic
            print(f"Security Mic: {sec_mic}") 


    if 'zbee_aps' in dir(packet):
        print ('\n *** APS ***')
        app_layer = packet['zbee_aps']
        if hasattr(app_layer, '_ws_expert'):
            ws_expert = app_layer._ws_expert
            print(f"Application Link WS Expert: {ws_expert}")  
        if hasattr(app_layer, '_ws_expert_group'):
            ws_expert_grp = app_layer._ws_expert_group
            print(f"Application Link WS Expert Group: {ws_expert_grp}")    
        if hasattr(app_layer, '_ws_expert_message'):
            ws_expert_msg = app_layer._ws_expert_message
            print(f"Application Link WS Expert Message: {ws_expert_msg}")      
        if hasattr(app_layer, '_ws_expert_severity'):
            ws_expert_severity = app_layer._ws_expert_severity
            print(f"Application Link WS Expert Severity: {ws_expert_severity}")  
        if hasattr(app_layer, 'count'):
            count = app_layer.count
            print(f"Application Link Count: {count}")   
        if hasattr(app_layer, 'data'):
            data = app_layer.data
            print(f"Application Link Data: {data}")     
        if hasattr(app_layer, 'delivery'):
            delivery = app_layer.delivery
            print(f"Application Link Deliivery: {delivery}")  
        if hasattr(app_layer, 'security'):
            security = app_layer.security
            print(f"Application Link Security: {security}")                                                                             
        if hasattr(app_layer, 'zbee_aps_link_key_type'):
            key_type = app_layer.zbee_aps_link_key_type
            print(f"Application Link Key Type: {key_type}")
        if hasattr(app_layer, 'zbee_sec_key_id'):
            key_id = app_layer.zbee_sec_key_id
            print(f"Application Link Key ID: {key_id}")            
        if hasattr(app_layer, 'zbee_sec_ext_nonce'):
            nonce = app_layer.zbee_sec_ext_nonce
            print(f"Application Link Nonce: {nonce}")
                      
            
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
        print(dir(zb))


    if 'zbee_zcl_general.gp' in dir(packet):
        zb=packet['zbee_zcl_general.gp']
        print('\n *** ZCL GENERAL ***')
        print(zb)
        print(dir(zb))


    if 'zbee_nwk_gp' in dir(packet):
        zb=packet['zbee_nwk_gp']
        print('\n *** NWK GP ***')
        print(zb)


    if 'zbee_beacon' in dir(packet):
        beacon=packet['zbee_beacon']
        print('\n *** BEACON ***')
        
        if hasattr(beacon, 'profile'):
            profile = beacon.profile
            print(f"Beacon Profile: {profile}")
            if "0x0002" in profile:
                print("Beacon Profile: ZigBee PRO")
            if "0x0000" in profile:
                print("Beacon Profile: ZigBee 2004") 
            if "0x0001" in profile:
                print("Beacon Profile: ZigBee 2006")                  
            if "0x0003" in profile:
                print("Beacon Profile: ZigBee 2007")    
            if "0x0004" in profile:
                print("Beacon Profile: ZigBee 2007 PRO")     
            if "0x0101" in profile:
                print("Beacon Profile: ZigBee IP")    
            if "0x0102" in profile:
                print("Beacon Profile: ZigBee PRO with Green Power")   
            if "0x0103" in profile:
                print("Beacon Profile: ZigBee PRO with RF4CE")      
            if "0x0104" in profile:
                print("Beacon Profile: ZigBee PRO with Healthcare")  
            if "0x0105" in profile:
                print("Beacon Profile: ZigBee PRO with Smart Energy")   
            if "0x0107" in profile:
                print("Beacon Profile: ZigBee PRO with Home Automation")  
            if "0x0108" in profile:
                print("Beacon Profile: ZigBee PRO with Light Link")     
            if "0x0109" in profile:
                print("Beacon Profile: ZigBee PRO with Building Automation") 
            if "0x010A" in profile:
                print("Beacon Profile: ZigBee PRO with Telecom Services") 
            if "0x010B" in profile:
                print("Beacon Profile: ZigBee PRO with Remote Control")   
            if "0x010C" in profile:
                print("Beacon Profile: ZigBee PRO with Input Service")    
            if "0x010D" in profile:
                print("Beacon Profile: ZigBee PRO with Residential Control")     
            if "0x010E" in profile:
                print("Beacon Profile: ZigBee PRO with AMI/Smart Metering")    
            if "0x010F" in profile:
                print("Beacon Profile: ZigBee PRO with Light Link 1.1")                                                                                                                                                                                                             
        if hasattr(beacon, 'protocol'):
            proto = beacon.protocol
            print(f"Beacon Protocol: {proto}")

# Check if the pcap file path is provided as a command-line argument
if len(sys.argv) < 2:
    print("Please provide the path to the pcap file as a command-line argument.")
    sys.exit(1)

pcap_file = sys.argv[1]

# Create a FileCapture object with the provided pcap file path
capture = pyshark.FileCapture(pcap_file)

# Set the callback function to process each captured packet
capture.apply_on_packets(process_packet)
