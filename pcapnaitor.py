from scapy.all import rdpcap, UDP, IP

# Load packets from the specified PCAP file
pcap_file = "assignment.pcap"
packets = rdpcap(pcap_file)

# Dictionary to store call information by Call-ID
calls = {}
rtp_counts = {}

# Iterate through each packet in the PCAP
for pkt in packets:
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        ip = pkt[IP]
        # Decode UDP payload to string for SIP analysis
        payload = bytes(udp.payload).decode(errors='ignore')

        # Extract Call-ID from SIP headers if present
        call_id = None
        for line in payload.split("\r\n"):
            if line.lower().startswith("call-id:"):
                call_id = line.split(":", 1)[1].strip()
                break

        # If Call-ID is found, process SIP signaling
        if call_id:
            # Initialize call info if Call-ID is new
            if call_id not in calls:
                calls[call_id] = {
                    'invite_time': None,    # Timestamp of INVITE
                    'bye_time': None,       # Timestamp of BYE
                    'cancel_time': None,    # Timestamp of CANCEL
                    'status': 'Unknown',    # Final call status
                    'rtp_ports': set(),     # RTP ports associated with call
                    'rtp_count': 0          # RTP packet count
                }
            # Record INVITE timestamp and RTP ports
            if payload.startswith("INVITE"):
                if calls[call_id]['invite_time'] is None:
                    calls[call_id]['invite_time'] = pkt.time
                    calls[call_id]['rtp_ports'].add(udp.sport)
                    calls[call_id]['rtp_ports'].add(udp.dport)
            # Record BYE timestamp and set status
            elif payload.startswith("BYE"):
                calls[call_id]['bye_time'] = pkt.time
                calls[call_id]['status'] = 'Hanged up'
            # Record CANCEL timestamp and set status
            elif payload.startswith("CANCEL"):
                calls[call_id]['cancel_time'] = pkt.time
                calls[call_id]['status'] = 'Cancelled'
        else:
            # If not SIP, check if packet matches RTP ports for any call
            for cid, info in calls.items():
                if udp.sport in info['rtp_ports'] or udp.dport in info['rtp_ports']:
                    info['rtp_count'] += 1

# Print summary for each call
print("\nCall List:")
for call_id, info in calls.items():
    duration = None
    # Calculate duration based on INVITE and BYE/CANCEL timestamps
    if info['invite_time'] and info['bye_time']:
        duration = info['bye_time'] - info['invite_time']
    elif info['invite_time'] and info['cancel_time']:
        duration = info['cancel_time'] - info['invite_time']
    print(f"Call-ID: {call_id}")
    print(f"  Status: {info['status']}")
    print(f"  Duration: {duration:.2f} seconds" if duration else "  Duration: Unknown")
    print(f"  RTP packets: {info['rtp_count']}\n")

# Print total number of SIP calls found
print(f"Total number of SIP calls: {len(calls)}")