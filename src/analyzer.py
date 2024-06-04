from scapy.all import rdpcap, UDP, IP
import re
from datetime import datetime

def extract_sip_payload(packet):
    if UDP in packet:
        try:
            return packet[UDP].payload.load.decode('utf-8', 'ignore')
        except AttributeError:
            return None
    return None

def reconstruct_calls(pcap_file):
    packets = rdpcap(pcap_file)
    calls = {}

    for packet in packets:
        sip_payload = extract_sip_payload(packet)
        if sip_payload and "SIP" in sip_payload[:10]:
            call_id_match = re.search(r'\r\nCall-ID: ([^\r\n]+)', sip_payload, re.IGNORECASE)
            if call_id_match:
                call_id = call_id_match.group(1).strip()
                calls.setdefault(call_id, []).append(packet)

    return calls

def diagnose_issues(call_flow):
    issues, recommendations = [], []

    # Provisional responses (100s)
    if any(code in event for code in ["180 Ringing", "183 Session Progress"] for event in call_flow):
        issues.append("Detected normal call progress signals.")
        recommendations.append("No action needed unless unexpected in call flow.")
    
    # Successful responses (200s)
    if "200 OK" in call_flow:
        issues.append("Call successfully established.")
        recommendations.append("No issues detected.")
    
    # Redirection responses (300s)
    if any(code in event for code in ["300 Multiple Choices", "302 Moved Temporarily"] for event in call_flow):
        issues.append("Detected call redirection.")
        recommendations.append("Ensure the redirection is expected and correctly handled.")
    
    # Client failure responses (400s)
    client_failure_codes = [
        "400 Bad Request", "401 Unauthorized", "403 Forbidden",
        "404 Not Found", "405 Method Not Allowed", "406 Not Acceptable",
        "407 Proxy Authentication Required", "408 Request Timeout",
        "410 Gone", "413 Request Entity Too Large", "414 Request-URI Too Long",
        "415 Unsupported Media Type", "416 Unsupported URI Scheme",
        "420 Bad Extension", "421 Extension Required", "422 Session Interval Too Small",
        "423 Interval Too Brief", "480 Temporarily Unavailable",
        "481 Call/Transaction Does Not Exist", "482 Loop Detected",
        "483 Too Many Hops", "484 Address Incomplete", "485 Ambiguous",
        "486 Busy Here", "487 Request Terminated", "488 Not Acceptable Here",
        "491 Request Pending", "493 Undecipherable"
    ]
    for code in client_failure_codes:
        if any(code in event for event in call_flow):
            issues.append(f"Detected issue related to client or request: {code}.")
            recommendations.append("Review the specific error code for troubleshooting steps.")
    
    # Server failure responses (500s)
    server_failure_codes = [
        "500 Server Internal Error", "501 Not Implemented", "502 Bad Gateway",
        "503 Service Unavailable", "504 Server Time-out", "505 Version Not Supported",
        "513 Message Too Large"
    ]
    for code in server_failure_codes:
        if any(code in event for event in call_flow):
            issues.append(f"Detected server-side issue: {code}.")
            recommendations.append("Review the specific error code for troubleshooting steps and check server status.")
    
    # Global failure responses (600s)
    global_failure_codes = [
        "600 Busy Everywhere", "603 Decline", "604 Does Not Exist Anywhere",
        "606 Not Acceptable"
    ]
    for code in global_failure_codes:
        if any(code in event for event in call_flow):
            issues.append(f"Detected global failure: {code}.")
            recommendations.append("Review the specific error code for troubleshooting steps, possibly requiring network-wide actions.")

    # Extend diagnostics as needed with more specific advice if required

    return issues, recommendations


def interpret_sip_messages(calls):
    analysis_results = []

    for call_id, packets in calls.items():
        call_flow, errors, src_ip, dst_ip = [], [], None, None
        caller, called = None, None  # To store caller and called party info
        ip_details = {}  # New: To store detailed IP info including roles and actions
        start_time, end_time = float(packets[0].time), float(packets[-1].time)

        for packet in packets:
            sip_payload = extract_sip_payload(packet)
            if sip_payload:
                timestamp = datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S')
                if IP in packet:
                    current_src_ip = packet[IP].src
                    current_dst_ip = packet[IP].dst
                    # Initialize or update IP details
                    ip_details.setdefault(current_src_ip, {"role": "Unknown", "actions": []})
                    ip_details.setdefault(current_dst_ip, {"role": "Unknown", "actions": []})

                # Identify INVITE messages for caller and called party roles
                if "INVITE" in sip_payload:
                    caller_match = re.search(r'From:.*?sip:(.*?)@', sip_payload, re.IGNORECASE)
                    called_match = re.search(r'To:.*?sip:(.*?)@', sip_payload, re.IGNORECASE)
                    if caller_match and called_match:
                        caller = caller_match.group(1)
                        called = called_match.group(1)
                        ip_details[current_src_ip]["role"] = "Caller"
                        ip_details[current_dst_ip]["role"] = "Called Party"
                        src_ip = current_src_ip  # Originating IP
                        dst_ip = current_dst_ip  # Destination IP

                # Extract call flow details
                request_line_match = re.search(r'^(INVITE|ACK|BYE|CANCEL)\s', sip_payload, re.MULTILINE)
                status_line_match = re.search(r'^SIP/2.0 (\d{3}) (.+)$', sip_payload, re.MULTILINE)

                if request_line_match or status_line_match:
                    call_event = f"{timestamp}: {sip_payload.splitlines()[0]}"
                    call_flow.append(call_event)
                    ip_details[current_src_ip]["actions"].append(call_event)
                    ip_details[current_dst_ip]["actions"].append(call_event)

                # Handle errors within SIP messages
                if status_line_match:
                    code = status_line_match.group(1)
                    if code.startswith('4') or code.startswith('5'):
                        errors.append(f"{timestamp}: Error {code} {status_line_match.group(2)}")

        # Diagnose issues and generate recommendations based on call flow
        issues, recommendations = diagnose_issues(call_flow)

        # Compile analysis results
        analysis_results.append({
            "Call ID": call_id,
            "Originating IP": src_ip,
            "Destination IP": dst_ip,
            "Caller": caller,
            "Called Party": called,
            "Call Flow": call_flow,
            "Errors": errors,
            "Issues": issues,
            "Recommendations": recommendations,
            "IP Details": ip_details,  # Include detailed IP roles and actions
            "Summary": {
                "Start Time": datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S'),
                "End Time": datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S'),
                "Duration (seconds)": round(end_time - start_time, 2),
                "Total Packets": len(packets)
            }
        })

    return analysis_results



def analyze_pcap(pcap_file):
    calls = reconstruct_calls(pcap_file)
    return interpret_sip_messages(calls)
