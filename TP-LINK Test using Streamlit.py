import streamlit as st
import requests
import hashlib
import base64
from urllib.parse import urlparse
import re
import time
import pandas as pd

# Custom CSS for professional styling
st.markdown("""
<style>
    .main {
        background-color: #f5f7fa;
        padding: 20px;
    }
    .stButton>button {
        background-color: #0066cc;
        color: white;
        border-radius: 5px;
        padding: 10px 20px;
        font-weight: bold;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    .stButton>button:hover {
        background-color: #0055aa;
    }
    .stTextInput>div>input {
        border-radius: 5px;
        border: 1px solid #d1d5db;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    .card {
        background-color: white;
        padding: 1px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
        margin-bottom: 20px;
        border: 1px solid #e5e7eb;
    }
    .section-title {
        font-size: 28px;
        font-weight: 600;
        color: #D3D3D3;
        margin-bottom: 20px;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        border-bottom: 2px solid #e5e7eb;
        padding-bottom: 5px;
    }
    .info-box {
        font-size: 16px;
        color: #FFFFFF;
        line-height: 1.6;
        margin-bottom: 10px;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    .debug-box {
        background-color: #e5e7eb;
        padding: 12px;
        border-radius: 6px;
        margin-top: 10px;
        font-family: 'Courier New', Courier, monospace;
        color: #1f2937;
        border: 1px solid #d1d5db;
    }
    .app-header {
        text-align: center;
        margin-bottom: 30px;
        font-size: 32px;
        font-weight: 700;
        color: #D3D3D3;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
</style>
""", unsafe_allow_html=True)

# Original router monitoring functions with enhancements
def md5_hash(text):
    """Generate MD5 hash of the input text."""
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def get_auth_cookie(username, password, use_md5=True):
    """Generate Basic Authentication cookie."""
    if use_md5:
        password = md5_hash(password)
    auth_str = f"{username}:{password}"
    b64_auth = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
    return f"Basic {b64_auth}"

def login(router_url, username, password):
    """Log in to the router and return session, final URL, and response text."""
    session = requests.Session()
    auth_cookie = get_auth_cookie(username, password, use_md5=True)
    session.cookies.set("Authorization", auth_cookie, path="/", domain=urlparse(router_url).hostname)
    login_url = router_url + "/userRpm/LoginRpm.htm"
    params = {"Save": "Save"}
    try:
        resp = session.get(login_url, params=params, allow_redirects=True)
        if resp.status_code == 200:
            return session, resp.url, resp.text
        else:
            st.error(f"Login failed with status code: {resp.status_code}")
            return None, None, None
    except requests.exceptions.RequestException as e:
        st.error(f"Connection error: {str(e)}")
        return None, None, None

def extract_token(response_data):
    """Extract session token using multiple methods with debugging."""
    url, resp_text = response_data if isinstance(response_data, tuple) else (response_data, response_data)
    
    # Method 1: Extract from URL
    token = extract_token_from_url(url)
    if token:
        st.markdown(f"<div class='debug-box'>Connected Successfully. Token extracted from URL: {token}</div>", unsafe_allow_html=True)
        return token
    
    # Method 2: Extract from response text (main pattern)
    token = extract_token_from_response(resp_text)
    if token:
        st.markdown(f"<div class='debug-box'>Connected Successfully. Token extracted from response: {token}</div>", unsafe_allow_html=True)
        return token
    
    # Method 3: Extract from href (fallback)
    token = parse_response(resp_text)
    if token:
        st.markdown(f"<div class='debug-box'>Connected Successfully. Token extracted from href: {token}</div>", unsafe_allow_html=True)
        return token
    
    # Debug raw response if no token found
    st.markdown("<div class='debug-box'>No token found. Raw response snippet:</div>", unsafe_allow_html=True)
    st.markdown(f"<div class='debug-box'>{resp_text[:500]}...</div>", unsafe_allow_html=True)  # Show first 500 chars
    return None

def extract_token_from_url(url):
    """Extract session token from URL."""
    match = re.search(r'/([A-Za-z0-9]+)/userRpm/Index\.htm', url)
    return match.group(1) if match else None

def extract_token_from_response(resp_text):
    """Extract session token from response text."""
    match = re.search(r'/([A-Za-z0-9]+)/userRpm/Index\.htm', resp_text)
    return match.group(1) if match else None

def parse_response(resp_text):
    """Parse response text to extract token from href."""
    match = re.search(r'href\s*=\s*"([^"]+)"', resp_text)
    if match:
        url = match.group(1)
        path_parts = urlparse(url).path.strip("/").split("/")
        if len(path_parts) >= 2:
            return path_parts[0]
    return None

def retrieve_dhcp_clients(session, token, router_url):
    """Retrieve DHCP clients list."""
    time.sleep(0.5)
    status_url = f"{router_url}/{token}/userRpm/AssignedIpAddrListRpm.htm"
    headers = {
        "Referer": f"{router_url}/{token}/userRpm/Index.htm",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    }
    try:
        response = session.get(status_url, headers=headers, timeout=10)
        return response.text
    except requests.exceptions.RequestException as e:
        # Added indented block to handle the exception
        return None

def retrieve_wireless_clients_html(session, token, router_url, page=1, vap_idx=0):
    """Retrieve wireless clients HTML."""
    time.sleep(0.5)
    status_url = f"{router_url}/{token}/userRpm/WlanStationRpm.htm?Page={page}&vapIdx={vap_idx}"
    headers = {
        "Referer": f"{router_url}/{token}/userRpm/Index.htm",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    }
    try:
        response = session.get(status_url, headers=headers, timeout=10)
        return response.text
    except requests.exceptions.RequestException:
        return None

def retrieve_router_status(session, token, router_url):
    """Retrieve router status HTML."""
    time.sleep(0.5)
    status_url = f"{router_url}/{token}/userRpm/StatusRpm.htm"
    headers = {
        "Referer": f"{router_url}/{token}/userRpm/Index.htm",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    }
    try:
        response = session.get(status_url, headers=headers, timeout=10)
        return response.text
    except requests.exceptions.RequestException:
        return None

def get_connected_devices_and_status(session, token, router_url):
    """Fetch and parse connected devices and router status."""
    devices = []
    lan_info = {}
    wan_info = {}
    wireless_info = {}
    sys_info = {}
    traffic_info = {}

    # Fetch wireless MACs
    wireless_macs = set()
    html_text = retrieve_wireless_clients_html(session, token, router_url)
    if html_text:
        try:
            match = re.search(r'var hostList = new Array(\s*(.*?)\s*);', html_text, re.DOTALL)
            if match:
                array_str = match.group(1).strip()
                elements = re.findall(r'"([^"]*)"|(\d+)', array_str)
                elements = [e[0] if e[0] else e[1] for e in elements]
                field_count = 5
                html_devices = [elements[i:i+field_count] for i in range(0, len(elements), field_count) if len(elements[i:i+field_count]) == field_count]
                wireless_macs = {device[0].lower() for device in html_devices}
        except Exception as e:
            pass

    # Fetch and parse DHCP clients
    dhcp_text = retrieve_dhcp_clients(session, token, router_url)
    if dhcp_text:
        try:
            match = re.search(r'var DHCPDynList = new Array(\s*(.*?)\s*);', dhcp_text, re.DOTALL)
            if match:
                array_str = match.group(1).strip()
                elements = re.findall(r'"([^"]*)"', array_str)
                field_count = 4
                dhcp_devices = [elements[i:i+field_count] for i in range(0, len(elements), field_count) if len(elements[i:i+field_count]) == field_count]
                # Include all DHCP devices without strict wireless MAC filtering
                devices = [
                    {"NAME": dev[0], "MAC ADDRESS": dev[1], "IP ADDRESS": dev[2], "LEASE TIME": dev[3]}
                    for dev in dhcp_devices
                ]
        except Exception:
            pass

    # Fetch and parse router status
    status_text = retrieve_router_status(session, token, router_url)
    if status_text:
        try:
            # Parse lanPara
            lan_match = re.search(r'var lanPara = new Array\((.*?)\);', status_text, re.DOTALL)
            if lan_match:
                lan_elements = re.findall(r'"([^"]*)"|(\d+)', lan_match.group(1))
                lan_elements = [e[0] if e[0] else e[1] for e in lan_elements]
                lan_info = {
                    "mac_address": lan_elements[0] if len(lan_elements) > 0 else "N/A",
                    "ip_address": lan_elements[1] if len(lan_elements) > 1 else "N/A",
                    "subnet_mask": lan_elements[2] if len(lan_elements) > 2 else "N/A"
                }
            
            # Parse wanPara
            wan_match = re.search(r'var wanPara = new Array\((.*?)\);', status_text, re.DOTALL)
            if wan_match:
                wan_elements = re.findall(r'"([^"]*)"|(\d+)', wan_match.group(1))
                wan_elements = [e[0] if e[0] else e[1] for e in wan_elements]
                connection_type = "Dynamic IP" if wan_elements[0] == "4" else "N/A"
                wan_info = {
                    "mac_address": wan_elements[1] if len(wan_elements) > 1 else "N/A",
                    "ip_address": wan_elements[2] if len(wan_elements) > 2 else "N/A",
                    "subnet_mask": wan_elements[4] if len(wan_elements) > 4 else "N/A",
                    "gateway": wan_elements[7] if len(wan_elements) > 7 else "N/A",
                    "dns": wan_elements[11] if len(wan_elements) > 11 else "N/A",
                    "connection_type": connection_type
                }
            
            # Parse wlanPara
            wlan_match = re.search(r'var wlanPara = new Array\((.*?)\);', status_text, re.DOTALL)
            if wlan_match:
                wlan_elements = re.findall(r'"([^"]*)"|(\d+)', wlan_match.group(1))
                wlan_elements = [e[0] if e[0] else e[1] for e in wlan_elements]
                ssids = [wlan_elements[1]] if len(wlan_elements) > 1 and wlan_elements[1] else []
                if len(wlan_elements) > 11 and wlan_elements[11]:
                    ssids.append(wlan_elements[11])
                wireless_info = {
                    "ssid": ", ".join(ssids) if ssids else "N/A"
                }
            
            # Parse statusPara
            status_match = re.search(r'var statusPara = new Array\((.*?)\);', status_text, re.DOTALL)
            if status_match:
                status_elements = re.findall(r'"([^"]*)"|(\d+)', status_match.group(1))
                status_elements = [e[0] if e[0] else e[1] for e in status_elements]
                sys_info = {
                    "firmware_version": status_elements[5] if len(status_elements) > 5 else "N/A",
                    "hardware_version": status_elements[6] if len(status_elements) > 6 else "N/A"
                }
            
            # Parse statistList
            stat_match = re.search(r'var statistList = new Array\((.*?)\);', status_text, re.DOTALL)
            if stat_match:
                stat_elements = re.findall(r'"([^"]*)"|(\d+)', stat_match.group(1))
                stat_elements = [e[0] if e[0] else e[1] for e in stat_elements]
                traffic_info = {
                    "bytes_received": stat_elements[0] if len(stat_elements) > 0 else "N/A",
                    "bytes_sent": stat_elements[1] if len(stat_elements) > 1 else "N/A",
                    "packets_received": stat_elements[2] if len(stat_elements) > 2 else "N/A",
                    "packets_sent": stat_elements[3] if len(stat_elements) > 3 else "N/A"
                }
        except Exception:
            pass

    return devices, lan_info, wan_info, wireless_info, sys_info, traffic_info

# Streamlit App
st.markdown("<div class='app-header'>Router Monitoring Dashboard</div>", unsafe_allow_html=True)
st.markdown("Monitor connected devices and router status with a professional interface.")

# Sidebar for inputs
with st.sidebar:
    st.header("Router Configuration")
    router_url = st.text_input("Router URL", value="http://192.168.100.108", help="Enter the router's IP address or URL")
    username = st.text_input("Username", value="admin", help="Enter the router admin username")
    password = st.text_input("Password", type="password", value="admin", help="Enter the router admin password")
    if st.button("Connect to Router"):
        st.session_state['connect'] = True

# Main content
if 'connect' in st.session_state and st.session_state['connect']:
    with st.spinner("Connecting to router..."):
        session, final_url, resp_text = login(router_url, username, password)
        if session:
            token = extract_token((final_url, resp_text))
            if token:
                devices, lan_info, wan_info, wireless_info, sys_info, traffic_info = get_connected_devices_and_status(session, token, router_url)
                
                # Display Connected Devices
                st.markdown("<div class='section-title'>Connected Wireless Devices</div>", unsafe_allow_html=True)
                if devices:
                    st.markdown(f"<div class='info-box'>Total connected wireless devices: {len(devices)}</div>", unsafe_allow_html=True)
                    df = pd.DataFrame(devices)
                    df.index = df.index + 1
                    st.dataframe(df, use_container_width=True)
                else:
                    st.warning("No connected devices found or failed to retrieve data.")

                # Display Router Status
                if any(value != "N/A" for value in {**lan_info, **wan_info, **wireless_info, **sys_info, **traffic_info}.values()):
                    st.markdown("<div class='section-title'>Router Status</div>", unsafe_allow_html=True)
                    # First row: LAN Information and WAN Information side by side
                    col1, col2 = st.columns(2)
                    with col1:
                        if any(value != "N/A" for value in lan_info.values()):
                            st.markdown("<div class='card'>", unsafe_allow_html=True)
                            st.markdown('<b style="font-size: 20px;">LAN Information</b>', unsafe_allow_html=True)
                            if lan_info.get('mac_address', 'N/A') != "N/A":
                                st.markdown(f"<div class='info-box'>MAC Address: {lan_info.get('mac_address', 'N/A')}</div>", unsafe_allow_html=True)
                            if lan_info.get('ip_address', 'N/A') != "N/A":
                                st.markdown(f"<div class='info-box'>IP Address: {lan_info.get('ip_address', 'N/A')}</div>", unsafe_allow_html=True)
                            if lan_info.get('subnet_mask', 'N/A') != "N/A":
                                st.markdown(f"<div class='info-box'>Subnet Mask: {lan_info.get('subnet_mask', 'N/A')}</div>", unsafe_allow_html=True)
                            st.markdown("</div>", unsafe_allow_html=True)
                    with col2:
                        if any(value != "N/A" for value in wan_info.values()):
                            st.markdown("<div class='card'>", unsafe_allow_html=True)
                            st.markdown('<b style="font-size: 20px;">WAN Information</b>', unsafe_allow_html=True)
                            if wan_info.get('mac_address', 'N/A') != "N/A":
                                st.markdown(f"<div class='info-box'>MAC Address: {wan_info.get('mac_address', 'N/A')}</div>", unsafe_allow_html=True)
                            if wan_info.get('ip_address', 'N/A') != "N/A":
                                st.markdown(f"<div class='info-box'>IP Address: {wan_info.get('ip_address', 'N/A')}</div>", unsafe_allow_html=True)
                            if wan_info.get('subnet_mask', 'N/A') != "N/A":
                                st.markdown(f"<div class='info-box'>Subnet Mask: {wan_info.get('subnet_mask', 'N/A')}</div>", unsafe_allow_html=True)
                            if wan_info.get('gateway', 'N/A') != "N/A":
                                st.markdown(f"<div class='info-box'>Gateway: {wan_info.get('gateway', 'N/A')}</div>", unsafe_allow_html=True)
                            if wan_info.get('dns', 'N/A') != "N/A":
                                st.markdown(f"<div class='info-box'>DNS: {wan_info.get('dns', 'N/A')}</div>", unsafe_allow_html=True)
                            if wan_info.get('connection_type', 'N/A') != "N/A":
                                st.markdown(f"<div class='info-box'>Connection Type: {wan_info.get('connection_type', 'N/A')}</div>", unsafe_allow_html=True)
                            st.markdown("</div>", unsafe_allow_html=True)

                    # Second row: Wireless Information and System Information side by side
                    col3, col4 = st.columns(2)
                    with col3:
                        if wireless_info.get('ssid', 'N/A') != "N/A":
                            st.markdown("<div class='card'>", unsafe_allow_html=True)
                            st.markdown('<b style="font-size: 20px;">Wireless Information</b>', unsafe_allow_html=True)
                            st.markdown(f"<div class='info-box'>SSID: {wireless_info.get('ssid', 'N/A')}</div>", unsafe_allow_html=True)
                            st.markdown("</div>", unsafe_allow_html=True)
                    with col4:
                        if any(value != "N/A" for value in sys_info.values()):
                            st.markdown("<div class='card'>", unsafe_allow_html=True)
                            st.markdown('<b style="font-size: 20px;">System Information</b>', unsafe_allow_html=True)
                            if sys_info.get('firmware_version', 'N/A') != "N/A":
                                st.markdown(f"<div class='info-box'>Firmware Version: {sys_info.get('firmware_version', 'N/A')}</div>", unsafe_allow_html=True)
                            if sys_info.get('hardware_version', 'N/A') != "N/A":
                                st.markdown(f"<div class='info-box'>Hardware Version: {sys_info.get('hardware_version', 'N/A')}</div>", unsafe_allow_html=True)
                            st.markdown("</div>", unsafe_allow_html=True)

                    # Traffic Statistics
                    if any(value != "N/A" for value in traffic_info.values()):
                        st.markdown("<div class='card'>", unsafe_allow_html=True)
                        st.markdown('<b style="font-size: 20px;">Traffic Statistics</b>', unsafe_allow_html=True)
                        if traffic_info.get('bytes_received', 'N/A') != "N/A":
                            st.markdown(f"<div class='info-box'>Bytes Received: {traffic_info.get('bytes_received', 'N/A')}</div>", unsafe_allow_html=True)
                        if traffic_info.get('bytes_sent', 'N/A') != "N/A":
                            st.markdown(f"<div class='info-box'>Bytes Sent: {traffic_info.get('bytes_sent', 'N/A')}</div>", unsafe_allow_html=True)
                        if traffic_info.get('packets_received', 'N/A') != "N/A":
                            st.markdown(f"<div class='info-box'>Packets Received: {traffic_info.get('packets_received', 'N/A')}</div>", unsafe_allow_html=True)
                        if traffic_info.get('packets_sent', 'N/A') != "N/A":
                            st.markdown(f"<div class='info-box'>Packets Sent: {traffic_info.get('packets_sent', 'N/A')}</div>", unsafe_allow_html=True)
                        st.markdown("</div>", unsafe_allow_html=True)
            else:
                st.error("Failed to extract session token. Please check the router URL and credentials.")
        else:
            st.error("Failed to connect to the router. Please verify the URL and credentials.")
else:
    st.info("Enter router details in the sidebar and click 'Connect to Router' to view the dashboard.")