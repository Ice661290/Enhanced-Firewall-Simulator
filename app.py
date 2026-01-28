import streamlit as st
import time
import random
import socket
from datetime import datetime
from collections import defaultdict

# ================ 1. ส่วน Logic ของ Firewall (ก๊อปมาจากไฟล์เดิม) ================

# สร้างตัวแปร Global สำหรับเก็บข้อมูลใน Memory (แทนการเขียนไฟล์)
if 'traffic_logs' not in st.session_state:
    st.session_state.traffic_logs = []
if 'blacklist' not in st.session_state:
    st.session_state.blacklist = {
        "10.0.0.5": "Known malicious IP - Port Scanner",
        "192.168.1.66": "Previous DDoS attacker",
        "172.16.0.100": "Brute force attempt detected"
    }

traffic_counter = defaultdict(list)

def create_firewall_rules():
    return {
        "192.168.1.100": True,
        "80": True,
        "443": True
    }

def check_rate_limit(ip, max_requests=5, time_window=10):
    current_time = time.time()
    traffic_counter[ip] = [t for t in traffic_counter[ip] if current_time - t < time_window]
    if len(traffic_counter[ip]) >= max_requests:
        return False
    traffic_counter[ip].append(current_time)
    return True

def is_blacklisted(ip):
    return ip in st.session_state.blacklist

def log_to_streamlit(message, type="INFO"):
    # ฟังก์ชันช่วยบันทึก Log ลงหน้าเว็บ
    timestamp = datetime.now().strftime("%H:%M:%S")
    icon = "✅" if type == "ALLOWED" else "❌"
    if type == "CRITICAL": icon = "🚨"
    
    entry = f"{icon} [{timestamp}] {message}"
    
    # เพิ่ม Log ใหม่ไปไว้บนสุด
    st.session_state.traffic_logs.insert(0, entry)
    # เก็บแค่ 20 บรรทัดล่าสุดพอ (จะได้ไม่รก)
    if len(st.session_state.traffic_logs) > 20:
        st.session_state.traffic_logs.pop()

def check_firewall(ip_address, port):
    firewall_rules = create_firewall_rules()
    
    # 1. ตรวจ Rate Limit
    if not check_rate_limit(ip_address):
        log_to_streamlit(f"BLOCKED: {ip_address}:{port} (Rate Limit Exceeded)", "CRITICAL")
        return False
    
    # 2. ตรวจ Blacklist
    if is_blacklisted(ip_address):
        log_to_streamlit(f"BLOCKED: {ip_address}:{port} (Blacklisted IP)", "CRITICAL")
        return False
    
    # 3. ตรวจตามกฎ
    if ip_address in firewall_rules and firewall_rules[ip_address]:
        log_to_streamlit(f"ALLOWED: {ip_address}:{port}", "ALLOWED")
        return True
    if str(port) in firewall_rules and firewall_rules[str(port)]:
        log_to_streamlit(f"ALLOWED: {ip_address}:{port}", "ALLOWED")
        return True
    
    log_to_streamlit(f"BLOCKED: {ip_address}:{port} (No Rule)", "BLOCKED")
    return False

# ================ 2. ส่วนหน้าตาเว็บ (UI) ================

st.set_page_config(page_title="Cloud Firewall", page_icon="🔥")

st.title("🔥 Cloud Firewall Monitor")
st.caption("จำลองการทำงาน Firewall บน Cloud ด้วย Python Streamlit")

col1, col2 = st.columns([2, 1])

with col2:
    st.subheader("🚫 Blacklist Rules")
    st.write(st.session_state.blacklist)
    
    st.subheader("⚙️ Control")
    run_btn = st.button('▶ Start Simulation')
    stop_btn = st.button('⏹ Stop (Refresh Page)')

with col1:
    st.subheader("📡 Live Traffic Logs")
    # พื้นที่สำหรับแสดง Log ที่จะอัปเดตเรื่อยๆ
    log_placeholder = st.empty()

# ================ 3. ส่วน Loop จำลอง Traffic ================

if run_btn:
    # วนลูปทำงาน
    while True:
        # --- (นี่คือ Logic จำลอง Traffic ที่คุณถามถึง) ---
        # สุ่ม IP และ Port เหมือนโค้ดเดิม
        ip_address = ".".join(str(random.randint(0, 255)) for _ in range(4))
        port = random.randint(1, 65535)
        
        # ใส่ Logic เพื่อสุ่มให้เจอเคสแปลกๆ บ้าง
        if random.random() < 0.2: ip_address = "192.168.1.100" # IP ที่อนุญาต
        elif random.random() < 0.1: ip_address = "10.0.0.5"    # IP โจร
        
        # เรียกใช้ Firewall เพื่อตรวจสอบ
        check_firewall(ip_address, port)
        
        # อัปเดต Log บนหน้าเว็บ
        with log_placeholder.container():
            for log in st.session_state.traffic_logs:
                # เปลี่ยนสีข้อความตามสถานะ
                if "ALLOWED" in log: st.success(log)
                elif "CRITICAL" in log: st.error(log)
                else: st.warning(log)
        
        # หน่วงเวลา 1 วินาที
        time.sleep(1)