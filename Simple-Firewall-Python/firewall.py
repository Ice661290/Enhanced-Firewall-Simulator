import socket
import time
import random
import json
from datetime import datetime
from collections import defaultdict

# ================ ฟังก์ชันเดิม ================
def create_firewall_rules():
    """Defines a set of firewall rules. You can customize these rules as needed.
    Returns a dictionary where keys are IP addresses or ports, and values are booleans indicating allowed traffic."""
    firewall_rules = {
        "192.168.1.100": True,
        "80": True,
        "443": True
    }
    return firewall_rules

def check_firewall(ip_address, port):
    """Checks if traffic is allowed based on firewall rules."""
    firewall_rules = create_firewall_rules()
    
    # ================ เพิ่มใหม่: Rate Limiting ================
    if not check_rate_limit(ip_address):
        log_traffic(ip_address, port, "BLOCKED (Rate Limit)", threat_level="HIGH")
        send_alert(ip_address, port, "RATE_LIMIT_EXCEEDED")
        return False
    
    # ================ เพิ่มใหม่: Blacklist Check ================
    if is_blacklisted(ip_address):
        log_traffic(ip_address, port, "BLOCKED (Blacklist)", threat_level="CRITICAL")
        send_alert(ip_address, port, "BLACKLISTED_IP")
        return False
    
    # ตรวจสอบตามกฎเดิม
    if ip_address in firewall_rules and firewall_rules[ip_address]:
        log_traffic(ip_address, port, "ALLOWED")
        return True
    if str(port) in firewall_rules and firewall_rules[str(port)]:
        log_traffic(ip_address, port, "ALLOWED")
        return True
    
    log_traffic(ip_address, port, "BLOCKED (No Rule)")
    return False


# ================ ฟังก์ชันใหม่ที่ 1: Logging System ================
def log_traffic(ip, port, status, threat_level="INFO"):
    """
    บันทึก log ของ traffic ทั้งหมด
    
    ประโยชน์:
    - ตรวจสอบย้อนหลังได้ว่ามี IP ไหนพยายามเข้ามาบ่อย
    - วิเคราะห์ pattern ของ attack
    - ใช้เป็นหลักฐานทางกฎหมายได้
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{threat_level}] {status}: {ip}:{port}\n"
    
    # เขียนลงไฟล์
    with open('firewall_log.txt', 'a', encoding='utf-8') as f:
        f.write(log_entry)
    
    # แสดงผลบนหน้าจอด้วย
    if threat_level in ["HIGH", "CRITICAL"]:
        print(f"🚨 {log_entry.strip()}")
    else:
        print(log_entry.strip())


# ================ ฟังก์ชันใหม่ที่ 2: Rate Limiting ================
traffic_counter = defaultdict(list)

def check_rate_limit(ip, max_requests=2, time_window=10):
    """
    ป้องกัน DDoS โดยจำกัดจำนวน request ต่อช่วงเวลา
    
    ประโยชน์:
    - ป้องกัน DDoS Attack (ส่ง request เยอะมากๆ)
    - ป้องกัน Brute Force Attack (ลองรหัสผ่านซ้ำๆ)
    - ลด Server Load จาก traffic ที่ผิดปกติ
    
    Args:
        ip: IP address ที่จะตรวจสอบ
        max_requests: จำนวน request สูงสุดที่อนุญาต (default: 5 ครั้ง)
        time_window: ช่วงเวลาที่ตรวจสอบ (default: 10 วินาที)
    """
    current_time = time.time()
    
    # ลบ timestamp เก่าที่เกินกว่า time_window
    traffic_counter[ip] = [t for t in traffic_counter[ip] 
                          if current_time - t < time_window]
    
    # ตรวจสอบว่าเกินจำนวนที่กำหนดไหม
    if len(traffic_counter[ip]) >= max_requests:
        return False  # บล็อก
    
    # บันทึก request ใหม่
    traffic_counter[ip].append(current_time)
    return True


# ================ ฟังก์ชันใหม่ที่ 3: Blacklist System ================
blacklist = {
    "10.0.0.5": "Known malicious IP - Port Scanner",
    "192.168.1.66": "Previous DDoS attacker",
    "172.16.0.100": "Brute force attempt detected"
}

def is_blacklisted(ip):
    """
    ตรวจสอบว่า IP อยู่ใน blacklist หรือไม่
    
    ประโยชน์:
    - บล็อก IP ที่รู้จักว่าเป็นอันตราย
    - ลดโอกาสโดนโจมตีซ้ำจาก IP เดิม
    - ประหยัด resource เพราะบล็อกทันที
    """
    return ip in blacklist

def add_to_blacklist(ip, reason):
    """เพิ่ม IP เข้า blacklist พร้อมระบุเหตุผล"""
    blacklist[ip] = reason
    print(f"➕ Added to blacklist: {ip} - Reason: {reason}")

def show_blacklist():
    """แสดง blacklist ทั้งหมด"""
    print("\n📋 Current Blacklist:")
    if not blacklist:
        print("  (Empty)")
    for ip, reason in blacklist.items():
        print(f"  • {ip}: {reason}")


# ================ ฟังก์ชันใหม่ที่ 4: Alert System ================
def send_alert(ip, port, alert_type):
    """
    ส่งการแจ้งเตือนเมื่อพบภัยคุกคาม
    
    ประโยชน์:
    - แจ้งเตือนทันทีเมื่อมีเหตุการณ์ผิดปกติ
    - สามารถตอบสนองได้เร็ว
    - ในระบบจริงอาจส่ง Email, SMS, หรือ Slack notification
    """
    alert_messages = {
        "RATE_LIMIT_EXCEEDED": "⚠️  ALERT: Possible DDoS attack detected",
        "BLACKLISTED_IP": "🛑 ALERT: Known malicious IP attempting access",
        "SUSPICIOUS_PORT": "🔍 ALERT: Access attempt on unusual port"
    }
    
    message = alert_messages.get(alert_type, "⚠️  ALERT: Security event detected")
    print(f"\n{'='*60}")
    print(f"{message}")
    print(f"IP: {ip} | Port: {port} | Time: {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}\n")


# ================ ฟังก์ชันจำลอง Traffic ================
def simulate_network_traffic():
    """Simulates network traffic and applies firewall rules."""
    print("🔥 Enhanced Firewall Simulator Started")
    print("="*60)
    print("Features:")
    print("  ✓ Traffic Logging (saves to firewall_log.txt)")
    print("  ✓ Rate Limiting (max 2 requests per 10 seconds)")
    print("  ✓ Blacklist Protection")
    print("="*60)
    print(f"\nSimulating  requests... (Press Ctrl+C to stop early)\n")
    
    try:
        iteration = 0
        while True:
            iteration += 1
            
            # สร้าง traffic แบบสุ่ม
            ip_address = ".".join(str(random.randint(0, 255)) for _ in range(4))
            port = random.randint(1, 65535)
            
            # 20% โอกาสที่จะเป็น IP ที่อนุญาต
            if random.random() < 0.2:
                ip_address = "192.168.1.100"
                port = random.choice([80, 443])
            
            # 15% โอกาสที่จะส่ง request เร็วมาก (จำลอง DDoS)
            elif random.random() < 0.15:
                ip_address = "203.45.67.89"  # IP ที่จะโดน Rate Limit
                port = random.randint(1000, 9999)
                print(f"⚡ Simulating rapid requests from {ip_address}...")
            
            # 10% โอกาสที่จะเป็น IP ใน blacklist
            elif random.random() < 0.1:
                ip_address = random.choice(list(blacklist.keys()))
            
            print(f"\n--- Request #{iteration} ---")
            if check_firewall(ip_address, port):
                print(f"✅ Allowing traffic from {ip_address} on port {port}")
            else:
                print(f"❌ Blocking traffic from {ip_address} on port {port}")
            
            # แสดง blacklist ทุก 10 requests
            if iteration % 10 == 0:
                show_blacklist()
            
            # ปรับ delay: ถ้าเป็น IP ที่จำลอง DDoS ให้ส่งเร็วๆ
            if ip_address == "203.45.67.89":
                time.sleep(0.5)  # ส่งเร็วมาก เพื่อให้โดน Rate Limit
            else:
                time.sleep(1.5)  # ปกติ
            
    except KeyboardInterrupt:
        print("\n\n🛑 Firewall simulator stopped")
        print(f"Total requests processed: {iteration}")
        print("Check 'firewall_log.txt' for complete logs")


if __name__ == "__main__":
    simulate_network_traffic()