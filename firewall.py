import socket
import time
import random
import json
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
from datetime import datetime
from collections import defaultdict

# ================ ตัวแปร Global สำหรับควบคุม GUI ================
is_running = False
gui_app = None

# ================ ฟังก์ชันเดิม (Logic ของ Firewall) ================
def create_firewall_rules():
    """กำหนดชุดกฎของ Firewall โดยสามารถปรับแต่งกฎเหล่านี้ได้ตามต้องการ ฟังก์ชันนี้จะคืนค่าเป็น Dictionary 
    ซึ่งมี Key เป็น IP Address หรือ Port และมี Value เป็นค่า Boolean (True/False) ที่ระบุว่าอนุญาตให้ผ่านได้หรือไม่"""
    firewall_rules = {
        "192.168.1.100": True,
        "80": True,
        "443": True
    }
    return firewall_rules

def check_firewall(ip_address, port):
    """ตรวจสอบว่าการรับส่งข้อมูล (Traffic) ได้รับอนุญาตให้ผ่านหรือไม่ โดยอ้างอิงจากกฎของ Firewall"""
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


# ================ ฟังก์ชันใหม่ที่ 1: Logging System (แก้ไขสำหรับ GUI) ================
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
    
    # เขียนลงไฟล์ (ใช้ mode 'a' เพื่อต่อท้ายใน session นี้)
    # หมายเหตุ: การล้างไฟล์เก่าทำที่ฟังก์ชัน clear_log_file() ตอนเริ่มโปรแกรม
    with open('firewall_log.txt', 'a', encoding='utf-8') as f:
        f.write(log_entry)
    
    # แสดงผลบน GUI และ Console
    if gui_app:
        gui_app.update_log_display(log_entry.strip(), threat_level)
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
    if gui_app:
        gui_app.update_blacklist_display()
    print(f"➕ Added to blacklist: {ip} - Reason: {reason}")

def show_blacklist():
    """แสดง blacklist ทั้งหมด"""
    # ฟังก์ชันนี้ถูกแทนที่ด้วยการแสดงผลบน GUI
    pass


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
    
    full_msg = f"{message} | IP: {ip}"
    if gui_app:
        gui_app.update_alert_display(full_msg)
    print(full_msg)

# ================ ฟังก์ชันเคลียร์ Log ================
def clear_log_file():
    """
    ล้างข้อมูลในไฟล์ log เก่าทั้งหมดเมื่อเริ่มโปรแกรม
    ประโยชน์:
    - ง่ายต่อการตรวจสอบและ Debug โปรแกรม
    - ลดความสับสนเมื่อมีการแก้ไขกฎ Firewall
    - ป้องกันไฟล์ Log มีขนาดใหญ่เกินความจำเป็น
    """
    with open('firewall_log.txt', 'w', encoding='utf-8') as f:
        f.write("") # เขียนทับด้วยค่าว่าง
    print("🧹 Log file cleared.")

# ================ ส่วนของ GUI Application ================
class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Firewall Simulator")
        # --- กำหนดขนาดหน้าต่าง ---
        window_width = 1000
        window_height = 700
        # --- คำนวณหาจุดกึ่งกลางจอ ---
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        # หาจุด x, y ที่จะทำให้หน้าต่างอยู่ตรงกลาง
        center_x = int(screen_width/2 - window_width/2)
        center_y = int(screen_height/2 - window_height/2)
        # ตั้งค่า geometry (ขนาด + ตำแหน่ง)
        self.root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
        
        self.root.configure(bg="#f0f0f0")

        # --- ส่วนหัว ---
        header_frame = tk.Frame(root, bg="#2c3e50", pady=10)
        header_frame.pack(fill=tk.X)
        tk.Label(header_frame, text="🛡️ Enhanced Firewall Simulator", font=("Arial", 20, "bold"), fg="white", bg="#2c3e50").pack()
        tk.Label(header_frame, text="Logs saved to: firewall_log.txt (Auto-cleared on start)", font=("Arial", 10), fg="#bdc3c7", bg="#2c3e50").pack()

        # --- ปุ่มควบคุม ---
        control_frame = tk.Frame(root, pady=10, bg="#f0f0f0")
        control_frame.pack()
        
        self.btn_start = tk.Button(control_frame, text="▶ Start Simulation", command=self.start_simulation, bg="#27ae60", fg="white", font=("Arial", 12, "bold"), width=15)
        self.btn_start.pack(side=tk.LEFT, padx=10)
        
        self.btn_stop = tk.Button(control_frame, text="⏹ Stop", command=self.stop_simulation, bg="#c0392b", fg="white", font=("Arial", 12, "bold"), width=15, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=10)

        # --- พื้นที่แสดงข้อมูล (แบ่งซ้าย-ขวา) ---
        main_content = tk.Frame(root, bg="#f0f0f0")
        main_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # ฝั่งซ้าย: Live Logs
        left_panel = tk.LabelFrame(main_content, text="Traffic Logs", font=("Arial", 12, "bold"), bg="#f0f0f0")
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        self.log_area = scrolledtext.ScrolledText(left_panel, height=20, font=("Consolas", 10), state='disabled', bg="black", fg="#00ff00")
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # กำหนดสีตัวอักษร
        self.log_area.tag_config("INFO", foreground="#00ff00")      # สีเขียว
        self.log_area.tag_config("ALLOWED", foreground="#00ff00")   # สีเขียว
        self.log_area.tag_config("BLOCKED", foreground="#f1c40f")   # สีเหลือง
        self.log_area.tag_config("HIGH", foreground="#e67e22")      # สีส้ม
        self.log_area.tag_config("CRITICAL", foreground="#e74c3c")  # สีแดง

        # ฝั่งขวา: Blacklist & Alerts
        right_panel = tk.Frame(main_content, bg="#f0f0f0", width=300)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, padx=5)

        # ส่วนแสดง Alert
        alert_frame = tk.LabelFrame(right_panel, text="⚠️ Recent Alerts", font=("Arial", 12, "bold"), bg="#f0f0f0", fg="red")
        alert_frame.pack(fill=tk.X, pady=5)
        self.alert_list = tk.Listbox(alert_frame, height=8, fg="red", font=("Arial", 10))
        self.alert_list.pack(fill=tk.X, padx=5, pady=5)

        # ส่วนแสดง Blacklist
        blacklist_frame = tk.LabelFrame(right_panel, text="🚫 Blacklist Rules", font=("Arial", 12, "bold"), bg="#f0f0f0")
        blacklist_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Treeview สำหรับ Blacklist
        columns = ('IP', 'Reason')
        self.blacklist_tree = ttk.Treeview(blacklist_frame, columns=columns, show='headings', height=10)
        self.blacklist_tree.heading('IP', text='IP Address')
        self.blacklist_tree.heading('Reason', text='Reason')
        self.blacklist_tree.column('IP', width=120)
        self.blacklist_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.update_blacklist_display()

    def update_log_display(self, message, threat_level):
        """อัปเดตข้อความลงบน GUI Log"""
        self.log_area.config(state='normal')
        
        # เลือก Tag สีตามระดับภัยคุกคาม
        tag = "INFO"
        if "ALLOWED" in message: tag = "ALLOWED"
        elif "BLOCKED" in message: tag = "BLOCKED"
        if threat_level == "HIGH": tag = "HIGH"
        if threat_level == "CRITICAL": tag = "CRITICAL"

        self.log_area.insert(tk.END, message + "\n", tag)
        self.log_area.see(tk.END) # Auto scroll
        self.log_area.config(state='disabled')

    def update_alert_display(self, message):
        """เพิ่ม Alert ลงในรายการ"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.alert_list.insert(0, f"[{timestamp}] {message}") # Insert ที่ด้านบนสุด
        if self.alert_list.size() > 20: # เก็บแค่ 20 รายการล่าสุด
            self.alert_list.delete(20, tk.END)

    def update_blacklist_display(self):
        """รีเฟรชตาราง Blacklist"""
        for item in self.blacklist_tree.get_children():
            self.blacklist_tree.delete(item)
        for ip, reason in blacklist.items():
            self.blacklist_tree.insert('', tk.END, values=(ip, reason))

    def start_simulation(self):
        global is_running
        if not is_running:
            is_running = True
            self.btn_start.config(state=tk.DISABLED)
            self.btn_stop.config(state=tk.NORMAL)
            
            # รัน Simulation ใน Thread แยก เพื่อไม่ให้ GUI ค้าง
            self.thread = threading.Thread(target=run_simulation_loop)
            self.thread.daemon = True
            self.thread.start()

    def stop_simulation(self):
        global is_running
        is_running = False
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.update_log_display("🛑 Simulation Stopped.", "INFO")

# ================ ฟังก์ชัน Loop จำลอง Traffic (แยกออกมาเพื่อ Threading) ================
def run_simulation_loop():
    iteration = 0
    while is_running:
        iteration += 1
        
        # สร้าง traffic แบบสุ่ม
        ip_address = ".".join(str(random.randint(0, 255)) for _ in range(4))
        port = random.randint(1, 65535)
        
        if random.random() < 0.2:
            ip_address = "192.168.1.100"
            port = random.choice([80, 443])
        elif random.random() < 0.15:
            ip_address = "203.45.67.89"
            port = random.randint(1000, 9999)
        elif random.random() < 0.1:
            ip_address = random.choice(list(blacklist.keys()))
        
        # ตรวจสอบ Firewall
        check_firewall(ip_address, port)
        
        # ปรับ Delay
        if ip_address == "203.45.67.89":
            time.sleep(0.5)
        else:
            time.sleep(1.5)

if __name__ == "__main__":
    # 1. ล้าง Log เก่าทิ้งก่อนเริ่มโปรแกรม
    clear_log_file()
    
    # 2. เริ่มต้น GUI
    root = tk.Tk()
    gui_app = FirewallGUI(root)
    root.mainloop()