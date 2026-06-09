# ⚡ SUDOIT - Professional WiFi Penetration Testing Framework

> **"With great power comes great responsibility"**

---

## 👤 Author

**Created by:** CR0WNNE0_fuxv>#SUDOIT  
**Team:** Ethical Hacker Lab  
**Project:** SUDOIT Framework  
**Version:** 1.0.0

---

## ⚠️ DISCLAIMER / PERINGATAN

### 🇬🇧 English:
**THIS TOOL IS FOR EDUCATIONAL PURPOSES AND AUTHORIZED TESTING ONLY!**

- This framework is designed for security professionals and ethical hackers
- **NEVER** use this tool on networks you don't own or have written permission to test
- Unauthorized access to computer networks is **ILLEGAL** and punishable by law
- The author is **NOT RESPONSIBLE** for any misuse, damage, or illegal activities
- By using this tool, you agree to use it **ETHICALLY** and **LEGALLY**
- Always obtain **WRITTEN PERMISSION** before testing any network

### 🇮🇩 Bahasa Indonesia:
**ALAT INI HANYA UNTUK TUJUAN PENDIDIKAN DAN PENGUJIAN YANG DIIZINKAN!**

- Framework ini dirancang untuk profesional keamanan dan ethical hacker
- **JANGAN PERNAH** gunakan alat ini pada jaringan yang bukan milik Anda atau tanpa izin tertulis
- Akses tidak sah ke jaringan komputer adalah **ILEGAL** dan dapat dihukum oleh hukum
- Pembuat **TIDAK BERTANGGUNG JAWAB** atas penyalahgunaan, kerusakan, atau aktivitas ilegal
- Dengan menggunakan alat ini, Anda setuju untuk menggunakannya secara **ETIS** dan **LEGAL**
- Selalu dapatkan **IZIN TERTULIS** sebelum menguji jaringan apa pun

---

## 📋 Features

- 🔍 Advanced WiFi Scanner (2.4/5 GHz + OUI fingerprinting)
- 🤝 WPA/WPA2 Handshake Capture (automated deauth)
- 💀 PMKID Attack (clientless)
- 📡 Deauth Attack Detection
- 🔓 WPS Pixie Dust Attack
- 👻 Evil Twin Detection
- 📻 KARMA Attack (probe monitoring)
- 🚨 Beacon Flood Detection
- 🎭 MAC Spoofing & Randomization
- 🔑 Cracking Engine (aircrack-ng + hashcat)
- 📊 Report Generator (JSON/HTML/CSV/PDF)
- 🌐 Web Dashboard (Flask + WebSocket)
- 🔌 Plugin System
- 💾 SQLite Session Persistence

---

## 📦 Installation

```bash
# Prerequisites (Kali Linux)
sudo apt update
sudo apt install -y aircrack-ng reaver hcxtools hashcat python3-pip

# Clone & Install
git clone https://github.com/CR0WNNE0-fuxv/SUDOIT.git
cd SUDOIT
pip install -r requirements.txt

# Run
sudo python3 sudoit.py
