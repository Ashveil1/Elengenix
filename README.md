# Elengenix AI Framework

The Universal AI Agent for Bug Bounty and Security Research.

Elengenix is a next-generation security framework that combines the reasoning capabilities of Large Language Models (LLMs) with a professional-grade security toolchain. Built for speed, modularity, and professional automation.

Current Status: Intensive R&D Phase. Focus on core agent orchestration and security module integration.

---

## Key Features

- Autonomous Agent: Intelligent reasoning for multi-step security missions.
- Universal Mode: A versatile interface for any task beyond security.
- Security Arsenal: Integrated tools including Subfinder, Nuclei, Httpx, Katana, and more.
- Permanent Memory: Vector-based semantic memory for recalling past findings and interactions.
- Telegram Gateway: Remote control and monitoring via secure Telegram bot.
- Watchman Daemon: 24/7 continuous target monitoring with change detection.
- Professional UI: Clean, text-based terminal interface using the Rich library.

---

## Quick Start

### Prerequisites

- Python 3.10+
- Go 1.20+ (for security tools)
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/Ashveil1/Elengenix.git
cd Elengenix

# For Linux/Ubuntu users:
chmod +x setup.sh
./setup.sh

# For Termux (Android) users:
chmod +x termux_setup.sh
./termux_setup.sh
```

### Configuration

1. Create a .env file in the root directory.
2. Add your API keys:
   ```env
   GEMINI_API_KEY=your_google_ai_key
   TELEGRAM_BOT_TOKEN=your_bot_token
   TELEGRAM_CHAT_ID=your_chat_id
   ```

3. Run the system health check:
   ```bash
   python3 main.py doctor
   ```

---

## วิธีใช้งาน (Usage)

การใช้งาน Elengenix สามารถทำได้ผ่านหลายช่องทาง ดังนี้:

### 1. การใช้งานผ่าน CLI Launcher (แนะนำ)
ใช้คำสั่งนี้เพื่อเปิดเมนูหลักของระบบ:
```bash
python3 elengenix_launcher.py
```

### 2. คำสั่งที่พบบ่อย (Common Commands)
คุณสามารถรันคำสั่งโดยตรงผ่าน main.py:
- ตรวจสอบความพร้อมของระบบ: `python3 main.py doctor`
- เริ่มภารกิจความปลอดภัย: `python3 main.py mission <target>`
- แชทกับ AI: `python3 main.py ai`
- ใช้งานเครื่องมือ Security: `python3 main.py arsenal`
- ตรวจสอบเป้าหมายแบบ 24/7: `python3 main.py watchman`

---

## สิ่งที่จำเป็นสำหรับการอัพเกรด (Upgrade Guide)

เพื่อให้ Elengenix ทำงานได้อย่างมีประสิทธิภาพและมีฟีเจอร์ล่าสุดเสมอ ควรทำตามขั้นตอนดังนี้:

1. อัพเดทซอร์สโค้ด:
   ```bash
   git pull origin main
   ```

2. อัพเดท Library ที่จำเป็น:
   ```bash
   pip install -r requirements.txt --upgrade
   ```

3. ตรวจสอบและซ่อมแซมส่วนประกอบ:
   รันคำสั่ง doctor เพื่อตรวจสอบว่าเครื่องมือและ Dependency ทั้งหมดพร้อมใช้งาน:
   ```bash
   python3 main.py doctor
   ```

4. อัพเดทฐานข้อมูลความรู้ (ถ้ามี):
   หากมีการเปลี่ยนแปลงโครงสร้างฐานข้อมูล ระบบจะแจ้งเตือนเมื่อรันคำสั่ง doctor

---

## Project Structure

- main.py: Core CLI entry point and command router.
- agent_brain.py: Autonomous reasoning engine.
- orchestrator.py: Tool execution and pipeline management.
- ui_components.py: Standardized UI elements and design tokens.
- tools/: Modular security tool integrations.
- data/: Local logs, state, and vector databases.

---

## Contributing

We welcome contributions from the security and AI community. Please refer to CONTRIBUTING.md for our coding standards and development guidelines.

## License

This project is licensed under the GPL License - see the LICENSE file for details.

---

Developed by Ashveil1.
