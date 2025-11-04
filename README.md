# 🛡️ Safe High-Risk Indicator Scanner (Passive)

> A passive vulnerability assessment tool for academic cybersecurity research — developed at **USTHB University** 🎓  

---

## 🧭 Overview
The **Safe High-Risk Indicator Scanner** is a Python-based project that performs **non-intrusive** (passive) web analysis.  
It helps identify, classify, and document potential vulnerabilities using **real CVE references** —  
all while maintaining **ethical** and **legal** testing boundaries.

### ✨ Core Highlights
✅ Passive scanning — zero exploitation, 100% safe  
✅ Detects outdated CMS components and plugins  
✅ Integrates with public CVE databases  
✅ Organizes results by risk level: *Low / Medium / High / Critical*  
✅ Modular design — simple to extend and automate  

---

## 🎯 Research Objectives
1. Apply **passive reconnaissance** methods in ethical cybersecurity.  
2. Analyze and document **real-world vulnerabilities** responsibly.  
3. Build a **Python-based academic tool** for web risk analysis.  
4. Strengthen documentation, teamwork, and research reporting skills.  

---

## ⚙️ Technical Stack

| Component | Description |
|------------|-------------|
| 🐍 **Language** | Python 3.x |
| 📦 **Libraries** | `requests`, `argparse`, `colorama`, `re`, `json` |
| 💻 **Platform** | Cross-platform (Linux, Windows, macOS) |
| 🧩 **Interface** | Command Line (CLI) |

---

## 🚀 Installation

Clone the repository and install all dependencies:

```bash
git clone https://github.com/webixly/safe-high-risk-scanner.git
cd safe-high-risk-scanner
pip install -r requirements.txt
```

---

## 🧪 Usage

Run the scanner on any authorized target:

```bash
python3 scanner-vul.py --url https://example.com
```

### 🧰 Optional arguments

| Argument | Description |
|-----------|-------------|
| `--url` | Target URL to scan |
| `--output` | Save scan results to a file |
| `--level` | Scan depth (1 = basic, 3 = full) |

**Example:**
```bash
python3 scanner-vul.py --url https://example.com --level 3 --output report.txt
```

---

## 📊 Example Output
```
[+] Target: https://example.com
[!] Detected CVE-2023-12345 (WordPress Plugin X)
[!] Risk Level: High
[+] Passive Analysis Completed Successfully.
```

---

## 🎓 Academic Context
This repository is part of a **Cybersecurity & Network Systems** research project  
at **USTHB – Faculty of Electronics**.  

It demonstrates:
- Ethical passive reconnaissance methods  
- CVE-based vulnerability classification  
- Secure and responsible academic cybersecurity practices  

📁 A complete research paper or technical report can be included in a `/docs` folder for submission.

---

## 🔮 Future Work
🧠 Integrate AI/ML models for vulnerability prediction  
📊 Add a web dashboard for live visual reports  
🌐 Synchronize with external CVE APIs automatically  
⏰ Automate periodic passive scans  

---

## ⚖️ Ethics & Legal Disclaimer
> ⚠️ This tool is created **solely for educational and research purposes**.  
> The developers bear **no responsibility** for misuse or illegal activity.  
> Always ensure **explicit authorization** before scanning any target.

---

## 👨‍💻 Author

| Info | Details |
|------|----------|
| 🧑‍💻 **Name** | Pablo *(Webixly)* |
| 🎓 **University** | USTHB – Faculty of Electronics |
| 💼 **Program** | Cybersecurity & Network Systems |
| 🌐 **GitHub** | [webixly](https://github.com/webixly) |
| 📧 **Email** | Aymenmoh20000@gmail.com |

---

## 🌟 Acknowledgments
Special thanks to:
- 🧭 USTHB professors & mentors for continuous guidance  
- 💡 Open-source cybersecurity communities  
- 🤝 Fellow students who participated in testing and feedback  

---

## 📜 License
This project is licensed under the **[MIT License](LICENSE)**.  
You are free to use, modify, and share this project with proper credit.

---

> _"Security through knowledge — ethics through discipline."_ 🧠
