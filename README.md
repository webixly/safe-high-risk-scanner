# 🛡️ Safe High-Risk Indicator Scanner (Passive)

## 🎓 University Research Project
This repository contains the official documentation and source code for **Safe High-Risk Indicator Scanner**,  
a **passive vulnerability assessment tool** developed as part of a **Cybersecurity Research Project** at **USTHB University**.

---

## 📘 Overview
The **Safe High-Risk Indicator Scanner** is a Python-based tool that performs **non-intrusive** (passive) analysis of web targets.  
It allows security students and researchers to identify and classify potential vulnerabilities based on **real CVE references**.

### 🔍 Key Features
- Passive vulnerability scanning (no exploitation).  
- Detection of outdated plugins and CMS components.  
- Integration with public CVE databases.  
- Categorization by risk level (Low / Medium / High / Critical).  
- Modular code architecture for easy customization and future upgrades.

---

## 🧠 Research Objectives
1. Understand and apply principles of **passive reconnaissance**.  
2. Identify and classify common **web vulnerabilities** ethically.  
3. Develop a **Python-based security tool** for academic purposes.  
4. Enhance documentation and research presentation skills.  

---

## 🧩 Technical Stack
| Component | Description |
|------------|-------------|
| **Language** | Python 3.x |
| **Libraries** | `requests`, `argparse`, `colorama`, `re`, `json` |
| **Platform** | Cross-platform (Linux, Windows, macOS) |
| **Interface** | Command Line (CLI) |

---

## ⚙️ Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/webixly/safe-high-risk-scanner.git
cd safe-high-risk-scanner
pip install -r requirements.txt
```

---

## 🚀 Usage

Run the scanner with a target URL:

```bash
python3 scanner-vul.py --url https://example.com
```

### Optional arguments:
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

## 📄 Example Output
```
[+] Target: https://example.com
[!] Detected CVE-2023-12345 (WordPress Plugin X)
[!] Risk Level: High
[+] Passive Analysis Completed Successfully.
```

---

## 🧾 Academic Context
This project is part of a university research course in **Cybersecurity & Network Systems**  
at **USTHB – Faculty of Electronics**.  
It demonstrates ethical vulnerability analysis methods and secure coding practices.

You can include a detailed research paper or report in a `/docs` folder for presentation.

---

## 🔮 Future Work
- Add a web-based dashboard for visual reporting.  
- Integrate AI/ML for vulnerability prediction.  
- Expand CVE database synchronization.  
- Implement automated scan scheduling.

---

## 🔐 Ethics and Legal Disclaimer
> This tool is developed strictly for **educational and research purposes**.  
> The authors and contributors are **not responsible for misuse** or illegal activity.  
> Use only on systems you have **explicit permission** to analyze.

---

## 👨‍💻 Author
**Name:** Pablo (Webixly)  
**University:** USTHB – Faculty of Electronics  
**Program:** Cybersecurity & Network Systems  
**GitHub:** [webixly](https://github.com/webixly)  
📧 **pablo.webixly@gmail.com**

---

## ⭐ Acknowledgments
- Professors and mentors from USTHB for academic guidance.  
- Open-source cybersecurity communities for shared tools and datasets.  
- Fellow students for collaboration and testing support.  

---

## 📚 License
This project is licensed under the [MIT License](LICENSE).  
You are free to use, modify, and share it with proper credit.
