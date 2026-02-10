# 🕵️‍♂️ DarkAI – Intelligent Dark Web Crawler & Threat Analyzer

DarkAI is an AI-powered cybersecurity research system that crawls dark web (.onion) websites via the 🧅 **Tor network** and classifies them as **safe or malicious** using 🤖 **Computer Vision (OCR)** and 🧠 **Natural Language Processing (NLP)**.

Unlike traditional web scrapers that rely only on HTML parsing, DarkAI analyzes **visually rendered page content**, making it effective against JavaScript-rendered pages, obfuscated text, and image-based content commonly found on the dark web.

This project is developed strictly for 🎓 **academic research** and is suitable for a **B.Tech Final Year Major Project**.

---

## 🎯 Project Objectives

- 🧅 Crawl dark web websites anonymously using the Tor network  
- 👁️ Extract visible page content using computer vision (OCR)  
- 🧠 Classify websites using AI-based NLP models  
- 🔁 Recursively discover and analyze linked onion sites  
- 🚫 Prevent deadlocks and infinite crawling loops  
- ✅ Provide an ethical and reproducible cybersecurity research framework  

---

## 🧩 System Overview

DarkAI runs as a **long-running crawler service**.

1. 🚀 The system starts and initializes all AI models  
2. ⏳ It waits in an idle state for a user-submitted dark web URL  
3. ▶️ Once a URL is submitted, crawling and analysis begin automatically  
4. 🔗 Newly discovered onion links are recursively analyzed  

---

## ⚙️ How the System Works

1. 👤 The user submits a `.onion` URL  
2. 🧅 All network traffic is routed through the Tor network  
3. 🖥️ The page is rendered using a headless browser (Selenium + Chromium)  
4. 📸 A screenshot of the rendered page is captured  
5. 👁️ OCR extracts visible text from the screenshot  
6. 🧠 An NLP model analyzes the extracted text  
7. ⚠️ The website is classified as **Safe** or **Threat**  
8. 🔗 New onion links are discovered and added to the crawl queue  
9. 🔁 The crawling process continues automatically  

---

## 🧪 Technologies Used

- 🐍 Python 3  
- 🧅 Tor (SOCKS5 Proxy)  
- 🌐 Selenium with Headless Chromium  
- 👁️ EasyOCR (Computer Vision)  
- 🧠 HuggingFace Transformers (NLP)  
- 🐳 Docker & Docker Compose  

---

## 📁 Project Structure

DarkAI/
├── data/ # Runtime data (empty, ignored by Git)
│ └── .gitkeep
├── sentinel/
│ ├── Dockerfile
│ ├── main.py
│ └── requirements.txt
├── docker-compose.yml
├── README.md
├── LICENSE
└── .gitignore


---

## ▶️ How to Use

### 🔹 Step 1: Start the System

From the project root directory, run:
docker compose up -d --build

This starts:
- 🧅 Tor service  
- 🤖 Sentinel-AI crawler container  

---

### 🔹 Step 2: Verify System Logs

Check that the crawler is running and ready:

docker logs -f sentinel-ai

Expected logs:
[*] Initializing AI models
Using CPU. Note: This module is much faster with a GPU.
[✓] Tor connection established
[✓] Sentinel-AI ready
[⏳] Waiting for target URL...


✅ This confirms the system is running correctly.

---

### 🔹 Step 3: Submit a Dark Web URL

In a **new terminal**, submit a `.onion` URL:
docker exec -it sentinel-ai python main.py http://exampleonionaddress.onion

⚠️ Notes:
- Always include `http://`  
- Submit **one seed URL at a time**  

---

### 🔹 Step 4: Observe Crawling Output

Example output:
[+] Seed added: http://exampleonionaddress.onion

[>] Crawling http://exampleonionaddress.onion
 (depth=0)
[✓] Search Engine | Threat=False
[>] Crawling /about (depth=1)
[✓] Directory | Threat=False



Each log entry shows:
- 🌐 URL being crawled  
- 🔢 Crawl depth  
- 🧠 AI-detected category  
- ⚠️ Threat verdict  

---

## 🗃️ Data Handling

- ❌ No crawled data is committed to the repository  
- ❌ Runtime artifacts (databases, screenshots) are excluded via `.gitignore`  
- 📁 The `data/` directory remains empty for ethical and academic compliance  

---

## ⚖️ Ethical Considerations

This project is intended strictly for 🎓 **academic research and cybersecurity analysis**.

- ❌ No illegal activity is encouraged  
- ❌ Dark web data is not published  
- ✅ The repository contains only the analysis framework  

---

## 🎓 Academic Relevance

This project integrates concepts from:

- 🔐 Cyber Security  
- 🌐 Computer Networks  
- 🤖 Artificial Intelligence  
- 👁️ Computer Vision  
- 🧠 Operating Systems  
- 🛠️ Software Engineering  

It is suitable for submission as a **B.Tech Final Year Major Project**.

---

## 📜 License

MIT License
