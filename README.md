# DarkAI – Intelligent Dark Web Crawler & Threat Analyzer

DarkAI is an AI-powered cybersecurity research system that crawls dark web (.onion) websites through the Tor network and classifies them as safe or malicious using Computer Vision (OCR) and Natural Language Processing (NLP).

Unlike traditional scrapers that rely solely on HTML parsing, DarkAI analyzes visually rendered content, enabling effective analysis of JavaScript-heavy pages, obfuscated text, or image-based content. This project is intended strictly for academic research and is suitable as a B.Tech Final Year Major Project.

---

## Project Objectives

- Crawl dark web websites anonymously using the Tor network  
- Extract visible content using OCR  
- Classify websites using AI-based NLP models  
- Recursively discover and analyze linked onion sites  
- Prevent deadlocks and infinite crawl loops  
- Provide an ethical, reproducible cybersecurity research framework  

---

## System Overview

DarkAI operates as a persistent crawler service.

1. System initializes and loads all AI models  
2. Remains idle while waiting for a submitted dark web URL  
3. When a URL is provided, crawling and analysis begin  
4. Newly discovered onion links are recursively analyzed  

---

## How the System Works

1. User submits a `.onion` URL  
2. All requests are routed through the Tor network  
3. Page is rendered using a headless browser (Selenium + Chromium)  
4. A screenshot of the rendered page is captured  
5. OCR extracts visible text  
6. NLP models analyze the extracted content  
7. The site is classified as Safe or Threat  
8. New onion links are discovered and added to the queue  
9. Crawling continues recursively  

---

## System Architecture

(Architecture reference: `doc/architecture.png`)

The system uses a Tor-based crawling pipeline integrated with AI models that classify dark web content and recursively discover new links without deadlocks.

---

## Technologies Used

- Python 3  
- Tor (SOCKS5 Proxy)  
- Selenium (Headless Chromium)  
- EasyOCR  
- HuggingFace Transformers  
- Docker & Docker Compose  

---

## Project Structure

```
DarkAI/
├── data/                     # Runtime data (generated at execution)
│   └── .gitkeep              # Keeps empty folder tracked by Git
├── sentinel/                 # Core crawler + AI engine
│   ├── Dockerfile            # Docker image definition
│   ├── main.py               # Main crawler execution logic
│   └── requirements.txt      # Python dependencies
├── docker-compose.yml        # Multi-container orchestration (Tor + Sentinel)
├── README.md                 # Project documentation
├── LICENSE                   # Open-source license
└── .gitignore                # Ignored files and folders 
```

How to Use
```Step 1: Start the System```

From the project root directory:

```docker compose up -d --build```

This starts the Tor service and the Sentinel-AI crawler container.

Step 2: Verify System Logs
```docker logs -f sentinel-ai```

Expected output:

[*] Initializing AI models
```
Using CPU. Note: This module is much faster with a GPU.
[✓] Tor connection established
[✓] Sentinel-AI ready
[⏳] Waiting for target URL...
```
Step 3: Submit a Dark Web URL
```docker exec -it sentinel-ai python main.py http://example.onion```

Notes:

```Include http://```

Submit one seed URL at a time

Step 4: View Crawling Output

Example:
```
[+] Seed added: http://example.onion
[>] Crawling http://example.onion (depth=0)
[✓] Search Engine | Threat=False
[>] Crawling /about (depth=1)
[✓] Directory | Threat=False
```
