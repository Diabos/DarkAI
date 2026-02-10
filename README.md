# DarkAI – Intelligent Dark Web Crawler & Threat Classifier

DarkAI is an AI-powered dark web crawling system that discovers `.onion` websites over the Tor network and classifies them using **computer vision (OCR)** and **natural language processing (NLP)**.

Unlike traditional scrapers, DarkAI analyzes **visually rendered content**, making it resilient against obfuscation, JavaScript-rendered pages, and image-based text.

---

## 🚀 Features

- 🧅 Crawls dark web (.onion) sites via Tor
- 🖥️ Renders pages using headless Chromium
- 👁️ Computer Vision using EasyOCR
- 🧠 NLP-based threat classification (Transformers)
- 🔁 Recursive crawling with depth control
- 🧾 Deadlock-free queue system
- 🐳 Fully Dockerized (one-command setup)

---

## 🧠 System Architecture

1. User submits a `.onion` URL
2. Page is loaded via Tor
3. Screenshot is captured
4. OCR extracts visible text
5. NLP model classifies content
6. New links are discovered and queued
7. Process continues automatically

---

## ⚙️ Tech Stack

- **Python 3.10**
- **Tor (SOCKS5)**
- **Selenium + Chromium**
- **EasyOCR**
- **HuggingFace Transformers**
- **SQLite**
- **Docker & Docker Compose**

---

## 🛠️ Installation (2 Commands)

### Prerequisites
- Docker Desktop
- Internet access (Tor bootstrap)

### Steps

```bash
git clone https://github.com/Diabos/DarkAI.git
cd DarkAI
docker compose up -d --build
