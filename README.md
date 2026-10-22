# ScamGraph-AI
# 🛡️ ScamGraph AI
### AI-Powered Scam Detection & Threat Intelligence Platform

**Detect suspicious messages. Connect scam patterns. Visualize digital threats.**

ScamGraph AI is a web-based threat intelligence platform designed to help analyze suspicious messages and investigate potential scam incidents. It combines machine learning, message analysis, OCR-based text extraction, and interactive graph visualization to make suspicious communication patterns easier to explore.

The platform provides a centralized dashboard where users can submit suspicious information, review investigation reports, and visualize relationships between reported incidents.

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Problem Statement](#-problem-statement)
- [Our Solution](#-our-solution)
- [Key Features](#-key-features)
- [How It Works](#-how-it-works)
- [Technology Stack](#-technology-stack)
- [Project Structure](#-project-structure)
- [Installation and Setup](#-installation-and-setup)
- [Usage](#-usage)
- [Future Enhancements](#-future-enhancements)
- [Limitations](#-limitations)
- [Contributing](#-contributing)
- [Author](#-author)

---

## 🎯 Overview

Online scams often use deceptive messages, suspicious links, impersonation, and social engineering to trick people into sharing sensitive information or transferring money.

ScamGraph AI aims to make the initial investigation of suspicious communications more accessible by combining message analysis with a visual representation of reported incidents.

The project is developed using Python and Flask, with a web dashboard for interacting with the platform.

## ❗ Problem Statement

- Suspicious messages can be difficult for ordinary users to evaluate.
- Scam-related information may be scattered across separate reports.
- Investigators need a convenient way to review suspicious incidents and identify possible relationships.
- Manually reviewing large amounts of text and screenshots can be time-consuming.

## 💡 Our Solution

ScamGraph AI brings message analysis and incident visualization into one platform.

Users can submit suspicious message content for analysis, use OCR to extract text from supported images, review investigation reports, and explore connections represented in an interactive graph.

The goal is to support faster preliminary investigation and improve the visibility of potential scam patterns.

## ✨ Key Features

- **🤖 AI-Based Analysis:** Uses a machine-learning model to assist in classifying suspicious message content.
- **🔎 Suspicious Message Investigation:** Provides a workflow for examining potentially fraudulent communications.
- **🖼️ OCR Text Extraction:** Uses Tesseract OCR and Python integration to extract text from supported images.
- **🕸️ Graph Visualization:** Displays reported incidents and their represented relationships in a visual graph.
- **📊 Investigation Dashboard:** Brings analysis and investigation information together in one interface.
- **🗂️ Report History:** Stores investigation reports using SQLite.
- **🌐 Web-Based Interface:** Provides a browser-accessible interface built with Flask, HTML, and CSS.

*Feature availability and analysis results depend on the current implementation and the quality of the submitted data.*

## ⚙️ How It Works

1. **Submit information:** Provide suspicious message text or a supported image.
2. **Extract text:** For image-based input, OCR can be used to retrieve readable text.
3. **Analyze content:** The application processes the available text and uses its configured analysis or machine-learning workflow.
4. **Review the report:** Examine the available investigation results in the dashboard.
5. **Explore the graph:** View reported incidents and their represented connections to investigate potential patterns.

**Important:** A suspicious classification is an indication for further investigation, not proof that a message or sender is fraudulent.

## 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application logic |
| Flask | Web application and backend routes |
| Machine Learning | Message classification, where configured |
| HTML | Dashboard structure |
| CSS | Dashboard styling |
| Tesseract OCR | Text extraction from images |
| Pytesseract | Python interface for Tesseract OCR |
| SQLite | Local report storage |
| Joblib | Saving and loading the trained model, where used |
| Git & GitHub | Version control and project hosting |

## 📁 Project Structure

```text
ScamGraph-AI/
├── app.py
├── database.py
├── model.py
├── scamgraph.py
├── scam_model.joblib
├── requirements.txt
├── scamgraph.db
├── templates/
│   └── index.html
├── static/
│   └── style.css
└── README.md
```

- `app.py` — Flask application and web routes.
- `database.py` — Database-related operations.
- `model.py` — Machine-learning functionality.
- `scamgraph.py` — ScamGraph-related processing or graph logic.
- `scam_model.joblib` — Saved model artifact, if required by the application.
- `requirements.txt` — Python package dependencies.
- `scamgraph.db` — SQLite database containing local application data.
- `templates/index.html` — Main web interface.
- `static/style.css` — Dashboard styling.

## 🚀 Installation and Setup

### Prerequisites

Install the following before running the project:

- Python 3.10 or another version supported by your dependencies
- Git
- Tesseract OCR
- A web browser

### 1. Clone the repository

```bash
git clone https://github.com/ahanr1152-a11y/ScamGraph-AI.git
cd ScamGraph-AI
```

### 2. Create a virtual environment

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, you can run the following for the current terminal session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Tesseract OCR

Download and install Tesseract OCR for your operating system.

Official project: https://github.com/tesseract-ocr/tesseract

Make sure the Tesseract executable is installed and accessible to Pytesseract. On Windows, you may need to configure the executable path in your application.

### 5. Run the application

```bash
python app.py
```

Open the local URL printed in the terminal, typically:

```text
http://127.0.0.1:5000
```

Keep the terminal running while using the application.

## 🧪 Usage

1. Start the Flask application.
2. Open the dashboard in your browser.
3. Submit suspicious message content using the available interface.
4. Test image-based text extraction if OCR is supported by your current setup.
5. Review the investigation report and available analysis results.
6. Explore the graph visualization to inspect the represented incidents and relationships.

For meaningful testing, use sample messages and images that you have permission to analyze. Do not submit real people's sensitive information unnecessarily.

## 🔮 Future Enhancements

Potential improvements include:

- Improved classification accuracy using a larger and more diverse dataset.
- Explainable AI that highlights suspicious words, URLs, and message patterns.
- URL reputation and domain intelligence integrations.
- More advanced graph-based relationship analysis.
- Duplicate incident detection and report correlation.
- Exportable investigation reports.
- Authentication and role-based access for investigators.
- Secure deployment with persistent database storage.
- Evaluation metrics such as precision, recall, F1-score, and a confusion matrix.

These are planned possibilities, not necessarily features implemented in the current version.

## ⚠️ Limitations

- Machine-learning predictions may produce false positives or false negatives.
- OCR accuracy depends on image quality, language, and text clarity.
- Graph connections are only as reliable as the data and relationship logic used to create them.
- The current prototype should not be treated as a replacement for professional fraud investigation or security tools.
- Local SQLite data may not persist on hosting platforms that use ephemeral storage.
- A flagged message does not establish the identity or guilt of its sender.

## 🤝 Contributing

Contributions, bug reports, and suggestions are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Make your changes.
4. Test your changes locally.
5. Submit a pull request describing the improvement.

## 👨‍💻 Author

**Ahan Raj**

B.Tech CSE (AI & ML)  
Puran Murti Vidyapeeth

GitHub: [@ahanr1152-a11y](https://github.com/ahanr1152-a11y)

---

## 📄 License

No license has been specified yet. If you intend to allow others to reuse, modify, or distribute this project, consider adding an appropriate open-source license.

---

**ScamGraph AI — Turning suspicious messages into actionable investigation insights.**
