# Hamisecure

Hamisecure is an explainable email fraud detection system designed to classify emails as either legitimate or fraudulent. It uses machine learning models to predict email fraud and explains predictions based on various features like urgency, sensitive information request, domain analysis, and more.

## Features

- IMAP scanning for email inbox
- File upload for email analysis (supports .eml, .txt, .html)
- Fraud prediction with feature explanation
- Allowlist domain to avoid false positives

## How to Run

1. Clone this repository
2. Create a virtual environment: `python -m venv venv`
3. Install dependencies: `pip install -r requirements.txt`
4. Train the model: `python train.py`
5. Start the application: `python app.py`
6. Open your browser at `http://127.0.0.1:5000`

## Contributing

Feel free to fork and create pull requests. Contributions are welcome!

