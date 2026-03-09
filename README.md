# PhishGuard - Real-Time Phishing Detection System

## 🎥 YouTube Demo
(Add YouTube video link here after upload)

## Project Description
PhishGuard is a high-performance cybersecurity application designed to detect phishing attempts in real-time. It combines rule-based heuristics (Headers) with Advanced AI (NLP & XGBoost) to provide a robust defense against malicious emails. The system features a responsive React-based dashboard that mimics a professional email client, allowing users to scan live inboxes or manually input suspicious content for analysis.

## Tech Stack
### Frontend
- **React**: Modern UI framework
- **Vite**: Ultra-fast frontend build tool
- **Vanilla CSS**: Premium, customized aesthetic with Glassmorphism
- **Lucide Icons**: Professional iconography

### Backend
- **Flask**: Python web framework for the API
- **Scikit-Learn**: Powering the NLP Naive Bayes model
- **XGBoost**: Advanced Gradient Boosting for URL analysis
- **IMAPLib**: Real-time Gmail integration
- **Joblib**: Efficient model persistence

## How to Run
### Prerequisites
- Python 3.8+
- Node.js & npm

### Backend Setup
1. Navigate to the `backend` directory.
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Create a `.env` file from `.env.template` and add your Gmail credentials.
5. Start the server:
   ```bash
   python app.py
   ```

### Frontend Setup
1. Navigate to the `frontend` directory.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the development server:
   ```bash
   npm run dev
   ```

## Local Server
The backend runs on `http://127.0.0.1:5000` and the frontend typically on `http://localhost:5173`.
