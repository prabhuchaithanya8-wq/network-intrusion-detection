# Network Intrusion Detection System

A Python-based educational network traffic analysis dashboard.

## Features
- CSV traffic analysis
- Rule-based suspicious activity detection
- Protocol distribution and traffic timeline charts
- Alert filtering and CSV export
- Automated unit tests

## Setup
1. Create and activate a Python virtual environment.
2. Install packages using `python -m pip install -r requirements.txt`.
3. Generate sample data using `python generate_data.py`.
4. Run the dashboard using `python -m streamlit run app.py`.
5. Run tests using `python -m pytest -v`.

The included dataset is synthetic. Detection rules are illustrative heuristics
and must be validated before use in a real security environment.
