# CRNS - Cryptographic Secure Communication System

A secure communication system developed using Python and Streamlit to demonstrate cryptographic techniques for secure message communication.

## Features

- RSA-2048 key generation
- AES-256-GCM encryption and decryption
- RSA-OAEP encryption
- RSA-PSS digital signatures
- SHA-256 hashing
- Interactive Streamlit interface
- Secure message encryption and verification

## Technologies Used

- Python
- Streamlit
- PyCryptodome
- RSA
- AES-256-GCM
- SHA-256

## Project Structure

```text
CRNS/
│
├── app.py
├── requirements.txt
└── README.md
```

## Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## How to Run

Run the Streamlit application:

```bash
streamlit run app.py
```

The application will open in your web browser.

## Project Purpose

This project demonstrates the practical implementation of cryptographic algorithms for secure communication, including confidentiality, integrity, authentication, and digital signatures.

## Future Improvements

- Secure key storage
- User authentication
- File encryption support
- Enhanced communication features
- Cloud deployment