# Cloudflare-Management

## Application Overview

This graphical application, developed using the PySide6 and cryptography libraries, allows users to manage and configure various settings related to DNS, SSL/TLS, and network configurations. To use this application, you need an API key that grants you access to these settings. The application uses the API key to update and manage the configurations.

Features
DNS Management:

Add and remove DNS records.
View the current DNS status.
Update DNS settings.
SSL/TLS Management:

Generate and manage public and private keys.
Create Certificate Signing Requests (CSR).
Install and manage SSL/TLS certificates.
Network Management:

Configure network settings.
View the current network connection status.
Test and troubleshoot network issues.


### Application Installation Instructions

The application can be installed using two methods: via an executable file provided in the release or by manually installing the application.

## Method 1: Using the Executable File  (Recommended for Windows user)

Download the Executable:

Go to the release [https://github.com/090ebier/Cloudflare-Management/releases/tag/v1.0.1] section of the project's repository and download the provided .exe file.
Run the Executable:

Double-click the downloaded .exe file to run the application. Follow the on-screen instructions to complete the installation.

## Method 2: Manual Installation  (Recommended for Ubuntu user)

Step 1: Clone the Repository

Open a terminal or command prompt.
Clone the repository using the following command:
```
git clone https://github.com/090ebier/Cloudflare-Management.git
cd Cloudflare-Management
pip install -r requirements.txt
```
```
python Cloudflare-Management.py
```

