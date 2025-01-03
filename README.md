# scanSXv1

scanSXv1 is a web security analysis tool designed for testing common web application vulnerabilities such as SQL Injection and Cross-Site Scripting (XSS). The tool also includes a URL scanner for analyzing internal links in web applications. It is built to work seamlessly on Kali Linux or similar environments.

## Features
- **URL Scanner**: Analyzes internal links of a web application and generates a site map.
- **SQL Injection Scanner**: Tests for SQL Injection vulnerabilities using various techniques like Union-based, Error-based, and Time-based injection.
- **XSS Scanner**: Identifies reflected and form-based Cross-Site Scripting (XSS) vulnerabilities with dynamic payloads.
- Modular and extensible structure for future enhancements.

## Requirements
- Python 3.7 or above
- Required Python libraries are listed in `requirements.txt`

## Installation
1. Clone this project:
   ```bash
   git clone https://github.com/<Serhatti-007>/scanSXv1.git
2. Install setup:
   - cd scanSXv1
   - chmod +x setup.sh
   - ./setup.sh
3. Run the tool:
   python scanSXv1.py

## Disclaimer
This tool is intended for educational purposes and authorized security testing only. Unauthorized usage against websites or applications is illegal and strictly prohibited.