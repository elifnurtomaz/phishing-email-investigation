\# Phishing Email Investigation \& IOC Extraction Tool



\## 1. Project Overview



This project focuses on phishing email investigation and automated Indicator of Compromise (IOC) extraction using Python.



The project combines manual email analysis with a Python-based extraction tool to identify potentially suspicious indicators from EML files.



The extracted indicators are exported into CSV format for further investigation and threat intelligence analysis.



\## 2. Project Objectives



\- Investigate suspicious email messages.

\- Analyze email headers and HTML content.

\- Extract email addresses, URLs, domains, hostnames, and IPv4 addresses.

\- Identify HTML links and external resources.

\- Automate IOC extraction using Python.

\- Generate structured CSV reports.

\- Validate extraction results through automated tests.



\## 3. Features



\### Email Analysis

\- EML file parsing

\- Email header inspection

\- Sender and recipient extraction

\- SMTP envelope sender extraction



\### IOC Extraction

\- Email address extraction

\- URL extraction from HTML and plain-text content

\- HTML href and src identification

\- Domain and hostname extraction

\- IPv4 extraction from selected email headers

\- Defanging of extracted indicators



\### Reporting

\- CSV report generation

\- Duplicate indicator handling

\- Evidence location tracking

\- Extraction status documentation



\### Automated Testing

\- Synthetic EML fixture testing

\- Indicator validation

\- Duplicate detection testing

\- Missing file handling



\## 4. Technologies Used



\- Python

\- Regular Expressions (re)

\- Email Parsing

\- HTML Parsing

\- CSV Processing

\- IP Address Validation

\- Unit Testing



\## 5. Project Structure



phishing-email-investigation/

│

├── .gitignore

├── README.md

├── scripts/

│   └── extract\_iocs.py

└── tests/

&#x20;   ├── fixtures/

&#x20;   │   └── synthetic-email-01.eml

&#x20;   └── test\_extractor.py



\## 6. Installation and Usage



\### Requirements



\- Python 3.14 or compatible Python 3.x version

\- No external Python packages required



\### Run the IOC Extractor



Analyze the synthetic test email:



python scripts/extract\_iocs.py tests/fixtures/synthetic-email-01.eml



\### Output



The tool generates a CSV report in the reports directory.



Example:



reports/synthetic-email-01\_ioc\_extraction.csv



\## 7. Automated Testing



Run the test suite using:



python -m unittest discover -s tests -v



The current test suite contains five automated tests:



\- Expected indicator extraction

\- HTML href and src identification

\- Missing email file handling

\- Synthetic email extraction

\- Duplicate indicator validation



Current test status: 5 tests passed.



\## 8. Security Considerations



\- Extracted URLs are not accessed or executed.

\- Email attachments are not opened.

\- Extracted indicators are defanged where applicable.

\- IOC extraction does not automatically determine whether an indicator is malicious.

\- External threat intelligence platforms are used separately for reputation investigation.



\## 9. Project Limitations



\- The current version processes one EML file per execution.

\- Extraction is based on selected email headers and message content.

\- IPv4 extraction is limited to selected email headers.

\- Reputation analysis is not automated.

\- Extracted indicators require further validation.



\## 10. Future Improvements



\- Batch processing of multiple EML files

\- Enhanced email header analysis

\- Additional IOC extraction patterns

\- Improved error handling

\- Automated HTML report generation

\- Integration with threat intelligence APIs

