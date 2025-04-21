from setuptools import setup, find_packages

setup(
    name="network-security-tool",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "PyQt6>=6.4.0",
        "python-nmap>=0.7.1",
        "dnspython>=2.2.1",
        "python-whois>=0.8.0",
        "cryptography>=38.0.0",
        "requests>=2.28.0",
        "scapy>=2.5.0"
    ],
    entry_points={
        "console_scripts": [
            "network-security-tool=network_security_tool.main:main",
        ],
    },
    author="Your Name",
    author_email="your.email@example.com",
    description="A comprehensive network security analysis tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/network-security-tool",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
) 