from setuptools import setup, find_packages

setup(
    name="network_security_tool",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "PyQt6>=6.4.0",
        "cryptography>=41.0.0",
        "requests>=2.31.0",
        "scapy>=2.5.0",
        "python-nmap>=0.7.1",
        "passlib>=1.7.4",
    ],
    author="Your Name",
    author_email="your.email@example.com",
    description="A comprehensive network security toolkit",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/network-security-tool",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
) 