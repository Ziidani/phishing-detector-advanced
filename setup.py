from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="phishing-detector-advanced",
    version="1.0.0",
    author="Seu Nome",
    author_email="seu.email@example.com",
    description="Detector avançado de phishing com interface gráfica",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/seu-usuario/phishing-detector-advanced",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Education",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
        "Topic :: Education",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "phishing-detector=src.main:main",
        ]
    },
    include_package_data=True,
    package_data={
        "": ["data/*.txt", "data/*.pkl", "data/*.json"],
    },
)