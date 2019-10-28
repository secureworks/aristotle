from setuptools import setup, find_packages

with open("README.rst", "r") as fh:
    long_description = fh.read()

setup(
    name="aristotle",
    version="1.0.3",
    author="David Wharton",
    description="Script and library for the viewing and filtering of Suricata and Snort rulesets based on interpreted key-value pairs present in the metadata keyword within each rule.",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/secureworks/aristotle",
    packages=find_packages(),
    install_requires=[
        "boolean.py>=3.6",
        "python-dateutil",
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Networking :: Firewalls",
    ],
    python_requires='>=2.7',
    keywords='suricata, snort, metadata, ruleset, BETTER, IDS, IPS, signatures',
    project_urls={
        'Documentation': 'https://aristotle-py.readthedocs.io/',
        'Source': 'https://github.com/secureworks/aristotle',
    },
)
