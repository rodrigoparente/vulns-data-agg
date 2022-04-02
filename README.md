# Vulnerabilities Data Aggregation

The code from this repository can be used to download and correlate information about known vulnerabilities from different security feed sources, such as:

 - NIST
 - MITRE
 - OWASP
 - ExploitDB
 - Multiples Security Advisories (Microsoft, Adobe, Intel, etc)
 - Twitter

# Requirements

Install requirements using the following command

```bash
$ pip install -r requirements.txt
```

# Execute

Execute the code using the following command

```bash
$ python main.py
```

# Output

The result will be a csv file (named `vulns.csv`) placed in the `output folder`, containing information about all known vulnerabilities, exploits, security advisories, software and hardware weakness, etc.

# License

This project is [GNU GPLv3 licensed](./LICENSE).