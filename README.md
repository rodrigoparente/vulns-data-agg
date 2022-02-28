# Vulnerabilities Data Aggregation

The code from this repository can be used to download and correlate information about known vulnerabilities from different security feed sources.

# Requirements

Install requirements using the following command

```bash
$ pip install -r requirements.txt
```

# Info Download

## NVD

To download vulnerability info from [NVD](https://nvd.nist.gov/), execute the following command:

```bash
$ python download_cves.py
```

## ExploitDB

To download exploit info from [ExploitDB](https://www.exploit-db.com/), execute the following command:

```bash
$ python download_exploits.py [parameters...]
```

### Parameters

 - `update_db` can be used to update exploits db (might take a while)

## Mitre e OWASP

To download top weakness info from [Mitre](https://cwe.mitre.org/) and [OWASP](https://owasp.org/www-project-top-ten/), execute the following command:

```bash
$ python download_weakness.py
```

# Merging data

To merge all different data into a single csv file:

```bash
$ python merge_cves_exploits.py
```

# Output

The result will be a csv file (named `cves_final.csv`) placed in the `output folder`, containing information about all known vulnerabilities, exploits, software and hardware weakness, etc.
