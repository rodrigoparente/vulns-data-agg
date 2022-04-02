# project imports
from feeds.cves import download_cves
from feeds.cwes import download_cwes
from feeds.exploits import download_exploits
from feeds.advisories import download_advisories
from feeds.twitter import download_tweets


def main():
    # download info about CVEs
    download_cves()

    # download info about CWEs
    download_cwes()

    # download info about exploits
    download_exploits()

    # download info about advisories
    download_advisories()

    # download info about CVE
    download_tweets()


if __name__ == '__main__':
    main()
