# project imports
from feeds.cves import download_cves
from feeds.cwes import download_cwes
from feeds.exploits import download_exploits
from feeds.advisories import download_advisories
from feeds.twitter import download_tweets


def main():
    # download info about CVEs
    print('Downloading CVES...')
    download_cves()

    # download info about CWEs
    print('\nDownloading CWES...')
    download_cwes()

    # download info about exploits
    print('\nDownloading exploits...')
    download_exploits()

    # download info about advisories
    print('\nDownloading advisories...')
    download_advisories()

    # download info about CVE
    print('\nDownloading tweets...')
    download_tweets()


if __name__ == '__main__':
    main()
