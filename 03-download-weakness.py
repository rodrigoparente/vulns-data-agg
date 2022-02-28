# python imports
import os
import zipfile
from io import BytesIO
from urllib.request import urlopen

# third-party imports
import requests
from bs4 import BeautifulSoup


def main(weakness_feed, mitre_csv, mitre_id, owasp_csv, owasp_id):

    print('Preparing output folder...')

    # create output folder if it doesnt exists
    dirs = os.path.split(mitre_csv)[0]
    if not os.path.exists(dirs):
        os.makedirs(dirs)

    # delete output file if it exists
    for file_path in [mitre_csv, owasp_csv]:
        if os.path.exists(file_path):
            os.remove(file_path)

    # retrieving page
    source = requests.get(weakness_feed, headers={'User-Agent': 'Mozilla/5.0'}).text
    soup = BeautifulSoup(source, 'lxml')

    print('Downloading Mitre top 25 file...')

    try:
        mitre = soup.find('tr', {'id': f'cwe{mitre_id}'}).find('a', string='CSV.zip')
        feed_url = f"https://cwe.mitre.org/{mitre['href']}"

        with urlopen(feed_url) as response:
            with zipfile.ZipFile(BytesIO(response.read())) as uncompressed:
                with open(mitre_csv, 'wb') as f:
                    f.write(uncompressed.read(f'{mitre_id}.csv'))
    except Exception as e:
        print(f'Could not download Mitre file: {e}')

    print('Downloading OWASP top 10 file...')

    try:
        owasp = soup.find('tr', {'id': f'cwe{owasp_id}'}).find('a', string='CSV.zip')
        feed_url = f"https://cwe.mitre.org/{owasp['href']}"

        with urlopen(feed_url) as response:
            with zipfile.ZipFile(BytesIO(response.read())) as uncompressed:
                with open(owasp_csv, 'wb') as f:
                    f.write(uncompressed.read(f'{owasp_id}.csv'))
    except Exception as e:
        print(f'Could not download OWASP file: {e}')


if __name__ == '__main__':
    main(weakness_feed='https://cwe.mitre.org/data/downloads.html',
         mitre_csv='datasets/cwe_top_25.csv',
         mitre_id='1337',
         owasp_csv='datasets/owasp_top_10.csv',
         owasp_id='1344')