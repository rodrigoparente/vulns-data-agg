# python imports
from datetime import datetime

# third-party imports
import pandas as pd
import numpy as np


def process_security_feeds():
    cves = pd.read_csv('output/cves.csv')
    cves = cves.drop_duplicates(subset=['cve_id'])

    cves['cwe'] = cves['cwe'].apply(eval)
    cves['part'] = cves['part'].apply(eval)
    cves['vendor'] = cves['vendor'].apply(eval)

    cves['cve_published_date'] =\
        pd.to_datetime(cves['cve_published_date'], format='%m/%d/%Y')

    # merging weakness lists

    mitre_top_25 = pd.read_csv('output/cwe_top_25.csv')
    mitre_top_25 = mitre_top_25.drop_duplicates(subset=['CWE-ID'])

    owasp_top_10 = pd.read_csv('output/owasp_top_10.csv')
    owasp_top_10 = owasp_top_10.drop_duplicates(subset=['CWE-ID'])

    mitre_ids = mitre_top_25['CWE-ID'].index.tolist()
    mitre_cwes = [f'CWE-{id}' for id in mitre_ids]

    owasp_ids = owasp_top_10['CWE-ID'].index.tolist()
    owasp_cwes = [f'CWE-{id}' for id in owasp_ids]

    cve_in_mitre = list()
    cve_in_owasp = list()

    for row in zip(*cves.to_dict("list").values()):
        mitre = False
        owasp = False

        for cwe in row[1]:
            if cwe in mitre_cwes:
                mitre = True

            if cwe in owasp_cwes:
                owasp = True

        cve_in_mitre.append(1 if mitre else 0)
        cve_in_owasp.append(1 if owasp else 0)

    cves['mitre_top_25'] = cve_in_mitre
    cves['owasp_top_10'] = cve_in_owasp

    # merging exploits

    exploits = pd.read_csv('output/exploits.csv')
    exploits = exploits.drop_duplicates(subset=['cve_id'])

    cves = cves.merge(exploits, how='left', on='cve_id')

    cves['exploit_published_date'] =\
        pd.to_datetime(cves['exploit_published_date'], format='%Y-%m-%d', errors='coerce')

    # merging epss

    epss = pd.read_csv('output/epss.csv', comment='#')
    epss.rename(columns={'cve': 'cve_id'}, inplace=True)
    epss = epss.drop_duplicates(subset=['cve_id'])

    columns = ['cve_id', 'epss']
    cves = cves.merge(epss[columns], how='left', on='cve_id')

    # merging advisories

    microsoft_advisory = pd.read_csv('output/microsoft_advisory.csv')
    microsoft_advisory = microsoft_advisory.drop_duplicates(subset=['cve_id'])

    intel_advisory = pd.read_csv('output/intel_advisory.csv')
    intel_advisory = intel_advisory.drop_duplicates(subset=['cve_id'])

    adobe_advisory = pd.read_csv('output/adobe_advisory.csv')
    adobe_advisory = adobe_advisory.drop_duplicates(subset=['cve_id'])

    advisories = pd.concat([microsoft_advisory, intel_advisory, adobe_advisory])
    advisories = advisories.drop_duplicates(subset=['cve_id'])

    columns = ['cve_id', 'advisory_published_date', 'attack_type', 'reference']
    cves = cves.merge(advisories[columns], how='left', on='cve_id')

    cves['updatable'] = cves['reference'].apply(lambda value: 1 if value else 0)

    # merging tweets

    tweets = pd.read_csv('output/tweets.csv')

    cve_ids = cves['cve_id'].tolist()
    tweets_cve_ids = tweets['cve_id'].tolist()

    intersection = set(cve_ids).intersection(tweets_cve_ids)
    tweets = tweets.loc[tweets['cve_id'].isin(intersection)]

    max_audience = tweets['audience'].max()
    tweets['audience_percentile'] =\
        tweets['audience'].apply(lambda value: f'{value / max_audience:.5f}')

    columns = ['cve_id', 'audience', 'audience_percentile']
    cves = cves.merge(tweets[columns], how='left', on='cve_id')

    for row in tweets.itertuples():
        cve_index = cves.loc[cves['cve_id'] == row.cve_id].index
        cves.loc[cve_index, 'attack_type'] = row.attack_type

    # formating output

    vendors = pd.Series([x for _list in cves['vendor'] for x in _list])
    top_ten_vendors = vendors.value_counts()[0:10].index

    parts = list()
    vendors = list()
    cves_days = list()
    exploits_days = list()

    for row in zip(*cves.to_dict("list").values()):
        curr_part = ''
        for part in row[2]:
            if part == 'h':
                curr_part = 'hardware'
            elif part == 'o':
                curr_part = 'operating system'
            elif part == 'a':
                curr_part = 'application'
        parts.append(curr_part)

        curr_vendor = 'other'
        for vendor in row[3]:
            if vendor in top_ten_vendors:
                curr_vendor = vendor
        vendors.append(curr_vendor)

        cve_date = (datetime.now() - row[18]).days
        exploit_date = (datetime.now() - row[23]).days

        raw_days = [cve_date, exploit_date]
        human_readable_days = [cves_days, exploits_days]

        for date, result in zip(raw_days, human_readable_days):
            if date <= 60:
                result.append('menos de 3 meses')
            elif 60 < date <= 180:
                result.append('entre 3 e 6 meses')
            elif 180 < date <= 270:
                result.append('entre 6 e 9 meses')
            elif 270 < date <= 365:
                result.append('entre 9 e 12 meses')
            elif date > 365:
                result.append('mais de 12 meses')
            else:
                result.append(np.nan)

    cves['part'] = parts
    cves['vendor'] = vendors
    cves['cve_published_days'] = cves_days
    cves['exploit_published_days'] = exploits_days

    cves = cves[[
        'cve_id', 'part', 'vendor', 'base_score', 'confidentiality_impact', 'integrity_impact',
        'availability_impact', 'cve_published_date', 'cve_published_days', 'mitre_top_25',
        'owasp_top_10', 'exploit_count', 'epss', 'exploit_published_date', 'exploit_published_days',
        'attack_type', 'updatable', 'audience', 'audience_percentile'
    ]]

    return cves