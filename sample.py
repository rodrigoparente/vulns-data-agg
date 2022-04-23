# python imports
import time
import random
from datetime import datetime
from dateutil.relativedelta import relativedelta

# third-party
import pandas as pd
import numpy as np

from pytrends.request import TrendReq

# hide warnings
import warnings
warnings.filterwarnings('ignore')


def load_data(published_after):
    vulns = pd.read_csv('output/vulns.csv', low_memory=False)

    # converting date columns to datetime object
    for name in ['cve', 'exploit']:
        vulns[f'{name}_published_date'] =\
            pd.to_datetime(vulns[f'{name}_published_date'], format='%Y-%m-%d')

    # filtering vulns based in published_date and cvss_type
    vulns = vulns.loc[
        (vulns['cve_published_date'].dt.year > published_after) &
        (vulns['cvss_type'] == 3.0)]

    # creating a column called base_severity
    conditions = [
        ((vulns['base_score'] <= 3.9)),
        ((vulns['base_score'] >= 4.0) & (vulns['base_score'] <= 6.9)),
        ((vulns['base_score'] >= 7.0) & (vulns['base_score'] <= 8.9)),
        ((vulns['base_score'] >= 9.0))
    ]

    choices = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

    vulns['base_severity'] = np.select(conditions, choices, default='OTHER')
    vulns['base_severity'] = pd.Categorical(vulns.base_severity, categories=choices, ordered=True)

    return vulns


def generate_sample(vulns, general_amount, exploit_amount, audience_amount):

    result_dfs = list()

    for severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
        exploits =\
            vulns.loc[
                (vulns['base_severity'] == severity) &
                (vulns['exploit_count'] > 0)
            ]

        audience =\
            vulns.loc[
                (vulns['base_severity'] == severity) &
                (~vulns['audience'].isnull()) &
                (~vulns['cve_id'].isin(exploits['cve_id']))
            ]

        df =\
            vulns.loc[
                (vulns['base_severity'] == severity) &
                (~vulns['cve_id'].isin(exploits['cve_id'])) &
                (~vulns['cve_id'].isin(audience['cve_id']))
            ]

        if exploits.shape[0] >= exploit_amount:
            exploits = exploits.sample(n=exploit_amount)

        if audience.shape[0] >= audience_amount:
            audience = audience.sample(n=audience_amount)

        # if the number of vulns with exploits and audience is not equals
        # to the value asked for, we add the difference to the general amount
        size = (general_amount + exploit_amount + audience_amount) -\
            (exploits.shape[0] + audience.shape[0])

        df = df.sample(n=size)

        concatenated = pd.concat([df, exploits, audience])

        result_dfs.append(concatenated)

    return pd.concat(result_dfs)


def generate_network(vulns):

    # asset context
    asset_ctx = [
        ['DMZ', 'SERVER', 'PRODUCTION', np.nan, 1, np.nan],
        ['DMZ', 'SERVER', 'PRODUCTION', np.nan, 0, np.nan],
        ['LOCAL', 'SERVER', 'PRODUCTION', 'CUSTOMERS', 1, np.nan],
        ['LOCAL', 'SERVER', 'PRODUCTION', 'CUSTOMERS', 0, np.nan],
        ['LOCAL', 'SERVER', 'PRODUCTION', 'EMPLOYEES', 1, 1],
        ['LOCAL', 'SERVER', 'PRODUCTION', 'EMPLOYEES', 1, 0],
        ['LOCAL', 'SERVER', 'PRODUCTION', 'EMPLOYEES', 0, 1],
        ['LOCAL', 'SERVER', 'PRODUCTION', 'EMPLOYEES', 0, 0],
        ['LOCAL', 'SERVER', 'DEVELOPMENT', np.nan, 1, np.nan],
        ['LOCAL', 'SERVER', 'DEVELOPMENT', np.nan, 0, np.nan],
        ['LOCAL', 'WORKSTATION', 'PRODUCTION', np.nan, 1, 1],
        ['LOCAL', 'WORKSTATION', 'PRODUCTION', np.nan, 1, 0],
        ['LOCAL', 'WORKSTATION', 'PRODUCTION', np.nan, 0, 1],
        ['LOCAL', 'WORKSTATION', 'PRODUCTION', np.nan, 0, 0],
        ['LOCAL', 'WORKSTATION', 'DEVELOPMENT', np.nan, 1, np.nan],
        ['LOCAL', 'WORKSTATION', 'DEVELOPMENT', np.nan, 0, np.nan],
    ]

    asset_ctx_cols = ['topology', 'type', 'environment', 'data', 'end_of_life', 'honeypot']

    # columns of the final dataset
    output_columns = vulns.columns.tolist() + asset_ctx_cols

    # list to hold output values (vulns + ctx info)
    values_list = [[] for _ in range(len(output_columns))]

    # randomly assigning a context to the selected vuln
    for row in zip(*vulns.to_dict("list").values()):
        row_list = list(row) + random.choice(asset_ctx)
        for index, value in enumerate(row_list):
            values_list[index].append(value)

    # formating output list
    results = dict()
    for column, values in zip(output_columns, values_list):
        results.setdefault(column, values)

    # generating pandas df
    return pd.DataFrame(results, columns=output_columns)


def get_interest(vulns):

    # instantiating pytrends object
    pytrends = TrendReq()

    # getting dates
    today = datetime.now().strftime('%Y-%m-%dT%H')
    a_week_days_ago = (datetime.now() - relativedelta(days=7, hours=1)).strftime('%Y-%m-%dT%H')

    interests, trends = list(), list()
    last_progress_value = -1

    # retrieving interest of all vulns
    for index, row in enumerate(zip(*vulns.to_dict("list").values())):
        cve = row[0]

        # building trend query
        pytrends.build_payload([cve], timeframe=f'{a_week_days_ago} {today}')
        df = pytrends.interest_over_time()

        trend, interest = np.nan, 0

        if not df.empty:
            df = df.drop(['isPartial'], axis=1)
            df.reset_index('date', inplace=True)

            series = dict()
            for row in zip(*df.to_dict("list").values()):
                date = row[0].strftime('%Y-%m-%d')
                interest = row[1]

                if date not in series.keys():
                    series.setdefault(date, interest)
                elif interest > series[date]:
                    series[date] = interest

            # calculating the direction of the interest
            trend = np.gradient(list(series.values()))[-1]

            # calculating the overrall interest
            interest = sum(series.values()) / (len(series) * 100)

            if trend > 0:
                trend, interest = 'increasing', interest
            elif trend < 0:
                trend, interest = 'decreasing', interest
            else:
                trend, interest = 'steady', interest

        trends.append(trend)
        interests.append(interest)

        progress = round(index / vulns.shape[0] * 100)
        if progress % 20 == 0 and\
                progress != last_progress_value:
            time.sleep(120)
            last_progress_value = progress

    vulns['google_trend'] = trends
    vulns['google_interest'] = interests

    return vulns


if __name__ == '__main__':

    try:
        vulns = load_data(published_after=2019)
    except FileNotFoundError:
        print('Input dataset not found.')
        exit(0)

    print('Generating random samples...')

    # generating a sample for labelled dataset
    labelled = generate_sample(
        vulns, general_amount=54, exploit_amount=7, audience_amount=4)

    # generating a sample for unlabelled dataset
    unlabelled = vulns.loc[~vulns['cve_id'].isin(labelled['cve_id'])]
    unlabelled = unlabelled.sample(n=1040)

    # generating random network values
    labelled = generate_network(labelled)
    unlabelled = generate_network(unlabelled)

    # getting googlge trends interest
    unlabelled = get_interest(unlabelled)
    labelled = get_interest(labelled)

    columns = [
        'cve_id', 'part', 'vendor', 'base_score', 'confidentiality_impact', 'integrity_impact',
        'availability_impact', 'cve_published_date', 'readable_cve_date', 'mitre_top_25',
        'owasp_top_10', 'exploit_count', 'epss', 'exploit_published_date',
        'readable_exploit_date', 'attack_type', 'reference', 'update_available', 'audience',
        'audience_percentile', 'google_trend', 'google_interest', 'topology', 'type',
        'environment', 'data', 'end_of_life', 'honeypot'
    ]

    # filtering columns
    labelled = labelled[columns]
    unlabelled = unlabelled[columns]

    # saving dataset to a csv file
    labelled.to_csv('output/vulns_labelled.csv', index=False)
    unlabelled.to_csv('output/vulns_unlabelled.csv', index=False)
