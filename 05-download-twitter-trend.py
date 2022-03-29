# python imports
import os
import csv
import json
import re
import logging
from time import sleep
from collections import namedtuple
from urllib.parse import urlencode
from datetime import datetime
from datetime import timedelta

# third-party imports
import requests
from dotenv import load_dotenv
import pandas as pd

# local imports
from utils.file import make_dir, remove_file, save_to_csv


log = logging.getLogger(__name__)


class TwitterStream():
    def __init__(self, token):
        self.bearer_token = token

        self.running = False
        self.session = requests.Session()

        self.base_url = 'https://api.twitter.com/2/tweets/search/stream'

        # remove old rules that are active
        self.delete_rules(self.get_rules())

    def _bearer_oauth(self, r):
        r.headers['Authorization'] = f'Bearer {self.bearer_token}'
        r.headers['User-Agent'] = 'v2FilteredStreamPython'

        return r

    def _connect(self, method, url):
        self.running = True
        http_error_wait = 5

        try:
            while self.running:
                with self.session.request(
                    method, url, auth=self._bearer_oauth, stream=True
                ) as resp:

                    if resp.status_code == 200:

                        self.on_connect()
                        if not self.running:
                            break

                        for raw_data in resp.iter_lines():

                            if not self.running:
                                break

                            if raw_data:
                                data = json.loads(raw_data)

                                if "data" in data:
                                    tweet = namedtuple('tweet', data.keys())(*data.values())
                                    self.on_tweet(tweet)
                    else:
                        self.on_error(
                            f'An error occurred with the stream (HTTP {resp.status_code})')

                        if not self.running:
                            break

                        sleep(http_error_wait)
                        http_error_wait *= 2

        except Exception as exc:
            print(f'Stream encountered an exception: {exc}')
        finally:
            self.session.close()
            self.running = False
            self.on_disconnect()

    def disconnect(self):
        self.running = False

    def get_rules(self):
        resp = requests.get(
            f'{self.base_url}/rules',
            auth=self._bearer_oauth
        )

        if resp.status_code != 200:
            self.on_error(f'Cannot get rules (HTTP {resp.status_code}): {resp.text}')

        return resp.json()

    def delete_rules(self, rules):
        if rules is None or 'data' not in rules:
            return None

        ids = list(map(lambda rule: rule['id'], rules['data']))
        payload = {'delete': {'ids': ids}}

        resp = requests.post(
            f'{self.base_url}/rules',
            auth=self._bearer_oauth,
            json=payload
        )

        if resp.status_code != 200:
            self.on_error(f'Cannot delete rules (HTTP {resp.status_code}): {resp.text}')

    def add_rules(self, rules):
        """
        References
        ----------
        https://developer.twitter.com/en/docs/twitter-api/tweets/filtered-stream/integrate/build-a-rule
        """

        resp = requests.post(
            f'{self.base_url}/rules',
            auth=self._bearer_oauth,
            json={'add': rules}
        )

        if resp.status_code != 201:
            self.on_error(f'Cannot add rules (HTTP {resp.status_code}): {resp.text}')

    def filter(self, expansions=None, tweet_fields=None, user_fields=None):
        """
        References
        ----------
        https://developer.twitter.com/en/docs/twitter-api/tweets/filtered-stream/api-reference/get-tweets-search-stream
        """

        query_dict = dict()

        if expansions:
            query_dict.update({'expansions': ','.join(expansions)})
        if tweet_fields:
            query_dict.update({'tweet.fields': ','.join(tweet_fields)})
        if user_fields:
            query_dict.update({'user.fields': ','.join(user_fields)})

        url = f'{self.base_url}?{urlencode(query_dict)}'

        self._connect('GET', url)

    def on_connect(self):
        log.info('Successfull connected to Twitter API.')

    def on_disconnect(self):
        log.info('Successfull disconnected from Twitter API.')

    def on_tweet(self, tweet):
        log.info('Tweet received.')

    def on_error(self, error_msg):
        log.info('An error occurred.')


class Listener(TwitterStream):
    def __init__(self, token, file_path, duration):
        super().__init__(token)

        self.tmp_file = file_path
        self.tweets = list()

        self.start_time = datetime.now()
        self.end_time = self.start_time + timedelta(**duration)

        self.prep_tmp_file()

    def prep_tmp_file(self):
        # create output folder if it doesnt exists
        dirs = os.path.split(self.tmp_file)[0]
        if not os.path.exists(dirs):
            os.makedirs(dirs)

        # remove tmp file if exists
        if os.path.exists(self.tmp_file):
            os.remove(self.tmp_file)

        self.write_to_file([
            'cve_id', 'published_date', 'text', 'lang',
            'tweet_id', 'tweet_retweet_count',
            'tweet_author_id', 'tweet_author_followers',
            'original_tweet_id', 'original_retweet_count',
            'original_author_id', 'original_author_followers'])

    def write_to_file(self, entries):
        with open(self.tmp_file, 'a') as f:
            writer = csv.writer(f)
            writer.writerow(entries)

    def on_connect(self):
        start = self.start_time.strftime('%H:%M %d/%m/%Y')
        end = self.end_time.strftime('%H:%M %d/%m/%Y')

        print(f'Program start running at {start} and will finish at {end}')

    def on_tweet(self, tweet):

        # tweet info

        tweet_author_id = tweet.data.get('author_id')
        tweet_id = tweet.data.get('id')

        published_date = tweet.data.get('created_at')
        text = tweet.data.get('text')
        lang = tweet.data.get('lang')

        tweet_metrics = tweet.data.get('public_metrics')
        tweet_retweet_count = tweet_metrics.get('retweet_count')

        tweet_author = list(filter(
            lambda user: (user['id'] == tweet_author_id), tweet.includes.get('users')))[0]

        tweet_author_metrics = tweet_author.get('public_metrics')
        tweet_author_followers = tweet_author_metrics.get('followers_count')

        # reference tweet info

        original_author_id = 0
        original_tweet_id = 0
        original_retweet_count = 0
        original_author_followers = 0

        if tweet.data.get('referenced_tweets') is not None:
            for reference in tweet.data.get('referenced_tweets'):
                if reference.get('type') == 'retweeted':
                    original_tweet_id = reference.get('id')
                    break

            if original_tweet_id:
                referenced_tweets = tweet.includes.get('tweets')

                original_tweet =\
                    list(filter(lambda tweet: (tweet['id'] == original_tweet_id),
                                referenced_tweets))[0]

                original_author_id = original_tweet.get('author_id')
                original_tweet_id = original_tweet_id

                original_twitter_metrics = original_tweet.get('public_metrics')
                original_retweet_count = original_twitter_metrics.get('retweet_count')

                original_tweet_author =\
                    list(filter(lambda user: (user['id'] == original_author_id),
                                tweet.includes.get('users')))[0]

                original_tweet_author_metrics = original_tweet_author.get('public_metrics')
                original_author_followers = original_tweet_author_metrics.get('followers_count')

        # vulnerability identifier

        cve_id = re.search('CVE-[0-9]{4}-[0-9]+', text)

        if datetime.now() < self.end_time:
            if cve_id:
                self.write_to_file([
                    cve_id.group(0), published_date, text, lang,
                    tweet_id, tweet_retweet_count,
                    tweet_author_id, tweet_author_followers,
                    original_tweet_id, original_retweet_count,
                    original_author_id, original_author_followers])
        else:
            self.disconnect()

    def on_error(self, error_msg):
        print(error_msg)


def process_tweets(input_path, output_path):
    tweets_csv = pd.read_csv(input_path)

    tweets_dict = dict()

    print('Processing tweets...')

    for row in tweets_csv.itertuples():
        if row.cve_id in tweets_dict.keys():
            tweet = tweets_dict[row.cve_id]

            if row.published_date > tweet['published_date']:
                tweet['published_date'] = row.published_date

            if row.lang not in tweet['lang']:
                tweet['lang'].append(row.lang)

            if row.tweet_author_id not in tweet['authors'].keys():
                tweet['authors'].update({
                    row.tweet_author_id: row.tweet_author_followers})

            if row.original_tweet_id:
                if row.original_author_id not in tweet['authors'].keys():
                    tweet['authors'].update({
                        row.original_author_id: row.original_author_followers})

                if row.original_tweet_id not in tweet['retweets'].keys():
                    tweet['retweets'].update({
                        row.original_tweet_id: row.original_retweet_count})
                elif row.original_retweet_count > tweet['retweets'][row.original_tweet_id]:
                    tweet['retweets'][row.original_tweet_id] = row.original_retweet_count

                if row.original_tweet_id not in tweet['tweets']:
                    tweet['tweets'].append(row.original_tweet_id)
            else:
                tweet['tweets'].append(row.tweet_id)
        else:
            tweets_dict.setdefault(row.cve_id, {
                'cve_id': row.cve_id,
                'published_date': row.published_date,
                'lang': [row.lang],
                'impact': [],
                'authors': {row.tweet_author_id: row.tweet_author_followers},
                'tweets': [],
                'retweets': {}
            })

            tweet = tweets_dict[row.cve_id]

            if row.original_tweet_id:
                tweet.update({
                    'authors': {row.original_author_id: row.original_author_followers},
                    'retweets': {row.original_tweet_id: row.original_retweet_count}
                })

                tweet['tweets'].append(row.original_tweet_id)
            else:
                tweet['tweets'].append(row.tweet_id)

    results = list()
    for key, value in tweets_dict.items():
        results.append([
            value.get('cve_id'), value.get('published_date'), value.get('lang'),
            value.get('impact'), len(value.get('tweets')),
            sum(value.get('retweets').values()), sum(value.get('authors').values())
        ])

    print('Preparing output folder...')

    make_dir(output_path)
    remove_file(output_path)

    print('Saving to file...')

    header = ['cveID', 'publishedDate', 'impact', 'tweets', 'retweets', 'audience']
    save_to_csv(output_path, header, results)


def main(raw_tweets_path, processed_tweets_path, rules, duration):
    # take environment
    # variables from .env
    load_dotenv()

    bearer_token = os.environ.get('BEARER_TOKEN', None)

    stream = Listener(
        bearer_token,
        file_path=raw_tweets_path,
        duration=duration)

    stream.add_rules(rules)

    stream.filter(
        expansions=['author_id', 'referenced_tweets.id'],
        user_fields=['verified', 'public_metrics'],
        tweet_fields=['created_at', 'lang', 'public_metrics', 'text'])

    process_tweets(
        input_path=raw_tweets_path,
        output_path=processed_tweets_path)


if __name__ == '__main__':
    main(raw_tweets_path='datasets/raw_tweets.csv',
         processed_tweets_path='datasets/tweets.csv',
         rules=[{'value': 'CVE -"$CVE"', 'tag': 'vulnerability identifier'}],
         duration={'hours': 24})
