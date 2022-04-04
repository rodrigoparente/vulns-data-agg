# third-party imports
import pandas as pd

# local imports
from commons.file import save_list_to_csv


def process_tweets(input_path, output_path):
    tweets_csv = pd.read_csv(input_path)

    tweets_dict = dict()

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

    header = ['cve_id', 'tweet_published_date', 'lang',
              'impact', 'tweets', 'retweets', 'audience']
    save_list_to_csv(output_path, header, results)
