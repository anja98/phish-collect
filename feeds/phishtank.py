''' Provides programmatic access to the data provided by Phishtank '''
import sys
import csv
import requests
import logging
import urllib
import chardet

from feeds.feed import Feed, FetchException
from models import Phish
from config import config


class PhishtankFeed(Feed):
    '''Implements the Phishtank phishing feed provider.'''

    def __init__(self):
        ''' Instantiates a new PhishtankFeed client'''
        self.feed = 'phishtank'
        self.url = config['phishtank']['url']
        self.last_seen = config['phishtank']['last_seen']
        self.username = config['phishtank']['username']
        self.password = config['phishtank']['password']

    def _process_rows(self, rows):
        '''
        Processes new phishing entries from the Phishtank API.

        Args:
            rows {list[str]} - The rows to process

        Row format:
        Index	Name	Description
        0	phish_id	The ID number by which Phishtank references this phishing submission.
        1	url	The phish URL as submitted to us. Because URLs can contain special characters, they are urlencoded on output.
        '''
        reader = csv.reader(rows, delimiter=',')
        entries = []
        urls_seen = []
        for record in reader:
            logging.debug('csv record: {}'.format(record))
            pid = record[0]
            try:
                url = urllib.unquote(record[1]).decode('utf-8')
                submission_time = record[3]
                verify_time = record[5]
            except:
                logging.error('cannot extract csv record: {}\nerror: {}'.format(', '.join(record), sys.exc_info()))
                continue
            # For now, we won't re-process already seen URLs
            if Phish.exists(url) or Phish.clean_url(url) in urls_seen:
                continue
            urls_seen.append(Phish.clean_url(url))
            entries.append(Phish(pid=pid, url=url, feed=self.feed, submission_time=submission_time, verify_time=verify_time))
        logging.info('processed {} CSV entries'.format(len(entries)))
        return entries

    def get(self, offset=0):
        '''
        Gets the latest phishing URLs from the Phishtank feed.

        We send the last seen phishtank ID as an offset.

        Args:
            offset {str} - The offset phish ID to send to Phishtank
        '''
        if not offset:
            most_recent_phish = Phish.get_most_recent(feed='phishtank')
            if most_recent_phish:
                offset = most_recent_phish.pid
            else:
                # If there is no offset in the db and we weren't given one
                # as a kwarg, we'll use the one we have listed in the config
                # (chances are, this means that it's a first-run)
                offset = self.last_seen
        logging.info(
            'Fetching {} feed with last offset: {}'.format(self.feed, offset))
        results = []
        params = {'last': offset}
        response = requests.get(
            self.url,
            timeout=5,
            params=params,
            auth=(self.username, self.password))
        logging.debug('Status: {}\nResponse Headers: {}'.format(response.status_code, response.headers))
        if not response.ok:
            if response.status_code == 404:
                response_txt = ''
            else:
                response_txt = response.text.encode("utf-8")
            raise FetchException (
                logging.error(
                    'Error fetching response:\nStatus: {}\nResponse:{}\nResponse Headers:{}'.format(
                        response.status_code, response_txt, response.headers)))

        # The first row is the csv header 
        entries = response.text.encode("utf-8").splitlines()
        if not entries or len(entries) < 1:
            raise FetchException(
                'Error fetching response: Invalid response received: {}'.
                format(entries))
        # If there are no new entries, just return an empty list
        if len(entries) == 1:
            return results
        max_id = entries[1].split(',')[0]
        results = self._process_rows(entries[1:])
        return results
