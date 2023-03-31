import json
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.chrome.options import Options
import re


site = 'https://www.chron.com'


def process_browser_log_entry(entry):
    response = json.loads(entry['message'])['message']
    return response

def load_site(site):
    options = Options()
    options.add_argument('--headless')
    
    caps = DesiredCapabilities.CHROME
    caps['goog:loggingPrefs'] = {'performance': 'ALL'}
    driver = webdriver.Chrome(desired_capabilities=caps, options=options)
    driver.get(site)
    browser_log = driver.get_log('performance') 
    driver.close()
    return browser_log


def process_logs_to_domains(browser_log):
    urls = list()
    domains = set()
    events = [process_browser_log_entry(entry) for entry in browser_log]
    events = [event for event in events if 'Network.response' in event['method']]
    for event in events:
        try:
            if event['params']['response']['url']:
                urls.append(event['params']['response']['url'])
        except:
            pass
    
    for u in urls:
        if len(u) > 6:
            if 'xmlns' in u:
                regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
                url = re.search(regex, u)
                domains.add(u.split('/')[2])
            else:
                domains.add(u.split('/')[2])
    if '' in domains:
        domains.remove('')
    return domains




