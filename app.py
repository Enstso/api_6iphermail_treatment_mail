from flask import Flask, request, jsonify
from markupsafe import Markup

import base64
import json
import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from langdetect import detect
from spellchecker import SpellChecker


app = Flask(__name__)

@app.route('/treating_mail', methods=['POST'])
def treating_mail():
    data = request.json
    base64_text = data['base64_text']
    decoded_html = decode_base64(replace_characters(base64_text))
    text = extract_text_from_html(decoded_html)
    urls_in_text = find_urls(text)
    
    typo_errors = check_typography(text)
    num_spelling_errors = count_spelling_errors(text)
    redirect = check_url_redirect(urls_in_text)
    javascript = check_script_tags(decoded_html)
    https = check_https(urls_in_text)
    domains = is_domain_in_json(urls_in_text)
    
    score = 0
    
    if typo_errors:
        score += 1
    if num_spelling_errors > 0:
        score += 1
    if redirect:
        score += 2
    if not https:
        score += 5
    if domains:
        score += 10
    if check_suspect_text(text) > 0:
        score += 5
    if javascript:
        score += 10

    decoded_html = remove_html_tags(decoded_html)

    decoded_html+=str(score)

    if score >= 7:
        res['content'] = text

    return Markup(decoded_html)
    


def decode_base64(base64_text):
    base64_bytes = base64_text.encode('utf-8')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('utf-8')
    return message


def extract_text_from_html(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    return soup.get_text()


def remove_html_tags(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    # Remove <!DOCTYPE> and <html> tags
    for element in soup(['!doctype', 'html']):
        element.extract()
    return str(soup)

def check_typography(text):
    is_typo_present = False
    # Basic typography rules
    rules = {
        'double_space': r'  ',
        'space_before_punctuation': r' [,.!?;:](?=\w)',
        'no_space_after_punctuation': r'(?<=[,.!?;:])(?=\S)',
        'no_space_after_quote': r'(?<=["\'])\S'
    }

    # Checking for typographical errors
    for pattern in rules.values():
        matches = re.findall(pattern, text)
        if matches:
            is_typo_present = True
            break
    return is_typo_present


def check_https(urls):
    for url in urls:
        parsed_url = urlparse(url)
        if parsed_url.scheme != 'https':
            return False
    return True


def check_url_redirect(urls):
    try:
        for url in urls:
            response = requests.get(url, allow_redirects=False)
            if 'Location' in response.headers and response.headers['Location'] != url:
                return True
    except requests.RequestException as e:
        return False
    return False


def load_json_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
    return data


def is_domain_in_json(urls):
    hotlist_data = load_json_file('./hotlist.json')
    domains_data = load_json_file('./domains.json')
    
    for url in urls:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if domain in hotlist_data or domain in domains_data:
            return True
    return False


def check_suspect_text(text):
    suspect_count = 0
    suspect_phrases_data = load_json_file('./suspect_keywords.json')
    
    for phrase in suspect_phrases_data:
        if phrase in text:
            suspect_count += 1
    
    return suspect_count


def find_urls(text):
    pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    urls = re.findall(pattern, text)
    return urls


def check_script_tags(html):
    soup = BeautifulSoup(html, 'html.parser')
    scripts = soup.find_all('script')

    for script in scripts:
        if re.search(r'\b(?:alert|eval|prompt)\b', script.get_text(), re.IGNORECASE):
            return True
    return False


def count_spelling_errors(text):
    language = detect(text)

    spell = SpellChecker(language=language)

    words = text.split()
    misspelled = spell.unknown(words)
    num_errors = len(misspelled)
    return num_errors

def replace_characters(string):
    modified_string = string.replace('-', '+').replace('_', '/')
    return modified_string

if __name__ == '__main__':
    app.run(debug=True)