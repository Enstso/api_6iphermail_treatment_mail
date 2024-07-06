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
    if decoded_html == 'An error occurred. Please contact your mail provider.':
        return jsonify({'content': 'An error occurred. Please contact your mail provider.','score':-1}), 200
    
    text = extract_text_from_html(decoded_html)
    
    if text == 'An error occurred. Please contact your mail provider.':
        return jsonify({'content': 'An error occurred. Please contact your mail provider.','score':-1}), 200
    
    urls_in_text = find_urls(text)
    
    if urls_in_text == 'An error occurred. Please contact your mail provider.':
        return jsonify({'content': 'An error occurred. Please contact your mail provider.','score':-1}), 200
    
    print(f"URLs in text: {urls_in_text}")
    res = {}
    typo_errors = check_typography(text)
    
    if typo_errors == 'An error occurred. Please contact your mail provider.':
        return jsonify({'content': 'An error occurred. Please contact your mail provider.','score':-1}), 200
    
    num_spelling_errors = count_spelling_errors(text)
    
    if num_spelling_errors == 'An error occurred. Please contact your mail provider.':
        return jsonify({'content': 'An error occurred. Please contact your mail provider.','score':-1}), 200
    
    redirect = check_url_redirect(urls_in_text)
    
    if redirect == 'An error occurred. Please contact your mail provider.': 
        return jsonify({'content': 'An error occurred. Please contact your mail provider.','score':-1}), 200    
    javascript = check_script_tags(decoded_html)
    
    if javascript == 'An error occurred. Please contact your mail provider.':
        return jsonify({'content': 'An error occurred. Please contact your mail provider.','score':-1}), 200    
    https = check_https(urls_in_text)
    
    if https == 'An error occurred. Please contact your mail provider.':
        return jsonify({'content': 'An error occurred. Please contact your mail provider.','score':-1}), 200    
    domains_url = is_domain_in_json(urls_in_text)
    if domains_url == 'An error occurred. Please contact your mail provider.':
        return jsonify({'content': 'An error occurred. Please contact your mail provider.','score':-1}), 200    
    domain_text = text_is_domain_in_json(text)
    if domain_text == 'An error occurred. Please contact your mail provider.':
        return jsonify({'content': 'An error occurred. Please contact your mail provider.','score':-1}), 200
    score = 0
    
    if typo_errors:
        score += 1
    if num_spelling_errors > 0:
        score += 1
    if redirect:
        score += 2
    if not https:
        score += 5
    if domains_url:
        score += 10
    if domain_text:
        score += 10
    if check_suspect_text(text) > 0:
        score += 5
    if javascript:
        score += 10

    print(f"Final score: {score}")
    res['score'] = score
    res['content'] = decoded_html
    if score >= 8:
        res['content'] = text
        res['score'] = score
        return jsonify(res), 200

    return jsonify(res), 200

   

def retirer_balises_a(html):
    try:
        soup = BeautifulSoup(html, 'html.parser')
        for a_tag in soup.find_all('a'):
            a_tag.extract()
        cleaned_html = str(soup)
        return cleaned_html
    
    except FeatureNotFound as e:
        return f"Erreur de parsing HTML: {str(e)}"
    
    except Exception as e:
        return f"Une erreur est survenue: {str(e)}"

def decode_base64(base64_text):
    try:
        base64_bytes = base64_text.encode('utf-8')
        message_bytes = base64.b64decode(base64_bytes)
        message = message_bytes.decode('utf-8')
        return message
    except (Exception) as e:
        return 'An error occurred. Please contact your mail provider.'

def extract_text_from_html(html_content):
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        return soup.get_text()
    except Exception as e:
        return 'An error occurred. Please contact your mail provider.'
    

def check_typography(text):
    try:
        is_typo_present = False
        # Règles de typographie de base
        rules = {
            'double_space': r'  ',
            'space_before_punctuation': r' [,.!?;:](?=\w)',
            'no_space_after_punctuation': r'(?<=[,.!?;:])(?=\S)',
            'no_space_after_quote': r'(?<=["\'])\S'
        }

        # Vérification des erreurs typographiques
        for pattern in rules.values():
            matches = re.findall(pattern, text)
            if matches:
                is_typo_present = True
                break
        return is_typo_present
    except Exception as e:
        return 'An error occurred. Please contact your mail provider.'

def check_https(urls):
    try:
        for url in urls:
            parsed_url = urlparse(url)
            if parsed_url.scheme != 'https':
                return False
        return True
    except Exception as e:
        return 'An error occurred. Please contact your mail provider.'

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
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        return data
    except Exception as e:
        return 'An error occurred. Please contact your mail provider.'

def is_domain_in_json(urls):
    try:
        hotlist_data = load_json_file('./hotlist.json')
        domains_data = load_json_file('./domains.json')

        for url in urls:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            if domain in hotlist_data or domain in domains_data:
                return True
        return False
    except Exception as e:
        return 'An error occurred. Please contact your mail provider.'

def text_is_domain_in_json(mail):
    try:
        mail = mail.split()
        print(f"mail: {mail}")
        hotlist_data = load_json_file('./hotlist.json')
        domains_data = load_json_file('./domains.json')

        for elmt in mail:
            if elmt in hotlist_data or elmt in domains_data:
                print(f"elmt: {elmt}")
                return True
        return False
    except Exception as e:
        return 'An error occurred. Please contact your mail provider.'

def check_suspect_text(text):
    try:
        suspect_count = 0
        suspect_phrases_data = load_json_file('./suspect_keywords.json')

        for phrase in suspect_phrases_data:
            if phrase in text:
                suspect_count += 1
        return suspect_count
    except Exception as e:
        return 'An error occurred. Please contact your mail provider.'

def find_urls(text):
    try:
        pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        urls = re.findall(pattern, text)
        return urls
    except Exception as e:
        return 'An error occurred. Please contact your mail provider.'
    
def check_script_tags(html):
    try:
        soup = BeautifulSoup(html, 'html.parser')
        scripts = soup.find_all('script')

        for script in scripts:
            if re.search(r'\b(?:alert|eval|prompt)\b', script.get_text(), re.IGNORECASE):
                return True
        return False
    except Exception as e:
        return 'An error occurred. Please contact your mail provider.'

def count_spelling_errors(text):
    try:
        language = detect(text)
        spell = SpellChecker(language=language)
        words = text.split()
        misspelled = spell.unknown(words)
        num_errors = len(misspelled)
        return num_errors
    except Exception as e:
        return 'An error occurred. Please contact your mail provider.'

def replace_characters(string):
    try:
        modified_string = string.replace('-', '+').replace('_', '/')
        return modified_string
    except Exception as e:
        return 'An error occurred. Please contact your mail provider.'

if __name__ == '__main__':
    app.run(debug=True)