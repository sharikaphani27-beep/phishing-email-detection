import os
import re
import string
import pickle
import nltk
import pandas as pd
import numpy as np

from flask import Flask, render_template, request, jsonify
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer

app = Flask(__name__)

nltk.download('stopwords', quiet=True)
from nltk.corpus import stopwords

MODEL_PATH = 'model.pkl'
VECTORIZER_PATH = 'vectorizer.pkl'

stop_words = set(stopwords.words('english'))

model = None
vectorizer = None

def preprocess_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+", " URL ", text)
    text = re.sub(r"\d+", "", text)
    text = text.translate(str.maketrans('', '', string.punctuation))
    words = text.split()
    words = [w for w in words if w not in stop_words]
    return " ".join(words)

def load_model():
    global model, vectorizer
    try:
        model = pickle.load(open(MODEL_PATH, 'rb'))
        vectorizer = pickle.load(open(VECTORIZER_PATH, 'rb'))
    except:
        model = None
        vectorizer = None

def analyze_email_client(text, url, has_suspicious_keywords, has_ip_in_url, has_attachment, num_links):
    score = 0
    factors = []
    
    text = (text or '').lower()
    url = (url or '').lower()
    
    if has_suspicious_keywords:
        score += 25
        factors.append('Contains suspicious keywords')
    
    if has_ip_in_url:
        score += 30
        factors.append('URL contains IP address')
    
    if has_attachment:
        score += 15
        factors.append('Email has attachment')
    
    if re.search(r'click here|verify|urgent|account.*suspended|password|bank.*update|confirm.*identity', text):
        score += 20
        factors.append('Urgent/pressuring language detected')
    
    if re.search(r'http://\d+\.\d+.\d+.\d+', url):
        score += 25
        factors.append('HTTP with numeric IP')
    
    if url and len(url) > 50:
        score += 15
        factors.append('Unusually long URL')
    
    if num_links and num_links > 3:
        score += 10
        factors.append('Multiple links in email')
    
    suspicious_domains = ['.xyz', '.top', '.club', '.win', '.info', 'secure-', 'login-', 'verify-', 'update-']
    for domain in suspicious_domains:
        if domain in url:
            score += 15
            factors.append('Suspicious URL pattern')
            break
    
    confidence = min(max(score, 10), 100)
    
    return {
        'isPhishing': score >= 50,
        'confidence': confidence,
        'factors': factors
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    
    result = analyze_email_client(
        data.get('subject', '') + ' ' + data.get('body', ''),
        data.get('url', ''),
        data.get('hasSuspiciousKeywords', False),
        data.get('hasIPInURL', False),
        data.get('hasAttachment', False),
        data.get('numLinks', 0)
    )
    
    return jsonify(result)

@app.route('/health')
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    load_model()
    app.run(debug=True, port=5000)