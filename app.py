from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    return 'API 6iphermail treatment mail'