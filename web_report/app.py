import os
import markdown
from flask import Flask, render_template

app = Flask(__name__)

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README_PATH = os.path.join(BASE_DIR, 'README.md')
LEARNING_PATH = os.path.join(BASE_DIR, 'LEARNING_GUIDE.md')

@app.route('/')
def index():
    content = ""
    # Merge README and Learning Guide for this one
    for path in [README_PATH, LEARNING_PATH]:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                content += markdown.markdown(f.read(), extensions=['fenced_code', 'tables']) + "<hr>"
    
    return render_template('index.html', content=content, title="Windows Monitoring Agent - Project Report")

if __name__ == '__main__':
    app.run(debug=True, port=5005)
