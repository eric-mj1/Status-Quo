from flask import Flask, request, render_template
from investigator import check_url, check_website

app = Flask(__name__)
@app.route('/', methods=['GET', 'POST'])
def home():
    
    result = None
    if request.method == 'POST':
        url = request.form.get('url')
        valid_url = check_url(url)
        if valid_url:
            result = check_website(valid_url)
        else:
            result = {"Error": "Invalid URL"}

    return render_template('index.html', result=result)

if __name__ == '__main__':

    app.run(debug=True)