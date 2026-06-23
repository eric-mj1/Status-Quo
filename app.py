from flask import Flask, request, render_template
from investigator import check_url, check_website, get_whois_info

app = Flask(__name__)
@app.route('/', methods=['GET', 'POST'])
def home():
    
    result = None
    if request.method == 'POST':
        url = request.form.get('url')
        valid_url = check_url(url)
        if valid_url:
            website = check_website(valid_url)
            domain = (
                valid_url
                .replace("https://", "")
                .replace("http://", "")
                .split("/")[0]
            )
            whois_data = get_whois_info(domain)
            result = {"Website": website,"WHOIS": whois_data}
            
        else:
            result = {"Error": "Invalid URL"}

    return render_template('index.html', result=result)

if __name__ == '__main__':

    app.run(debug=True)