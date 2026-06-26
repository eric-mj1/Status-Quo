from flask import Flask, request, render_template
from investigator import check_url, check_website, get_whois_info, get_dns_records, get_dns_info, get_ssl_info, get_security_headers

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
            dns_data = get_dns_info(domain)
            ssl_data = get_ssl_info(domain)
            security_headers = get_security_headers(valid_url)
            #print(ssl_data) 
            #print(dns_data) - used to verify if the DNS data is being retrieved correctly cause im a dumb aahhh
            #print(security_headers)
            result = {"Website": website,"WHOIS": whois_data, "DNS": dns_data, "SSL": ssl_data, "Security" : security_headers}

        else:
            result = {"Error": "Invalid URL"}

    return render_template('index.html', result=result)

if __name__ == '__main__':

    app.run(debug=True)