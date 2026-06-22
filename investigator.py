from urllib.parse import urlparse
import requests

def check_url(url):
    if not url.startswith(("http://", "https://")): # for people who are lazy (like me) to add the https
        url = "https://" + url
    parsed_url = urlparse(url)
    if not parsed_url.netloc:   # to check if the URL has a valid domain
        return None
    return url

def check_website(url):
    try:
        response = requests.get(url, timeout=5) 
        return{
            "Status Code": response.status_code,
            "Server": response.headers.get("Server", "Unknown"),
            "Content Type": response.headers.get("Content-Type", "Unknown"),
        }
    
    except requests.exceptions.RequestException as e:
        return {"Error": str(e)}