from urllib.parse import urlparse
import requests
import whois
from datetime import datetime, timezone

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
        content_type = response.headers.get("Content-Type", "Unknown")
        content_type = content_type.split(";")[0]   #got rid of the charset trailing after the content type

        return{
            "Status Code": response.status_code,
            "Server": response.headers.get("Server", "Unknown"),
            "Content Type": content_type,
        }
    
    except requests.exceptions.RequestException as e:
        return {"Error": str(e)}
    
def get_whois_info(domain):
    try:
        info = whois.whois(domain)

        creation = info.creation_date
        expiration = info.expiration_date

        if isinstance(creation, list):
            creation = creation[0]

        if isinstance(expiration, list): #for lists
            expiration = expiration[0]

        age = "Unknown"

        if creation:
            now = datetime.now(timezone.utc)

            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)

            age = (now - creation).days // 365 #calculate the age of the domain in years
        
        if creation:
            creation = creation.strftime("%d-%m-%Y")

        if expiration:
            expiration = expiration.strftime("%d-%m-%Y")

        return {
            "Registrar": info.registrar,
            "Creation Date": creation,
            "Expiration Date": expiration,
            "Domain Age": f"{age} years",
            "Name Servers": info.name_servers
        }
        
    except Exception as e:
        return {
        "WHOIS Error": str(e)
        }


        
