from urllib.parse import urlparse
from datetime import datetime, timezone
import requests
import whois
import dns.resolver
import ssl
import socket

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

def get_dns_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)

        cleaned = []

        for answer in answers:
            record = answer.to_text()
            record = record.replace('"', '')
            record = record.rstrip('.')

            if record_type == "MX":
                record = record.split(" ", 1)[1]

            cleaned.append(record)
        

        return cleaned

    except Exception:
        return []
    
def get_dns_info(domain):

    return {

        "A Records": get_dns_records(domain, "A"),

        "AAAA Records": get_dns_records(domain, "AAAA"),

        "MX Records": get_dns_records(domain, "MX"),

        "NS Records": get_dns_records(domain, "NS"),

        "TXT Records":  [record for record in get_dns_records(domain, "TXT") if record.startswith("v=spf1")] #need only spf txt record as it shows email authentication..
                                                                                                             #(if i added all txt records, it would be a mess)

    }


def get_ssl_info(domain):

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                certificate = secure_sock.getpeercert()

        issuer = dict(x[0] for x in certificate["issuer"])
        subject = dict(x[0] for x in certificate["subject"])
        issued = datetime.strptime(certificate["notBefore"], "%b %d %H:%M:%S %Y %Z")
        issued = issued.replace(tzinfo=timezone.utc)
        expires = datetime.strptime(certificate["notAfter"], "%b %d %H:%M:%S %Y %Z")
        expires = expires.replace(tzinfo=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days
        
        if (days_left < 0):
            status = "Expired"

        elif (days_left <= 30):
            status = "Expiring Soon"

        else:
            status = "Valid"

        return {

            "Issuer": issuer.get("organizationName", "Unknown"),

            "Common Name": subject.get("commonName", "Unknown"),

            "Issued On": issued.strftime("%d-%m-%Y"),

            "Expires On": expires.strftime("%d-%m-%Y"),

            "Days Left": f"{days_left} days",

            "Certificate Status": status
        }

    except Exception as e:
        return{"SSL Error": str(e)}

def get_security_headers(url):

    try:

        response = requests.get(
            url,
            timeout=5,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 "
                    "(Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 "
                    "(KHTML, like Gecko) "
                    "Chrome/137.0.0.0 Safari/537.36"
                )
            }
        )

        headers = response.headers
        csp = (headers.get("Content-Security-Policy") or headers.get("Content-Security-Policy-Report-Only"))

        if csp and len(csp) > 80:
            csp = csp[:80] + "..."

        security = {

            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),

            "Content-Security-Policy": csp,

            "X-Frame-Options": headers.get("X-Frame-Options"),

            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),

            "Referrer-Policy": headers.get("Referrer-Policy"),

            "Permissions-Policy": headers.get("Permissions-Policy"),

            "Cross-Origin-Opener-Policy": headers.get("Cross-Origin-Opener-Policy"),

            "Cross-Origin-Embedder-Policy": headers.get("Cross-Origin-Embedder-Policy"),

            "Cross-Origin-Resource-Policy": headers.get("Cross-Origin-Resource-Policy")

        }
        #print(response.headers)
        return security

    except Exception as e:

        return {
            "Error": str(e)
        }