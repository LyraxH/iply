import os
import requests
import subprocess
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv('VT_API_KEY')

RED = "\033[38;2;255;0;0m"
GREEN = "\033[38;2;0;255;0m"
YELLOW = "\033[38;2;255;255;0m"
RESET = "\033[0m"

def get_ip() -> str:
    """
    Returns the public IP address of the user
    """
    try:
        return requests.get("https://api.ipify.org").text.strip()
    except requests.exceptions.RequestException as e:
        raise RuntimeError("Request failed") from e

def analyze_ip_security(target_ip: str) -> dict | None:
    """
    Retrieves JSON data from VirusTotal API and analyzes the security of an IP address
    Returns a dictionary of stats and an overall risk verdict
    """
    if not VT_API_KEY:
        raise RuntimeError("No API key found")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{target_ip}"
    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json"
    }
    try:
        r = requests.get(url, headers = headers, timeout = 10)
    
        if r.status_code == 200:
            data = r.json()
            info = data.get('data', {}).get('attributes', {})
            stats = info.get('last_analysis_stats', {})
            tags = info.get('tags', [])
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            harmless_count = stats.get('harmless', 0)
            owner = info.get('as_owner', 'Unknown Owner')
            country = info.get('country', 'Unknown Country')
            continent = info.get('continent', 'Unknown Continent')
            reputation = info.get('reputation', 0)
            return {
                'owner': owner,
                'country': country,
                'continent': continent,
                'reputation': reputation,
                'malicious_count': malicious_count,
                'suspicious_count': suspicious_count,
                'harmless_count': harmless_count,
                'tags': tags
            }
        elif r.status_code == 401:
            raise RuntimeError("Invalid API Key")
        elif r.status_code == 404:
            raise RuntimeError("IP not found")
        elif r.status_code == 429:
            raise RuntimeError("Rate limit exceeded")
        else:
            raise RuntimeError(f"Error: {r.status_code}")
    except requests.exceptions.RequestException:
        raise RuntimeError("Error: Request failed")

def main():
    """
    Main CLI function for iply
    """
    while True:
        user_input = input("(g)et, (f)ind, (s)ecurity, (v)erbose (q)uit \n what do: ").lower()
        subprocess.run(["clear"])
        match (user_input):
            case 'g':
                print("your ip: ", get_ip())
            case 'f':
                target_ip = input("(m)ine\ninput target ip: ")
                if target_ip == 'm':
                    target_ip = get_ip()
                r = requests.get(f"http://ip-api.com/json/{target_ip}")
                data = r.json()
                subprocess.run(["clear"])
                print("Results:")
                print(f"IP:  {data['query']}")
                print(f"City:  {data['city']}")
                print(f"Region:  {data['regionName']}")
                print(f"Country:  {data['country']}")
                print(f"Zip:  {data['zip']}")
                print(f"ISP:  {data['isp']}")
                print(f"as: {data['as']}")
                input("\nPress Enter to return to menu...")
            case 's':
                target_ip = input("input target ip: ")
                results = analyze_ip_security(target_ip)
                if results:
                    print(f"--- Analysis for {target_ip} ---")
                    print(f"Owner: {results['owner']}")
                    print(f"Location: {results['country']}, {results['continent']}")
                    print(f"Reputation: ({results['reputation']})")
                    print(f"Malicious: {results['malicious_count']} | Suspicious: {results['suspicious_count']} | Harmless: {results['harmless_count']}")
                    if (results['malicious_count'] >= 3 or results['reputation'] <= -10):
                        print(f"{RED}Verdict: IP is dangerous{RESET}")
                    elif (results['malicious_count'] > 0 or results['reputation'] < 0):
                        print(f"{YELLOW}Verdict: IP is suspicious{RESET}")
                    elif (results['harmless_count'] >= 3 or results['reputation'] >= 3):
                        print(f"{GREEN}Verdict: IP is harmless{RESET}")
                    else:
                        print(f"Unknown IP: Lack of data")
                    vpn_indicators = ['vpn', 'proxy', 'tor', 'hosting']
                    found_tags = [t for t in results['tags'] if t in vpn_indicators]
                    if found_tags:
                        print(f"{YELLOW}VPN/Proxy Indicators Found: {', '.join(found_tags)}{RESET}")
                input("\nPress Enter to return to menu...")
            case 'v':
                target_ip = input('(m)ine\ninput ip: ')
                if target_ip == 'm':
                    target_ip = get_ip()
                r = requests.get(f"http://ip-api.com/json/{target_ip}")
                data = r.json()
                print(data)
                input("\nPress Enter to return to menu...")
            case 'q':
                break
            case _:
                print("Invalid option. Please try again.")

if __name__ == '__main__':
    main()