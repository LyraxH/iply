import os
import json
import requests
import subprocess
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv('VT_API_KEY')
if not VT_API_KEY:
    print('No API key found')

RED = "\033[38;2;255;0;0m"
GREEN = "\033[38;2;0;255;0m"
YELLOW = "\033[38;2;255;255;0m"
RESET = "\033[0m"

def get_IP():
    result = subprocess.run(['curl', 'https://api.ipify.org'], capture_output=True, text=True)
    return result.stdout

def get_rep(toGet):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{toGet}'
    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json"
    }
    r = requests.get(url, headers=headers)

    if r.status_code == 200:
        data = r.json()
        info = data.get('data', {}).get('attributes', {})
        stats = info.get('last_analysis_stats', {})
        malicious_count = stats.get('malicious', 0)
        suspicious_count = stats.get('suspicious', 0)
        harmless_count = stats.get('harmless', 0)
        owner = info.get('as_owner', 'Unknown Owner')
        country = info.get('country', 'Unknown Country')
        continent = info.get('continent', 'Unknown Continent')
        reputation = info.get('reputation', 0)
        print(f"--- Analysis for {toGet} ---")
        print(f"Owner: {owner}")
        print(f"Location: {country}, {continent}")
        print(f"Reputation: ({reputation})")
        print(f"Malicious: {malicious_count} | Suspicious: {suspicious_count} | Harmless: {harmless_count}")
        if (malicious_count >= 3 or reputation <= -10):
            print(f"{RED}Verdict: IP is dangerous{RESET}")
        elif (malicious_count > 0 or reputation < 0):
            print(f"{YELLOW}Verdict: IP is suspicious{RESET}")
        elif (harmless_count >= 3 or reputation >= 3):
            print(f"{GREEN}Verdict: IP is harmless{RESET}")
        else:
            print(f"Unknown IP: Lack of data")
        return
    elif r.status_code == 401:
        print('Invalid API key')
        return None
    elif r.status_code == 404:
        print('IP not found')
        return None
    elif r.status_code == 429:
        print('Rate limit exceeded')
        return None
    else:
        print('Error: ' + r.status_code)
        return None

def main():
    while True:
        toDo = input('(g)et, (f)ind, (s)ecurity, (v)erbose (q)uit \n what do: ').lower()
        subprocess.run(["clear"])
        match (toDo):
            case "g": #prints current ip
                result = subprocess.run(['curl', 'https://api.ipify.org'], capture_output=True, text=True)
                print('your ip:',result.stdout)
            case "f":
                toGet = input('(m)ine\ninput ip: ')
                if toGet == 'm':
                    toGet = get_IP()
                r = requests.get(f'http://ip-api.com/json/{toGet}')
                data = r.json()
                subprocess.run(["clear"])
                print('Results:')
                print(f'IP:  {data['query']}')
                print(f'City:  {data['city']}')
                print(f'Region:  {data['regionName']}')
                print(f'Country:  {data['country']}')
                print(f'Zip:  {data['zip']}')
                print(f'ISP:  {data['isp']}')
                print(f'as: {data['as']}')
                input("\nPress Enter to return to menu...")
            case "s":
                toGet = input('input ip: ')
                get_rep(toGet)
                input("\nPress Enter to return to menu...")
            case "v": #prints any ip (or yours) everything
                toGet = input('(m)ine\ninput ip: ')
                if toGet == 'm':
                    toGet = get_IP()
                r = requests.get(f'http://ip-api.com/json/{toGet}')
                data = r.json()
                print(data)
                input("\nPress Enter to return to menu...")
            case "q":
                break
            case _:
                print("Invalid option. Please try again.")

if __name__ == '__main__':
    main()