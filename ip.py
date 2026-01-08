import os
import json
import requests
import subprocess
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv('VT_API_KEY')
if not VT_API_KEY:
    print('No API key found')

toDo = input('(g)et, (f)ind, (s)ceure, (v)erbose \n what do: ')
subprocess.run(["clear"])
match (toDo):
    case "g": #prints current ip
        result = subprocess.run(['curl', 'https://api.ipify.org'], capture_output=True, text=True)
        print('your ip:',result.stdout)
    case "f":
        toGet = input('(m)ine\ninput ip: ')
        if toGet == 'm':
            toGet = subprocess.run(['curl', 'https://api.ipify.org'], capture_output=True, text=True)
            toGet = toGet.stdout
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
    case "s":
        print('a');
    case "v": #prints any ip (or yours) everything
        toGet = input('(m)ine\ninput ip: ')
        if toGet == 'm':
            toGet = subprocess.run(['curl', 'https://api.ipify.org'], capture_output=True, text=True)
            toGet = toGet.stdout
        r = requests.get(f'http://ip-api.com/json/{toGet}')
        data = r.json()
        print(data)