import json
import requests
import subprocess

toDo = input('(g)et, (f)ind \n what do: ')
subprocess.run(["clear"])
match (toDo):
    case "g":
        result = subprocess.run(['curl', 'https://api.ipify.org'], capture_output=True, text=True)
        print('your ip:',result.stdout)
    case "f":
        toGet = input('(m)ine\ninput ip: ')
        if toGet == 'm':
            toGet = subprocess.run(['curl', 'https://api.ipify.org'], capture_output=True, text=True)
            toGet = toGet.stdout
        r = requests.get(f'http://ip-api.com/json/{toGet}')
        data = r.json()
        print(data)