import requests

def check_url(api_key, url):
    api_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {
        'apikey': api_key,
        'resource': url,
    }
    
    response = requests.get(api_url, params=params)
    
    if response.status_code == 200:
        result = response.json()
        if result['response_code'] == 1:  # URL был проверен
            print(f"URL: {url}")
            print("Обнаруженные угрозы:")
            for engine in result['scans']:
                if result['scans'][engine]['detected']:
                    print(f"{engine}: Обнаружено")
                else:
                    print(f"{engine}: Не обнаружено")
        else:
            print("URL не найден в базе данных.")
    else:
        print(f"Ошибка: {response.status_code}")

if __name__ == "__main__":
    API_KEY = '6b98b76b60da24c0f6567bc9551b091abe7cb15760be75683fda7fbaba27239e'
    url_to_check = input("Введите URL для проверки: ")
    check_url(API_KEY, url_to_check)
