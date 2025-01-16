# **Diplom Project TeachMeSkills**


### Содержание:

 1. [SOC Practical test](https://github.com/AntonShadzin/Diplom_Cyb04/tree/main?tab=readme-ov-file#soc-practical-test)
 2. [Bash-скрипт по установке  Volatility](https://github.com/AntonShadzin/Diplom_Cyb04/tree/main?tab=readme-ov-file#%D1%81%D0%BE%D0%B7%D0%B4%D0%B0%D1%82%D1%8C-%D1%81%D0%BA%D1%80%D0%B8%D0%BF%D1%82-%D0%BD%D0%B0-%D0%BB%D1%8E%D0%B1%D0%BE%D0%BC-%D1%8F%D0%B7%D1%8B%D0%BA%D0%B5-%D0%BA%D0%BE%D1%82%D0%BE%D1%80%D1%8B%D0%B9-%D0%B2-%D0%B8%D0%BD%D1%84%D0%BE%D1%80%D0%BC%D0%B0%D1%82%D0%B8%D0%B2%D0%BD%D0%BE%D0%BC-%D0%B2%D0%B8%D0%B4%D0%B5-%D0%B1%D1%83%D0%B4%D0%B5%D1%82-%D0%B7%D0%B0%D0%BF%D1%83%D1%81%D0%BA%D0%B0%D1%82%D1%8C-%D1%81%D0%BA%D1%80%D0%B8%D0%BF%D1%82-%D1%81-%D1%83%D1%81%D1%82%D0%B0%D0%BD%D0%BE%D0%B2%D0%BA%D0%BE%D0%B9)
 3. [Python-скрипт проверки url через virustotal](https://github.com/AntonShadzin/Diplom_Cyb04/tree/main?tab=readme-ov-file#%D0%B0%D0%B2%D1%82%D0%BE%D0%BC%D0%B0%D1%82%D0%B8%D0%B7%D0%B8%D1%80%D0%BE%D0%B2%D0%B0%D1%82%D1%8C-%D0%BF%D1%80%D0%BE%D1%86%D0%B5%D1%81%D1%81-%D0%BF%D1%80%D0%BE%D0%B2%D0%B5%D1%80%D0%BA%D0%B8-url-%D1%87%D0%B5%D1%80%D0%B5%D0%B7-virustotal)
 4. [Playbook устранения уязвимости CVE-2021-41773](https://github.com/AntonShadzin/Diplom_Cyb04/tree/main?tab=readme-ov-file#%D0%B2%D1%8B-%D0%BE%D0%B1%D0%BD%D0%B0%D1%80%D1%83%D0%B6%D0%B8%D0%BB%D0%B8-%D1%83%D1%8F%D0%B7%D0%B2%D0%B8%D0%BC%D0%BE%D1%81%D1%82%D1%8C-cve-2021-41773-%D0%BD%D0%B0-%D0%B2%D0%B0%D1%88%D0%B5%D0%BC-web-%D1%81%D0%B5%D1%80%D0%B2%D0%B5%D1%80%D0%B5)
 5. [Установить SIEM систему (на ваше усмотрение Wazuh, ELK\EFK, cloud splunk)](https://github.com/AntonShadzin/Diplom_Cyb04/tree/main?tab=readme-ov-file#-%D1%83%D1%81%D1%82%D0%B0%D0%BD%D0%BE%D0%B2%D0%B8%D1%82%D1%8C-siem-%D1%81%D0%B8%D1%81%D1%82%D0%B5%D0%BC%D1%83-%D0%BD%D0%B0-%D0%B2%D0%B0%D1%88%D0%B5-%D1%83%D1%81%D0%BC%D0%BE%D1%82%D1%80%D0%B5%D0%BD%D0%B8%D0%B5-wazuh-elkefk-cloud-splunk)


## SOC Practical test 
___
>    Дать ответы на практический тест по кибербезопасности:
___

```text
Дать ответы на практическийпо кибербезопасности:
```

[Practical test docx file](/Practical%20test/Diplom.docx)

[Practical test README file](/Practical%20test/README.md)

## Создать скрипт на любом языке, который в информативном виде будет запускать скрипт с установкой:
___
>   AVML - создание дампа оперативной памяти
>    Volatility - фреймворк для работы с артефактами форензики
>    dwarf2json - создание symbol table для кастомного ядра linux
>    Сделает снимок Debug kernel для symbol table
___

> [!TIP]
> *Проверено на Ubuntu 18.04 20.04 22.04 Kali. Возможно при копировании в конец строк добавится скрытый символ ^M. Для работы его нужно будет удалить. Чтобы его увидеть в редакторе vi необходимо ввести :e ++ff=unix

[Script to install volatility](/Script%20install%20volatility/ubuntu)

<details><summary>Bash cкрипт</summary>

```bash

#!/bin/bash

RED='\e[31m'
GREEN='\e[32m'
BLUE='\e[34m'
RESET='\e[0m'

echo -e "$BLUE Welcome to install Volatility3 $RESET"
sudo apt-get update >/dev/null

echo -e "$BLUE Check and install dependency $RESET"

if dpkg -l python3-full >/dev/null
then echo -e "$GREEN Already installed python3-full $RESET"
else echo -e "$BLUE Install python3-full $RESET" && sudo apt-get install -y pyton3-full
fi

if dpkg -l python3-pip >/dev/null
then echo -e "$GREEN Already installed python3-pip $RESET"
else echo -e "$BLUE Install python3-pip $RESET" && sudo apt-get install -y pyton3-pip
fi

if dpkg -l wget >/dev/null
then echo -e "$GREEN Already installed wget $RESET"
else echo -e "$BLUE Install wget $RESET" && sudo apt-get install -y wget
fi

if dpkg -l git >/dev/null
then echo -e "$GREEN Already installed git $RESET"
else echo -e "$BLUE Install git $RESET" && sudo apt-get install -y git
fi

if dpkg -l golang-go >/dev/null
then echo -e "$GREEN Already installed golang-go $RESET"
else echo -e "$BLUE Install golang-go $RESET" && sudo apt-get install -y golang-go
fi

cd

echo -e "$GREEN Download the latest release of avml $RESET"

wget https://github.com/microsoft/avml/releases/download/v0.14.0/avml

echo -e "$GREEN Make the file executable $RESET"

sudo chmod +x avml


echo -e "$GREEN Move the executable to a directory in /usr/local/bin $RESET"

sudo mv avml /usr/local/bin/

if avml --help >/dev/null
then echo -e "$GREEN AVML is installed $RESET"
else echo -e "$RED AVML is not installed $RESET" && exit 0
fi

echo -e "$GREEN Create memory dump $RESET"

sudo avml ~/memory.dmp
sudo chown $USER:$USER memory.dmp
sudo chmod 755 memory.dmp


echo -e "$GREEN Install Volatility3 $RESET"

git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3

echo -e "$GREEN Install Volatility3 requirements $RESET"


pip3 install -r requirements-minimal.txt
pip3 install -r requirements.txt

echo -e "$GREEN Install the corresponding debug symbols $RESET"

release=$(lsb_release -cs)

sudo tee /etc/apt/sources.list.d/ddebs.list <<EOF

deb http://ddebs.ubuntu.com $release main restricted universe multiverse
deb http://ddebs.ubuntu.com $release-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com $release-proposed main restricted universe multiverse


EOF

wget -O - http://ddebs.ubuntu.com/dbgsym-release-key.asc | sudo apt-key add -


sudo apt update
sudo apt install linux-image-$(uname -r)-dbgsym

# Debug kernel is at: /usr/lib/debug/boot/vmlinux-$(uname -r)
echo -e "$GREEN Instal dwarf2json $RESET"
cd 
git clone https://github.com/volatilityfoundation/dwarf2json.git
cd dwarf2json
go build
sudo cp dwarf2json /usr/local/bin/
if dwarf2json --help >/dev/null
then echo -e "$GREEN dwarf2json is installed $RESET"
else echo -e "$RED dwarf2json is not installed $RESET" && exit 0
fi


cd /usr/lib/debug/boot/
chmod 755 vmlinux-$(uname -r)
chown $USER:$USER vmlinux-$(uname -r)
sudo mkdir ~/volatility3/volatility3/symbols/linux
sudo dwarf2json linux  --elf /usr/lib/debug/boot/vmlinux-$(uname -r) --system-map /boot/System.map-$(uname -r) > ~/Ubuntu-$(uname -r).json
sudo cp ~/Ubuntu-$(uname -r).json ~/volatility3/volatility3/symbols/linux/
cd ~/volatility3

PS3='Select module for volatility3: '
sys=("Lsof" "Pstree" "Bash" "Check_creds" "Exit")
select fav in "${sys[@]}"; do
    case $fav in
        "Lsof")
            echo -e  "$GREEN Lists open files for each processes $RESET"
            sudo python3 vol.py -f ~/memory.dmp linux.lsof.Lsof
            break
            ;;
         "Pstree")
            echo -e  "$GREEN Plugin for listing processes in a tree based on their parent process ID $RESET"
            sudo python3 vol.py -f ~/memory.dmp linux.pstree.PsTree
            break
            ;;
        "Bash")
            echo -e  "$GREEN Recovers bash command history from memory $RESET"
            sudo python3 vol.py -f ~/memory.dmp linux.bash.Bash
            break
            ;;
        "Check_creds")
            echo -e  "$GREEN Lists open files for each processes $RESET"
            sudo python3 vol.py -f ~/memory.dmp linux.check_creds.Check_creds
            break
            ;;
        "Exit")
            echo -e "$RED User requested exit $RESET"
            exit 0
            ;;
             *) echo -e "$RED invalid option $REPLY $RESET";;
    esac
done

```

</details>

## Автоматизировать процесс проверки url через virustotal
___
>  Напишите небольшой скрипт для автоматизированной проверки url. Можно использовать любой язык программирования
___

[Script to check URL on Virustotal](/Script%20to%20check%20URL%20on%20Virustotal/Virustotal.py)

<details><summary>Python</summary>

```python

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

```
</details>

## Вы обнаружили уязвимость CVE-2021-41773 на вашем web сервере
___
>    Вам необходимо создать задачу для IT по её устранению. Что нужно будет сделать специалисту, чтобы исправить эту уязвимость? Напишите plabook для специалиста SOC L1
___

[Playbook docx файл](/Playbook/Playbook%20по%20устранению%20уязвимости%20CVE.docx)

[Playbook README файл](/Playbook/README.md)

## ** Установить SIEM систему (на ваше усмотрение Wazuh, ELK\EFK, cloud splunk)
___
> Настроить логирование и отправку windows 10 логов
___

<details><summary>Скрины логов с Win 10</summary>

![win10_1](/Wazuh/wazuh_win10_1.png)

![win10_2](/Wazuh/wazuh_win10_2.png)

![win10_3](/Wazuh/wazuh_win10_3.png)

</details>

___
> Настроить логирование и отправку linux syslog / auditd
___

<details><summary>Скрины логов с Linux</summary>

![linux_1](/Wazuh/wazuh_kali_1.png)

![linux_2](/Wazuh/wazuh_kali_2.png)

![linux_3](/Wazuh/wazuh_kali_3.png)

</details>

[Мануал по работе с Wazuh](/Wazuh/siem.7z)