# **Diplom Project TeachMeSkills**


## SOC Practical test 
___
>    Дать ответы на практический тест по кибербезопасности:
___

```
Дать ответы на практический тест \n \r по кибербезопасности:
```

[Practical test](/Practical%20test/Diplom.docx)

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

## Автоматизировать процесс проверки url через virustotal
___
>  Напишите небольшой скрипт для автоматизированной проверки url. Можно использовать любой язык программирования
___

[Script to check URL on Virustotal](/Script%20to%20check%20URL%20on%20Virustotal/Virustotal.py)

## Вы обнаружили уязвимость CVE-2021-41773 на вашем web сервере
___
>    Вам необходимо создать задачу для IT по её устранению. Что нужно будет сделать специалисту, чтобы исправить эту уязвимость? Напишите plabook для специалиста SOC L1
___
[Устранение уязвимости](/Playbook/Playbook%20по%20устранению%20уязвимости%20CVE.docx)


## ** Установить SIEM систему (на ваше усмотрение Wazuh, ELK\EFK, cloud splunk)
___
> Настроить логирование и отправку windows 10 логов
___

<details><summary>Скрины логов с Win 10</summary>

![win10_1](/Wazuh/wazuh_win10_1.png)

![win10_2](/Wazuh/wazuh_win10_2.png)

![win10_3](/Wazuh/wazuh_win10_3.png)

</details>


    Настроить логирование и отправку linux syslog / auditd

<details><summary>Скрины логов с Linux</summary>

![linux_1](/Wazuh/wazuh_kali_1.png)

![linux_2](/Wazuh/wazuh_kali_2.png)

![linux_3](/Wazuh/wazuh_kali_3.png)

</details>

[Мануал по работе с Wazuh](/Wazuh/siem.7z)