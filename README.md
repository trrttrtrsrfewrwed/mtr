Для запуска:
```
pip install -r requirements.txt
sudo python3 mtr.py [args]
```

Аргументы:
```
usage: mtr.py [-h] [-6] [-u] [-T] [-m MAX_TTL] [-c REPORT_CYCLES] hostname

positional arguments:
  hostname

optional arguments:
  -h, --help            show this help message and exit
  -6                    use IPv6 instead of IPv4
  -u, --udp             use UDP instead of ICMP echo
  -T, --tcp             use TCP instead of ICMP echo
  -m MAX_TTL, --max-ttl MAX_TTL
                        maximum number of hops
  -c REPORT_CYCLES, --report-cycles REPORT_CYCLES
                        set the number of pings sent
```
Программа выводит результат работы в консоль.
Вывод будет изменяться, пока не пройдёт `REPORT_CYCLES` итераций,
после чего программа завершит работу
