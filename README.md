# Домашнее задание к занятию «ELK»

### Грибанов Антон. FOPS-31

## Дополнительные ресурсы

При выполнении задания используйте дополнительные ресурсы:
- [docker-compose elasticsearch + kibana](11-03/docker-compose.yaml);
- [поднимаем elk в docker](https://www.elastic.co/guide/en/elasticsearch/reference/7.17/docker.html);
- [поднимаем elk в docker с filebeat и docker-логами](https://www.sarulabs.com/post/5/2019-08-12/sending-docker-logs-to-elasticsearch-and-kibana-with-filebeat.html);
- [конфигурируем logstash](https://www.elastic.co/guide/en/logstash/7.17/configuration.html);
- [плагины filter для logstash](https://www.elastic.co/guide/en/logstash/current/filter-plugins.html);
- [конфигурируем filebeat](https://www.elastic.co/guide/en/beats/libbeat/5.3/config-file-format.html);
- [привязываем индексы из elastic в kibana](https://www.elastic.co/guide/en/kibana/7.17/index-patterns.html);
- [как просматривать логи в kibana](https://www.elastic.co/guide/en/kibana/current/discover.html);
- [решение ошибки increase vm.max_map_count elasticsearch](https://stackoverflow.com/questions/42889241/how-to-increase-vm-max-map-count).

**Примечание**: если у вас недоступны официальные образы, можете найти альтернативные варианты в DockerHub, например, [такой](https://hub.docker.com/layers/bitnami/elasticsearch/7.17.13/images/sha256-8084adf6fa1cf24368337d7f62292081db721f4f05dcb01561a7c7e66806cc41?context=explore).

### Задание 1. Elasticsearch 

Установите и запустите Elasticsearch, после чего поменяйте параметр cluster_name на случайный. 

*Приведите скриншот команды 'curl -X GET 'localhost:9200/_cluster/health?pretty', сделанной на сервере с установленным Elasticsearch. Где будет виден нестандартный cluster_name*.
```bash
sudo apt update && sudo apt install gnupg apt-transport-https
#Доступ к ресурсам elastic.co из РФ заблокирован.
#Пакет скачал через web browser (proxy-addon) по адресу: [(https://mirrors.huaweicloud.com/elasticsearch/8.8.1/)]
sudo apt install /home/qshar/elastic/elasticsearch-8.8.1-amd64.deb
sudo systemctl daemon-reload
sudo systemctl status elasticsearch.service
sudo systemctl enable elasticsearch.service
sudo sysctl vm.swappiness=1 #или выключаем подкачку: sudo swapoff -a

sudo nano /etc/elasticsearch/elasticsearch.yml # cluster.name: clusterGribanovAV и network.host: localhost
sudo systemctl start elasticsearch.service
curl -X GET 'localhost:9200/_cluster/health?pretty'
curl -X GET 'localhost:9200/_cat/master?pretty'
curl -X GET 'http://localhost:9200'
```
 ![sdb_003](https://github.com/Qshar1408/sdb_03/blob/main/img/sdb_03_001.png)
 ![sdb_003](https://github.com/Qshar1408/sdb_03/blob/main/img/sdb_03_002.png)

---

### Задание 2. Kibana

Установите и запустите Kibana.

*Приведите скриншот интерфейса Kibana на странице http://<ip вашего сервера>:5601/app/dev_tools#/console, где будет выполнен запрос GET /_cluster/health?pretty*.

```bash
sudo apt install /tmp/kibana-7.17.9-amd64.deb
sudo systemctl daemon-reload
sudo systemctl status logstash.service
sudo systemctl enable logstash.service
sudo systemctl start logstash.service

sudo nano /etc/kibana/kibana.yml # server.host: "localhost"  и  server.port: 5601

http://localhost:5601/app/dev_tools#/console
```

 ![sdb_003](https://github.com/Qshar1408/sdb_03/blob/main/img/sdb_03_003.png)
 
---

### Задание 3. Logstash

Установите и запустите Logstash и Nginx. С помощью Logstash отправьте access-лог Nginx в Elasticsearch. 

*Приведите скриншот интерфейса Kibana, на котором видны логи Nginx.*
 
 ![sdb_003](https://github.com/Qshar1408/sdb_03/blob/main/img/sdb_03_004.png)
 
---

### Задание 4. Filebeat. 

Установите и запустите Filebeat. Переключите поставку логов Nginx с Logstash на Filebeat. 

*Приведите скриншот интерфейса Kibana, на котором видны логи Nginx, которые были отправлены через Filebeat.*

 ![sdb_003](https://github.com/Qshar1408/sdb_03/blob/main/img/sdb_03_005.png)

