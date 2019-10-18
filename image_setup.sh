docker pull docker.elastic.co/elasticsearch/elasticsearch:7.4.0
docker pull docker.elastic.co/beats/filebeat:7.4.0
docker pull docker.elastic.co/kibana/kibana:7.4.0
docker pull bitsensor/elastalert:3.0.0-beta.1
docker pull blacktop/zeek:elastic
docker pull blacktop/elasticsearch:6.8.2
docker pull thehiveproject/cortex:3.0.0
docker pull thehiveproject/thehive:3.4.0
docker build -t kibana-ea-plugin:7.4.0 kibana
