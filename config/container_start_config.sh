#Containers should be run in a privileged mode for the iptables to work
# the image should have iptables installed
docker run -it --privileged --name=cont1 ubuntu:v2 /bin/bash 
