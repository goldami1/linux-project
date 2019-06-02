# Amikam Goldfarb and Shiran Avidov

FROM ubuntu:latest

ADD ./MyDockerDemo.txt /tmp/MyDockerDemo.txt

CMD  cat /tmp/MyDockerDemo.txt
