#
# EMLRender Dockerfile
#
# Author: Xavier Mertens <xavier@rootshell.be>
# Copyright: GPLv3 (http://gplv3.fsf.org)
# Fell free to use the code, but please share the changes you've made
#
 
FROM ubuntu:16.04
MAINTAINER Xavier Mertens <xavier@rootshell.be>

USER root
RUN apt-get update && apt-get install -y \
    wget python3-pip \
    xvfb xfonts-100dpi xfonts-75dpi xfonts-scalable xfonts-cyrillic \
    libssl-dev \
    flashplugin-nonfree

#
# Install precompiled wkhtmltoimage
#
WORKDIR /opt
RUN wget -O - --quiet https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.4/wkhtmltox-0.12.4_linux-generic-amd64.tar.xz | xz -d - | tar xvf -
RUN cp wkhtmltox/bin/wkhtmltoimage /usr/local/bin

#
# Install imgkit library
# 
RUN pip3 install imgkit

#
# Install PIL library
#
RUN pip3 install pillow

#
# Install flask
#
WORKDIR /tmp
COPY requirements.txt .
RUN pip3 install -r /tmp/requirements.txt
RUN rm /tmp/requirements.txt&

RUN mkdir /opt/emlrender
WORKDIR /opt/emlrender
COPY api.py .

EXPOSE 443

ENTRYPOINT [ "/opt/emlrender/api.py" ]