FROM kalilinux/kali-rolling

RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list && \
  echo "deb-src http://http.kali.org/kali kali-rolling main contrib non-free" >> /etc/apt/sources.list

ENV DEBIAN_FRONTEND noninteractive

RUN set -x \
  && apt -yqq update \
  && apt -yqq full-upgrade \
  && apt clean

RUN apt install --yes metasploit-framework

RUN sed -i 's/systemctl status ${PG_SERVICE}/service ${PG_SERVICE} status/g' /usr/bin/msfdb && \
  service postgresql start && \
  msfdb reinit

WORKDIR /usr/src/app

RUN apt install -y kali-system-core kali-system-cli

RUN apt install -y kali-linux-headless

COPY ./run.sh ./run.sh

RUN chmod +x ./run.sh

CMD ["./run.sh"]
