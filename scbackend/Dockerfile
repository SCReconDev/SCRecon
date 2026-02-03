FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whatweb \
    gobuster \
    git \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
RUN mkdir -p /app/state

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app
RUN chmod +x /app/start.sh

ENV PYTHONUNBUFFERED=1
CMD ["/app/start.sh"]

