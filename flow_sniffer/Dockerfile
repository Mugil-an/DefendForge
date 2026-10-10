FROM python:3.11-slim
RUN apt-get update && apt-get install -y libpcap-dev tcpdump gcc
RUN pip install cicflowmeter requests
COPY sniffer.py /app/sniffer.py
WORKDIR /app
CMD ["python", "sniffer.py"]
