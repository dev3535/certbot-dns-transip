FROM python:3.9.5
RUN pip install git+https://github.com/dev3535/certbot-dns-transip.git@master
ENTRYPOINT ["certbot"]
