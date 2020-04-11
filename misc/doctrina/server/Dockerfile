FROM python:3.8

COPY requirements.txt .
RUN pip install -r ./requirements.txt

COPY __main__.py /opt/app.py
COPY templates/ /opt/templates
COPY static/ /opt/static
COPY ml /opt/ml

WORKDIR /opt

CMD gunicorn app:app -b :7000 --name app
