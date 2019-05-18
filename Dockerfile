FROM python:3

RUN pip install --upgrade pip && \
    pip install flask pyotp qrcode pillow flask_sqlalchemy psycopg2 redis

COPY authserver.py /
COPY templates /templates/
COPY auth /auth/
WORKDIR /
#CMD ["./authserver.py"]
CMD ["sleep", "58888"]