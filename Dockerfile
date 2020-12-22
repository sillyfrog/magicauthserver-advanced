FROM python

RUN pip install --upgrade pip && \
    pip install flask pyotp qrcode pillow flask_sqlalchemy psycopg2 redis

EXPOSE 80
WORKDIR /
ENV  PYTHONUNBUFFERED=1

COPY authserver.py /
COPY templates /templates/
COPY auth /auth/

CMD ["./authserver.py"]