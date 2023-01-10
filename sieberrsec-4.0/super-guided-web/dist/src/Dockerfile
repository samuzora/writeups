FROM python:3

RUN useradd -ms /bin/bash ctf

COPY . /home/ctf

RUN chown -R ctf /home/ctf/*

# Ensure people can't just delete the flag file
RUN chmod -R 544 /home/ctf/
RUN chmod 544 /home/ctf/templates
RUN chmod 544 /home/ctf/content
RUN chmod 744 /home/ctf/content/databases

WORKDIR /home/ctf

RUN pip3 install -r requirements.txt

USER ctf

CMD ["python3", "-m", "gunicorn", "--bind", "0.0.0.0", "main:app"]