FROM python:3.12-slim

WORKDIR /home/analyzer

COPY . .

CMD ["python", "./log_analyzer.py"]
