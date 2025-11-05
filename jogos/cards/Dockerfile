# syntax=docker/dockerfile:1
FROM python:3.13-alpine AS base

# Instala dependências básicas
RUN apk add --no-cache gcc musl-dev libffi-dev

# Cria diretório da aplicação
WORKDIR /app

# Copia apenas requirements primeiro (cache eficiente)
COPY requirements.txt .

# Instala dependências Python
RUN pip install --no-cache-dir -r requirements.txt

# Copia o restante do projeto
COPY . .

# Cria usuário sem privilégios
RUN adduser -D flaskuser
RUN mkdir -p /app/logs && chown -R flaskuser:flaskuser /app/logs
RUN touch /app/app.log && chown flaskuser:flaskuser /app/app.log
RUN touch /app/error.log && chown flaskuser:flaskuser /app/error.log
USER flaskuser

# Exposição da porta
EXPOSE 8088

# Usa config separada para o Gunicorn
CMD ["gunicorn", "-c", "gunicorn_conf.py", "app:app"]
