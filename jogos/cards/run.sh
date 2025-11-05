#!/bin/sh
set -e

docker compose build --no-cache
docker compose up -d

echo "✅ Aplicação rodando em http://localhost:8088"
