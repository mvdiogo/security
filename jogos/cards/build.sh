#!/bin/bash
docker compose build --no-cache
docker compose up -d
echo "Aplicação está rodando. Acesse: http://localhost:8072"