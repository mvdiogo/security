import multiprocessing
host = "0.0.0.0"
port = "8088"
#bind = "0.0.0.0:8088"
workers = 4
threads = 2
worker_class = "gthread"
timeout = 300
graceful_timeout = 200
keepalive = 100
loglevel = "info"
errorlog = "/app/logs/error.log"
accesslog = "/app/logs/access.log"
