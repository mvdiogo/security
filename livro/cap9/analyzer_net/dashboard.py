from flask import Flask, render_template, jsonify, request
import sqlite3
from datetime import datetime, timedelta

app = Flask(__name__)
DB_PATH = 'network_traffic.db'

def get_packet_stats(filters=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    base_query = 'SELECT COUNT(*) FROM packets'
    malicious_query = 'SELECT COUNT(*) FROM packets WHERE is_malicious=1'
    
    # Construir condições de filtro
    conditions = []
    params = []
    
    if filters:
        # Filtro de status
        status = filters.get('status')
        if status == 'malicious':
            base_query += ' WHERE is_malicious=1'
        elif status == 'normal':
            base_query += ' WHERE is_malicious=0'
        
        # Filtro de texto
        search = filters.get('search')
        if search:
            search_condition = "(src_ip LIKE ? OR dst_ip LIKE ? OR protocol LIKE ? OR reason LIKE ?)"
            if 'WHERE' in base_query:
                base_query += ' AND ' + search_condition
            else:
                base_query += ' WHERE ' + search_condition
            params.extend([f'%{search}%'] * 4)
    
    # Executar consultas
    cursor.execute(base_query, params)
    total = cursor.fetchone()[0]
    
    # Consulta para maliciosos com filtros
    if 'WHERE' in base_query and 'is_malicious' not in base_query:
        malicious_query += base_query.split('WHERE')[1]
    
    cursor.execute(malicious_query, params)
    malicious = cursor.fetchone()[0]
    
    conn.close()
    return total, malicious

def get_recent_packets(filters=None, limit=50):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    base_query = '''
        SELECT timestamp, src_ip, src_port, dst_ip, dst_port, protocol, packet_size, is_malicious, reason
        FROM packets
    '''
    
    conditions = []
    params = []
    order_limit = ' ORDER BY id DESC LIMIT ?'
    params.append(limit)
    
    if filters:
        # Filtro de status
        status = filters.get('status')
        if status == 'malicious':
            conditions.append('is_malicious=1')
        elif status == 'normal':
            conditions.append('is_malicious=0')
        
        # Filtro de texto
        search = filters.get('search')
        if search:
            conditions.append("(src_ip LIKE ? OR dst_ip LIKE ? OR protocol LIKE ? OR reason LIKE ?)")
            params.extend([f'%{search}%'] * 4)
    
    # Construir query final
    if conditions:
        base_query += ' WHERE ' + ' AND '.join(conditions)
    
    base_query += order_limit
    cursor.execute(base_query, params)
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_traffic_over_time(filters=None, time_range='24h'):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Determinar intervalo de tempo
    now = datetime.now()
    if time_range == '24h':
        start_time = now - timedelta(hours=24)
        time_format = "%H:%M"
        time_group = "strftime('%H:%M', timestamp)"
    elif time_range == '7d':
        start_time = now - timedelta(days=7)
        time_format = "%Y-%m-%d"
        time_group = "date(timestamp)"
    else:  # 30d
        start_time = now - timedelta(days=30)
        time_format = "%Y-%m-%d"
        time_group = "date(timestamp)"
    
    # Construir query base
    base_query = f'''
        SELECT {time_group} AS time_group, COUNT(*)
        FROM packets
        WHERE timestamp >= ?
    '''
    
    conditions = []
    params = [start_time.strftime('%Y-%m-%d %H:%M:%S')]
    
    if filters:
        # Filtro de status
        status = filters.get('status')
        if status == 'malicious':
            conditions.append('is_malicious=1')
        elif status == 'normal':
            conditions.append('is_malicious=0')
        
        # Filtro de texto
        search = filters.get('search')
        if search:
            conditions.append("(src_ip LIKE ? OR dst_ip LIKE ? OR protocol LIKE ? OR reason LIKE ?)")
            params.extend([f'%{search}%'] * 4)
    
    # Adicionar condições extras
    if conditions:
        base_query += ' AND ' + ' AND '.join(conditions)
    
    base_query += f' GROUP BY time_group ORDER BY timestamp ASC'
    
    cursor.execute(base_query, params)
    data = cursor.fetchall()
    conn.close()
    
    # Formatar resultados
    result = []
    for row in data:
        result.append((row[0], row[1]))
    
    return result

@app.route("/")
def dashboard():
    # Obter filtros da query string
    status_filter = request.args.get('status')
    search_filter = request.args.get('search')
    
    filters = {}
    if status_filter in ['malicious', 'normal']:
        filters['status'] = status_filter
    if search_filter:
        filters['search'] = search_filter
    
    # Obter dados com filtros aplicados
    total, malicious = get_packet_stats(filters)
    recent_packets = get_recent_packets(filters)
    percent_malicious = (malicious / total * 100) if total > 0 else 0
    
    return render_template("dashboard.html",
                           total=total,
                           malicious=malicious,
                           percent=percent_malicious,
                           packets=recent_packets,
                           current_status=status_filter,
                           current_search=search_filter)

@app.route("/api/stats")
def api_stats():
    # Obter filtros da query string
    status_filter = request.args.get('status')
    search_filter = request.args.get('search')
    time_range = request.args.get('time_range', '24h')
    
    filters = {}
    if status_filter in ['malicious', 'normal']:
        filters['status'] = status_filter
    if search_filter:
        filters['search'] = search_filter
    
    # Obter dados com filtros aplicados
    total, malicious = get_packet_stats(filters)
    data_over_time = get_traffic_over_time(filters, time_range)
    
    return jsonify({
        "total": total,
        "malicious": malicious,
        "percent": (malicious / total * 100) if total > 0 else 0,
        "traffic_over_time": data_over_time
    })

@app.route("/api/packets")
def api_packets():
    # Obter filtros da query string
    status_filter = request.args.get('status')
    search_filter = request.args.get('search')
    limit = int(request.args.get('limit', 50))
    
    filters = {}
    if status_filter in ['malicious', 'normal']:
        filters['status'] = status_filter
    if search_filter:
        filters['search'] = search_filter
    
    # Obter pacotes com filtros aplicados
    packets = get_recent_packets(filters, limit)
    
    # Converter para formato JSON
    columns = ['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 
               'protocol', 'packet_size', 'is_malicious', 'reason']
    
    result = []
    for p in packets:
        result.append(dict(zip(columns, p)))
    
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True, port=5000)