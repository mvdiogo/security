from flask import Flask, render_template, request, redirect, url_for
from scanner import DASTScanner  # Importação da classe DASTScanner
import json
import threading

app = Flask(__name__)
scan_report = None
scan_in_progress = False  # Variável global para rastrear o status do scan

@app.route('/')
def index():
    """Página inicial para iniciar o scan."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Inicia o scan e redireciona para o relatório."""
    global scan_in_progress, scan_report
    if scan_in_progress:
        return "Um scan já está em andamento. Por favor, aguarde."
    
    target_url = request.form['target_url']
    scanner = DASTScanner(target_url)
    scan_in_progress = True
    
    def run_scan():
        global scan_report, scan_in_progress
        scan_report = scanner.run_full_scan()
        with open('report.json', 'w') as f:
            json.dump(scan_report, f, indent=2)
        scan_in_progress = False
    
    threading.Thread(target=run_scan).start()
    return redirect(url_for('report'))

@app.route('/report')
def report():
    """Exibe o relatório do scan ou informa que o scan está em andamento."""
    global scan_in_progress, scan_report
    if scan_in_progress:
        return render_template('scan_in_progress.html')
    else:
        if scan_report is None:
            try:
                with open('report.json', 'r') as f:
                    scan_report = json.load(f)
            except FileNotFoundError:
                return "Nenhum relatório disponível. Por favor, realize um scan primeiro."
        return render_template('report.html', report=scan_report)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)