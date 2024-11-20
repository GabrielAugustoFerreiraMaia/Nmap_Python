
import nmap
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import psutil
import platform
import csv
import json
import matplotlib.pyplot as plt
from scapy.all import sniff
from scapy.layers.inet import IP
import subprocess
import requests


class ScannerGUI:
    def __init__(self):
        self.janela = tk.Tk()
        self.janela.title("Scanner de Vulnerabilidades")

        self.label_ip = tk.Label(self.janela, text="IP:")
        self.label_ip.pack()

        self.entry_ip = tk.Entry(self.janela)
        self.entry_ip.pack()

        self.botao_scan = tk.Button(self.janela, text="Scan", command=self.scan)
        self.botao_scan.pack()

        self.botao_malware = tk.Button(self.janela, text="Detecção de Malware", command=self.detecao_malware)
        self.botao_malware.pack()

        self.botao_trafego = tk.Button(self.janela, text="Análise de Tráfego", command=self.analise_trafego)
        self.botao_trafego.pack()

        self.botao_patch = tk.Button(self.janela, text="Verificação de Patch", command=self.verificacao_patch)
        self.botao_patch.pack()

        self.botao_dispositivos = tk.Button(self.janela, text="Descoberta de Dispositivos", command=self.descoberta_dispositivos)
        self.botao_dispositivos.pack()

        self.botao_mapeamento = tk.Button(self.janela, text="Mapeamento de Rede", command=self.mapeamento_rede)
        self.botao_mapeamento.pack()

        self.botao_protocolos = tk.Button(self.janela, text="Análise de Protocolos", command=self.analise_protocolos)
        self.botao_protocolos.pack()

        self.botao_relatorio = tk.Button(self.janela, text="Relatório Detalhado", command=self.relatorio_detalhado)
        self.botao_relatorio.pack()

        self.text_result = tk.Text(self.janela)
        self.text_result.pack()

    def scan(self):
        ip = self.entry_ip.get()
        nm = nmap.PortScanner()
        nm.scan(ip, '1-1024')
        resultado = ""
        for host in nm.all_hosts():
            resultado += f"Host: {host} ({nm[host].hostname()})\n"
            for proto in nm[host].all_protocols():
                resultado += f"Protocol: {proto}\n"
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    resultado += f"Port: {port} \t State: {nm[host][proto][port]['state']}\n"
        self.text_result.insert(tk.END, resultado)

    def detecao_malware(self):
        arquivo = filedialog.askopenfilename(title="Selecione o arquivo")
        if arquivo:
            api_key = "a6fb28630285d4d49d09b7a013e9d0a6fd3ca55fe7715e611c91013b88c728ae"
            url = "https://www.virustotal.com/api/v3/files"
            headers = {"x-apikey": api_key}
            files = {"file": open(arquivo, "rb")}
            resposta = requests.post(url, headers=headers, files=files)
            if resposta.status_code == 200:
                resultado = resposta.json()
                id_arquivo = resultado["data"]["id"]
                self.buscar_analise(id_arquivo)
            else:
                self.text_result.insert(tk.END, "Erro ao enviar arquivo")
        else:
            self.text_result.insert(tk.END, "Nenhum arquivo selecionado")
        
    def scan_arquivo(self, arquivo):
        comando = f"clamdscan {arquivo}"
        resultado = subprocess.run(comando, shell=True, stdout=subprocess.PIPE)
        return resultado.stdout.decode()
        
    def buscar_analise(self, id_arquivo):
        api_key = "a6fb28630285d4d49d09b7a013e9d0a6fd3ca55fe7715e611c91013b88c728ae"
        url = f"https://www.virustotal.com/api/v3/analyses/{id_arquivo}"
        headers = {"x-apikey": api_key}
        resposta = requests.get(url, headers=headers)
        if resposta.status_code == 200:
            resultado = resposta.json()
        
            # Tratamento da resposta
            if 'data' in resultado and 'attributes' in resultado['data']:
                atributos = resultado['data']['attributes']
                if 'results' in atributos:
                    resultados = atributos['results']
                    self.text_result.insert(tk.END, "Resultados da Análise:\n")
                
                    # Verificar se algum antivírus detectou malware
                    malwares_detectados = []
                    for antivirus, resultado_antivirus in resultados.items():
                        if resultado_antivirus['category'] == 'malicious':
                            malwares_detectados.append(antivirus)
                
                    if malwares_detectados:
                        self.text_result.insert(tk.END, f"Malwares detectados por: {', '.join(malwares_detectados)}\n")
                    else:
                        self.text_result.insert(tk.END, "Nenhum malware detectado.\n")
                
                    # Verificar estatísticas de análise
                    if 'stats' in atributos:
                        estatisticas = atributos['stats']
                        self.text_result.insert(tk.END, f"Estatísticas de Análise:\n")
                        self.text_result.insert(tk.END, f"Maliciosos: {estatisticas['malicious']}\n")
                        self.text_result.insert(tk.END, f"Suspeitos: {estatisticas['suspicious']}\n")
                        self.text_result.insert(tk.END, f"Não detectados: {estatisticas['undetected']}\n")
                else:
                    self.text_result.insert(tk.END, "Nenhum resultado encontrado.\n")
            else:
                self.text_result.insert(tk.END, "Erro ao processar resposta.\n")
        else:
            self.text_result.insert(tk.END, "Erro ao buscar análise.\n")

    def analise_trafego(self):
        # Implementar análise de tráfego
        trafego = psutil.net_io_counters()
        resultado = f"Bytes recebidos: {trafego.bytes_recv}\n"
        resultado += f"Bytes enviados: {trafego.bytes_sent}\n"
        self.text_result.insert(tk.END, resultado)

    def verificacao_patch(self):
        # Implementar verificação de patch
        sistema_operacional = platform.system()
        versao = platform.release()
        resultado = f"Sistema operacional: {sistema_operacional}\n"
        resultado += f"Versão: {versao}\n"
        self.text_result.insert(tk.END, resultado)

    def descoberta_dispositivos(self):
        # Implementar descoberta de dispositivos
        nm = nmap.PortScanner()
        nm.scan('192.168.1.0/24', '1-1024')
        resultado = ""
        for host in nm.all_hosts():
            resultado += f"Host: {host} ({nm[host].hostname()})\n"
        self.text_result.insert(tk.END, resultado)

    def mapeamento_rede(self):
        # Implementar mapeamento de rede
        nm = nmap.PortScanner()
        nm.scan('192.168.1.0/24', '1-1024')
        hosts = nm.all_hosts()
        self.text_result.insert(tk.END, 'Mapeamento de Rede:\n')
        for host in hosts:
            self.text_result.insert(tk.END, f'Host: {host} ({nm[host].hostname()})\n')

    def analise_protocolos(self):
        pak = sniff(count=1)
        if pak[0].haslayer(IP):
            proto = pak[0][IP].proto
            protocolos = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP'}
            nome_proto = protocolos.get(proto, 'Desconhecido')
            self.text_result.insert(tk.END, f'Protocolo detectado: {nome_proto}')
        else:
            self.text_result.insert(tk.END, 'Protocolo desconhecido')

    def relatorio_detalhado(self):
        # Implementar relatório detalhado
        resultado = self.text_result.get('1.0', tk.END)
        with open('relatorio.txt', 'w') as arquivo:
            arquivo.write(resultado)

        # Gerar gráficos e estatísticas
        nm = nmap.PortScanner()
        nm.scan('192.168.1.0/24', '1-1024')
        hosts = nm.all_hosts()
        portas_abertas = []
        portas_fechadas = []

        for host in hosts:
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    if nm[host][proto][port]['state'] == 'open':
                        portas_abertas.append(port)
                    else:
                        portas_fechadas.append(port)

        plt.bar(['Portas Abertas', 'Portas Fechadas'], [len(portas_abertas), len(portas_fechadas)])
        plt.xlabel('Tipo de Porta')
        plt.ylabel('Quantidade')
        plt.title('Distribuição de Portas')
        plt.show()

        # Gráfico de pizza para mostrar a distribuição de vulnerabilidades
        vulnerabilidades = []
        for host in hosts:
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    if nm[host][proto][port]['state'] == 'open':
                        vulnerabilidades.append('Vulnerável')
                    else:
                        vulnerabilidades.append('Seguro')

        plt.pie([vulnerabilidades.count('Vulnerável'), vulnerabilidades.count('Seguro')], labels=['Vulneráveis', 'Seguros'], autopct='%1.1f%%')
        plt.title('Distribuição de Vulnerabilidades')
        plt.show()

    def run(self):
        self.janela.mainloop()

if __name__ == "__main__":
    scanner = ScannerGUI()
    scanner.run()
