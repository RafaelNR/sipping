#!/usr/bin/python
# -*- coding: utf-8 -*-
"""

SIP Ping - Um utilitário de diagnóstivo para monitoramento VOIP
Creado by Daniel Thompson
Alterações By Rafael Rodrigues


==========================================================================
Version 1.2
==========================================================================

Software License:
Do whatever you want with this code. There are no restrictions.

Not-license:
I'd like to hear back from you if you do something interesting with this.

==========================================================================

SIP Ping é uma ferramenta para monitorar um gateway SIP (PBX, SBC, telefone) para analises profundas. 
A maioria das ferramentas para monitoramento de VoIP é baseada no cumprimento de SLA
números e fornecendo estatísticas gerais de "disponibilidade de rede". SIP Ping
é para solução de problemas granular, sem SLA, somente enviado e recebendo pacotes.

Os sinalizadores e padrões da linha de comando estão disponíveis executando "python sipping.py -h"

"""

from hashlib import md5
import random
import re
import cgi
import cgitb
import sys
import os
import socket
import json
import urllib
import signal
from datetime import datetime
import time
import argparse

class colors: 
    reset='\033[0m'
    bold='\033[01m'
    disable='\033[02m'
    underline='\033[04m'
    reverse='\033[07m'
    strikethrough='\033[09m'
    invisible='\033[08m'
    class fg: 
        black='\033[30m'
        red='\033[31m'
        green='\033[32m'
        orange='\033[33m'
        blue='\033[34m'
        purple='\033[35m'
        cyan='\033[36m'
        lightgrey='\033[37m'
        darkgrey='\033[90m'
        lightred='\033[91m'
        lightgreen='\033[92m'
        yellow='\033[93m'
        lightblue='\033[94m'
        pink='\033[95m'
        lightcyan='\033[96m'
    class bg: 
        black='\033[40m'
        red='\033[41m'
        green='\033[42m'
        orange='\033[43m'
        blue='\033[44m'
        purple='\033[45m'
        cyan='\033[46m'
        lightgrey='\033[47m'

print(colors.reset)

# handler for ctrl+c / SIGINT
# last action before quitting is to write a \n to the end of the output file
def signal_handler(signal, frame):
	print('\nCtrl+C - Cancelando...')

	if v_logpath != "*":
		f_log = open(v_logpath, "a")
		f_log.write('\n')
		f_log.close()

	printstats()
	sys.exit('Sipping Finalizado!')

# Calcula a média
def calcAvg():
	        # min max avg
	v_total = 0
	for curr_ping in l_history:
		v_total = v_total + curr_ping

	if v_total > 0:
        	return v_total / len(l_history)
	else:
		return 0

# Trata os IPS
def handleIP(ip): 

	if ([0<=int(x)<256 for x in re.split('\.',re.match(r'^\d+\.\d+\.\d+\.\d+$',ip).group(0))].count(True)==4):
		return re.match("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)
	else:
		return None

def printstats():
	# loss stats
	print (colors.fg.green+"\t[Sucesso: {recd}]".format(recd=v_recd))
	print (colors.fg.red+"\t[Error: {lost}]".format(recd=v_recd,lost=v_lost))


	if v_longest_run > 0:
		print ("\t[Estatística de perda de pacotes]")
		print ("\t[Solicitação mais longa com perda: {0}]".format(str(v_longest_run)))
	if v_last_run_loss > 0:
		print ("\t[Última solicitação com perda: {0}]".format(str(v_last_run_loss)))
		print ("\t[Solicitações com perda: {0}]".format(str(v_current_run_loss)))

	v_avg = calcAvg()
	ping_min = v_min if v_min != float("inf") else 0
	ping_max = v_max if v_max != float("-inf") else 0

	print (colors.fg.blue+"\t[min/media/max | {min}/{avg}/{max}]".format(min=ping_min,max=ping_max,avg=v_avg))
	print (colors.reset+"-----------------------------------------------------------------------------------")


def handleArgs():
	# create and execute command line parser
	parser = argparse.ArgumentParser(description="Enviado mensagens SIP OPTIONS para um host e meça o tempo de resposta. Os resultados são registrados continuamente em CSV.")
	parser.add_argument("host", help="Equipamento SIP que vai fazer o ping.")
	parser.add_argument("-I", metavar="interval", default=1000, help="Intervalo de milissegundos entre os pinqs (padrão 1000)")
	parser.add_argument("-u", metavar="userid", default="sipping", help="UserID do herader da solicitação (padrão sipping)")
	parser.add_argument("-i", metavar="ip", default="*", help="IP no herader que enviará a solicitação (Tentara obter o IP Local)")
	parser.add_argument("-d", metavar="domain", default="seg.eti", help="Domain do herader (necessário se o host filtra domínio)")
	parser.add_argument("-p", metavar="port", default=5060, help="Porta de destino (padrão 5060)")
	parser.add_argument("--ttl", metavar="ttl", default=70, help="valor para ser usando no campo Max-Forwards field (padrão 70)")
	parser.add_argument("-w", metavar="file", default="[[default]]", help="Onde será salvo os arquivos. (padrão sipping-logs/[ip] - * para desabilitar.")
	parser.add_argument("-t", metavar="timeout", default="1000", help="Time (ms) to wait da resposta (padrão 1000)")
	parser.add_argument("-c", metavar="count", default="0", help="Número de pings enviados (padrão infinite)")
	parser.add_argument("-x", nargs="?", default=False, help="Exibir pacotes OPTIONS enviados")
	parser.add_argument("-X", nargs="?", default=False, help="Exibir pacotes OPTIONS recebidos")
	parser.add_argument("-q", nargs="?", default=True, help="Não existe msg de transmissão, somente estatística.")
	parser.add_argument("-S", nargs="?", default=True, help="Não exibe estatística a cada 5 pings, somente no Ctrl+C.")
	return vars(parser.parse_args())


def handleOptions():

	return """OPTIONS sip:{domain} SIP/2.0
Via: SIP/2.0/UDP {lanip}:{localport}
To: "SIP Ping"<sip:{userid}@{domain}>
From: "SIP Ping"<sip:{userid}@{domain}>
Call-ID: {callid}
CSeq: 1 OPTIONS
Max-forwards: {ttl}
X-redundancy: Request
Content-Length: 0

		""".format(domain=v_domain, lanip=v_lanip, userid=v_userid, localport=v_localport, callid=v_callid, ttl=v_ttl)

## MAIN
if __name__ == "__main__":
	
	args = handleArgs()
	# populate data from commandline
	# anything unspecified on the commandline is set to a default value by the parser
	v_interval = int(args["I"])
	v_fromip = args["i"]
	v_sbc = args["host"]


	# VERIFICA SE O IP DO HOST É VALIDO
	if handleIP(v_sbc) is None:
		# the user entered a hostname; resolve it
		try:
			v_sbc = socket.getaddrinfo(v_sbc, 5060)[0][4][0]
		# socket.gaierror catches socket-specific exceptions but I think we can go without
		#except socket.gaierror as error:
		except Exception as error:
			# dns failure or no response
			print(error)
			# print error.strerror
			sys.exit(1)

	v_userid = args["u"]
	v_port = int(args["p"])
	v_domain = args["d"]
	v_ttl = args["ttl"]
	v_timeout = int(args["t"])
	v_rawsend = args["x"] == None
	v_rawrecv = args["X"] == None
	v_quiet = not args["q"]
	v_nostats = not args["S"]

	if args["w"] == "[[default]]":
		if not os.path.exists("logs"): os.mkdir("logs")
			
		v_logpath = "logs/{ip}.csv".format(ip=v_sbc)
	else:
		v_logpath = args["w"]

	# if log output is enabled, ensure CSV has header
	if v_logpath != "*":
		if not os.path.isfile(v_logpath):
			# create new CSV file and write header
			f_log = open(v_logpath, "w")
			f_log.write("time,timestamp,host,latency,response")
			f_log.close()

	def generate_nonce(length=8):
		"""Generate pseudorandom number for call IDs."""
		return ''.join([str(random.randint(0, 9)) for i in range(length)])

	# writes onscreen timestamps in a consistent format

	def timef(timev=None):
				if timev == None:
								return datetime.now().strftime("%d/%m/%y %H:%M:%S")
				else:
								return datetime.fromtimestamp(timev)

	# register signal handler for ctrl+c since we're ready to start
	signal.signal(signal.SIGINT, signal_handler)
	if not v_quiet: print("Pressione Ctrl+C para sair.");

	# zero out statistics variables
	v_recd = 0
	v_lost = 0
	v_longest_run = 0
	v_last_run_loss = 0
	v_current_run_loss = 0
	last_lost = "never"
	l_history = []
	v_min = float("inf")
	v_max = float("-inf")
	v_iter = 0

	# empty list of last 5 pings
	l_current_results = []

	# start the ping loop
	while 1:
		# create a socket
		skt_sbc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		skt_sbc.bind(("0.0.0.0", 0))
		skt_sbc.settimeout(v_timeout / 1000.0)
		# find out what port we're transmitting from to correlate the return packet
		v_localport = skt_sbc.getsockname()[1]
		# find out what IP we're sourcing from to populate the Via
		if v_fromip != "*":
			v_lanip = v_fromip
		else:
			v_lanip = socket.gethostbyname(socket.gethostname()) 

		# latency is calculated from this timestamp
		start = time.time()

		# create a random callid so we can identify the message in a packet capture
		v_callid = generate_nonce(length=10)

		# Options para fazer a solicitaao e Call
		v_register_one = handleOptions()

		# print transmit announcement
		if not v_quiet: print (colors.fg.blue+"> "+ colors.reset +"[{time}] Enviado para [{host}:{port}]".format(host=v_sbc,port=v_port, time=timef()))

		# if -x was passed, print the transmitted packet
		if v_rawsend:
			print (v_register_one)	

		# send the packet
		skt_sbc.sendto(v_register_one, (v_sbc, v_port))

		start = time.time()
		# wait for response
		try:
			# start a synchronous receive
			data, addr = skt_sbc.recvfrom(1024) # buffer size is 1024 bytes

			# latency is calculated against this time		
			end = time.time()
			diff = float("%.2f" % ((end - start) * 1000.0))
			
			# pick out the first line in order to get the SIP response code
			v_response = data.split("\n")[0]
			
			# print success message and response code
			if not v_quiet: 
				print(colors.fg.green+"< "+ colors.reset +"[{time}] Recebido de {host} ({diff}ms): {response}".format(host=addr[0], diff=diff, time=timef(), response=v_response))

			# if -X was passed, print the received packet
			if v_rawrecv:
				print (data)

			# log success
			l_current_results.append("{time},{timestamp},{host},{diff},{id},{response}".format(host=addr[0], diff=diff, time=timef(), timestamp=time.time(), id=v_callid, response=v_response))

			# update statistics
			l_history.append(diff)
			if len(l_history) > 200:
				l_history = l_history[1:]
			if diff < v_min:
				v_min = diff
			if diff > v_max:
				v_max = diff;
			v_recd = v_recd + 1
			if v_current_run_loss > 0:
				v_last_run_loss = v_current_run_loss
				if v_last_run_loss > v_longest_run:
					v_longest_run = v_last_run_loss
				v_current_run_loss = 0
		except socket.timeout:

			# timed out; print a drop
			if not v_quiet: print (colors.fg.red+"X "+ colors.reset +"[{time}] Tempo limite para resposta do IP: [{host}:{port}]".format(host=v_sbc,port=v_port, time=timef()))
			# log a drop
			l_current_results.append("{time},{timestamp},{host},drop,{id},drop".format(host=v_sbc, time=timef(), timestamp=time.time(), id=v_callid))
			
			# increment statistics
			v_lost = v_lost + 1
			v_current_run_loss = v_current_run_loss + 1

		v_iter = v_iter + 1
		# if it's been five packets, print stats and write logfile
		if v_iter > 4:
			# print stats to screen
			if not v_nostats:
				printstats()
			
			# if logging is enabled, append stats to logfile
			if v_logpath != "*":
				f_log = open(v_logpath, "a")
				f_log.write("\n" + ("\n".join(l_current_results)))
				f_log.close()
			l_current_results = []

			v_iter = 0

		# pause for user-requested interval before sending next packet
		time.sleep(v_interval / 1000.0)
