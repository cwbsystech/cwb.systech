#!/usr/bin/env bash

# Autor:						Jensy Gregorio Gomez
# YouTube:						youtube.com/systech
# Instagram:					https://www.instagram.com/systech5/?hl=pt-br
# Github:						https://github.com/vaasystech-brz
# Data de criação:				01/01/2022
# Data de atualização:			01/01/2022
# Versão:						0.01
# Testado e homologado para a versão do Ubuntu Server 20.04.x LTS x64
# Testado e homologado para a versão do OpenSSH Server v8.2.x
#
# OpenSSH 
#			(Open Secure Shell) é um conjunto de utilitários de rede relacionado à
#			segurança que provém a criptografia em sessões de comunicações em uma 
#			rede de computadores usando o protocolo SSH. Foi criado com um código 
#			aberto alternativo ao código proprietário da suíte de softwares Secure 
#			Shell, oferecido pela SSH Communications Security. OpenSSH foi desenvolvido 
#			como parte do projeto OpenBSD.
#
# O TCP Wrapper 
#			É um sistema de rede ACL baseado em host, usado para filtrar acesso à 
#			rede a servidores de protocolo de Internet (IP) em sistemas operacionais 
#			do tipo Unix, como Linux ou BSD. Ele permite que o host, endereços IP de 
#			sub-rede, nomes e/ou respostas de consulta ident, sejam usados como tokens 
#			sobre os quais realizam-se filtros para propósitos de controle de acesso.

#
#
# Verificando os usuários logados na sessão do OpenSSH Server no Ubuntu Server
# Terminal:
#	sudo who -a (show who is logged on)
#	sudo w (Show who is logged on and what they are doing)
#	sudo users (print the user names of users currently logged in to the current host)
#	sudo last -a | grep 'still logged in' (show a listing of last logged in users)
#	sudo ss | grep -i ssh (another utility to investigate sockets)
#	sudo netstat -tnpa | grep 'ESTABLISHED.*sshd' (show networking connection)
#	sudo ps -axfj | grep sshd (report a snapshot of the current processes)
#
# Arquivo de configuração dos parâmetros utilizados nesse script
source 001-parametros.sh

pacote=$(dpkg --get-selections | grep "figlet" )
	if [ -n "$pacote" ] ;then
		echo
	else
		apt-get install figlet -qq > /dev/null
	fi


#
# Configuração da variável de Log utilizado nesse script
_LOG=$_LogScript
#
# Verificando se o usuário é Root e se a Distribuição é >= 20.04.x 
#		[ ]		=	teste de expressão 
#		&&		=	operador lógico 
#		AND		=	comparação de string
#		exit 1	=	A maioria dos erros comuns na execução

_Logo_Empresa
if [ "$_Usuario" == "0" ] && [ "$_VersaoUbuntu" == "20.04" ]
	then
		_Logo_Empresa
		echo -e "O usuário é Root, continuando com o script..."
		echo -e "Distribuição é >= 20.04.x, continuando com o script..."
		sleep 5
	else
		_Logo_Empresa
		echo -e "Usuário não é Root ($_Usuario) ou a Distribuição não é >= 20.04.x ($_VersaoUbuntu)"
		echo -e "Caso você não tenha executado o script com o comando: sudo -i"
		echo -e "Execute novamente o script para verificar o ambiente."
		exit 1
fi
#
# Verificando o acesso a Internet do servidor Ubuntu Server

if [ "$(nc -zw1 google.com 443 &> /dev/null ; echo $?)" == "0" ]
	then
		_Logo_Empresa
		echo -e "Você tem acesso a Internet, continuando com o script..."
		sleep 5
	else
		_Logo_Empresa
		echo -e "Você NÃO tem acesso a Internet, verifique suas configurações de rede IPV4"
		echo -e "e execute novamente este script."
		sleep 5
		exit 1
fi

# Verificando se a porta 22 está sendo utilizada no servidor Ubuntu Server

$_PortSsh
_Logo_Empresa
if [ "$(nc -vz 127.0.0.1 $_PortSsh &> /dev/null ; echo $?)" == "0" ]
	then
		_Logo_Empresa
		echo -e "A porta: $_PortSsh está sendo utilizada pelo serviço do OpenSSH Server, continuando com o script..."
		sleep 5
	else
		_Logo_Empresa
		echo -e "A porta: $_PortSsh não está sendo utilizada nesse servidor."
		echo -e "Verifique as dependências desse serviço e execute novamente esse script.\n"
		sleep 5
		exit 1
fi
#
# Verificando se a porta 4200 está sendo utilizada no servidor Ubuntu Server
_Logo_Empresa
if [ "$(nc -vz 127.0.0.1 $_PortShellInbox &> /dev/null ; echo $?)" == "0" ]
	then
		_Logo_Empresa
		echo -e "A porta: $_PortShellInbox já está sendo utilizada nesse servidor."
		echo -e "Verifique o serviço associado a essa porta e execute novamente esse script.\n"
		sleep 5
		exit 1
	else
		_Logo_Empresa
		echo -e "A porta: $_PortShellInbox está disponível, continuando com o script..."
		sleep 5
fi
#
# Verificando todas as dependências do OpenSSH Server

_Logo_Empresa
echo -n "Verificando as dependências do OpenSSH Server, aguarde... "

	for name in $_SshDepen
	do
  		[[ $(dpkg -s $name 2> /dev/null) ]] || { 
              echo -en "\n\nO software: $name precisa ser instalado. \nUse o comando 'apt install $name'\n";
              deps=1; 
              }
	done
		[[ $deps -ne 1 ]] && echo "Dependências.: OK" || { 
            echo -en "\nInstale as dependências acima e execute novamente este script\n";
            exit 1; 
            }
		sleep 5
#
# Verificando se o script já foi executado mais de 1 (uma) vez nesse servidor
# OBSERVAÇÃO IMPORTANTE: OS SCRIPTS FORAM PROJETADOS PARA SEREM EXECUTADOS APENAS 1 (UMA) VEZ
_Logo_Empresa
if [ -f $_LOG ]
	then
		_Logo_Empresa
		echo -e "Script $0 já foi executado 1 (uma) vez nesse servidor..."
		echo -e "É recomendado analisar o arquivo de $_LOG para informações de falhas ou erros"
		echo -e "na instalação e configuração do serviço de rede utilizando esse script..."
		echo -e "Todos os scripts foram projetados para serem executados apenas 1 (uma) vez."
		sleep 5
		exit 1
	else
		_Logo_Empresa
		echo -e "Primeira vez que você está executando esse script, tudo OK, agora só aguardar..."
		sleep 5
fi
#
# Script de configuração do OpenSSH Server no GNU/Linux Ubuntu Server 20.04.x LTS

_Logo_Empresa
echo -e "Início do script $0 em: $(date +%d/%m/%Y-"("%H:%M")")\n" &>> $_LOG
clear
echo
#
_Logo_Empresa
echo -e "Configuração do OpenSSH Server no GNU/Linux Ubuntu Server 20.04.x\n"
echo -e "Porta padrão utilizada pelo OpenSSH Server.: TCP $_PortSsh" 
echo -e "Porta padrão utilizada pelo Shell-In-a-Box.: TCP $_PortShellInbox" 
echo -e "Após a instalação do Shell-In-a-Box acessar a URL: https://$(hostname -I | cut -d' ' -f1):$_PortShellInbox/\n"
echo -e "Aguarde, esse processo demora um pouco dependendo do seu Link de Internet...\n"
sleep 5
#
_Logo_Empresa
echo -e "Adicionando o Repositório Universal do Apt, aguarde..."
	# Universe - Software de código aberto mantido pela comunidade:
	# opção do comando: &>> (redirecionar a saída padrão)
	add-apt-repository universe &>> $_LOG
echo -e "Repositório adicionado com sucesso!!!, continuando com o script...\n"
sleep 5
#
_Logo_Empresa
echo -e "Adicionando o Repositório Multiversão do Apt, aguarde..."
	# Multiverse – Software não suportado, de código fechado e com patente: 
	# opção do comando: &>> (redirecionar a saída padrão)
	add-apt-repository multiverse &>> $_LOG
echo -e "Repositório adicionado com sucesso!!!, continuando com o script...\n"
sleep 5
#
_Logo_Empresa
echo -e "Adicionando o Repositório Restrito do Apt, aguarde..."
	# Restricted - Software de código fechado oficialmente suportado:
	# opção do comando: &>> (redirecionar a saída padrão)
	add-apt-repository restricted &>> $_LOG
echo -e "Repositório adicionado com sucesso!!!, continuando com o script...\n"
sleep 5
#
_Logo_Empresa
echo -e "Atualizando as listas do Apt, aguarde..."
	#opção do comando: &>> (redirecionar a saída padrão)
	apt update &>> $_LOG
echo -e "Listas atualizadas com sucesso!!!, continuando com o script...\n"
sleep 5
#
_Logo_Empresa
echo -e "Atualizando todo o sistema operacional, aguarde..."
	# opção do comando: &>> (redirecionar a saída padrão)
	# opção do comando apt: -y (yes)
	apt -y upgrade &>> $_LOG
	apt -y dist-upgrade &>> $_LOG
	apt -y full-upgrade &>> $_LOG
_Logo_Empresa
echo -e "Sistema atualizado com sucesso!!!, continuando com o script...\n"
sleep 5
#
_Logo_Empresa
echo -e "Removendo todos os software desnecessários, aguarde..."
	# opção do comando: &>> (redirecionar a saída padrão)
	# opção do comando apt: -y (yes)
	apt -y autoremove &>> $_LOG
	apt -y autoclean &>> $_LOG
echo -e "Software removidos com sucesso!!!, continuando com o script...\n"
sleep 5
#
_Logo_Empresa
echo -e "Iniciando a Configuração do OpenSSH Server, aguarde...\n"
sleep 5
#
_Logo_Empresa
echo -e "Instalando as ferramentas básicas de rede do OpenSSH Server, aguarde..."
	# opção do comando: &>> (redirecionar a saída padrão)
	# opção do comando apt: -y (yes)
	apt -y install $_SshInstall &>> $_LOG 
_Logo_Empresa
echo -e "Ferramentas instaladas com sucesso!!!, continuando com o script...\n"
sleep 5
#
_Logo_Empresa
echo -e "Atualizando os arquivos de configuração do OpenSSH Server, aguarde..."
	# opção do comando: &>> (redirecionar a saída padrão)
	# opção do comando mv: -v (verbose)
	# opção do comando mkdir: -v (verbose)
	# opção do comando cp: -v (verbose)
	# opção do bloco e agrupamentos {}: (Agrupa comandos em um bloco)
	
	# Chamando as Funções que estão configuradas no Arquivo 001-Arquivos.sh
	
	_Logo_Empresa
	echo "Função do HOSTNAME"
	_Arquivo_Hostname &>> $_LOG
	sleep 4

	_Logo_Empresa
	echo "Função do HOSTS"
	_Arquivo_Hosts &>> $_LOG
	sleep 4

	_Logo_Empresa
	echo "Função do HOSTS.ALOW"
	_Arquivo_Hosts_Allow &>> $_LOG
	sleep 4

	_Logo_Empresa
	echo "Função do HOSTS.DENY"
	_Arquivo_Hosts_Deny &>> $_LOG
	sleep 4

	_Logo_Empresa
	echo "Função do NSSWITCH"
	_Arquivo_Nsswitch_Conf &>> $_LOG
	sleep 4

	_Logo_Empresa
	echo "Função do SSHD"
	_Arquivo_Sshd_Config &>> $_LOG
	sleep 4

	_Logo_Empresa
	echo "Função do SHELLINABOX"
	_Arquivo_Shellinabox &>> $_LOG
	sleep 4
	
	



	mv -v /etc/ssh/sshd_config /etc/ssh/sshd_config.old &>> $LOG
	mv -v /etc/default/shellinabox /etc/default/shellinabox.old &>> $LOG
	mv -v /etc/rsyslog.d/50-default.conf /etc/rsyslog.d/50-default.conf.old &>> $LOG

	mkdir -v /etc/neofetch/ &>> $LOG
	cp -v conf/ubuntu/config.conf /etc/neofetch/ &>> $LOG
	cp -v conf/ubuntu/neofetch-cron /etc/cron.d/ &>> $LOG
	
	cp -v conf/ubuntu/50-default.conf /etc/rsyslog.d/ &>> $LOG

	cp -v conf/ubuntu/{hostname,hosts,hosts.allow,hosts.deny,issue.net,nsswitch.conf} /etc/ &>> $LOG
	cp -v conf/ubuntu/vimrc /etc/vim/ &>> $LOG
	cp -v conf/ssh/sshd_config /etc/ssh/ &>> $LOG
	cp -v conf/ssh/shellinabox /etc/default/ &>> $LOG
	cp -v $_Netplan $_Netplan.old &>> $LOG
	cp -v conf/ubuntu/00-installer-config.yaml $_Netplan &>> $LOG
	
	_Logo_Empresa
	netplan --debug try
	sleep 2

	_Logo_Empresa
	netplan --debug apply
	sleep 2

	_Logo_Empresa
	systemd-resolve --status
	sleep 2

	_Logo_Empresa
	ip address show $_Interface_Lan 
	sleep 2

	_Logo_Empresa
	ip route
	sleep 2
	
_Logo_Empresa
echo -e "Arquivos atualizados com sucesso!!!, continuando com o script...\n"
sleep 5
#
_Logo_Empresa
echo -e "Editando o arquivo $_Netplan, pressione <Enter> para continuar.\n"
echo -e "CUIDADO!!!: o nome do arquivo de configuração da placa de rede pode mudar"
echo -e "dependendo da versão do Ubuntu Server, verifique o conteúdo do diretório:"
echo -e "/etc/netplan para saber o nome do arquivo de configuração do Netplan e altere"
echo -e "o valor da variável NETPLAN no arquivo de configuração: 00-parametros.sh"
	# opção do comando read: -s (Do not echo keystrokes)
	read -s
	vim $_Netplan
_Logo_Empresa
echo -e "Arquivo editado com sucesso!!!, continuando com o script...\n"
sleep 5
#
_Logo_Empresa
echo -e "Editando o arquivo de configuração hostname, pressione <Enter> para continuar."
	# opção do comando read: -s (Do not echo keystrokes)
	read -s
	vim /etc/hostname
_Logo_Empresa
echo -e "Arquivo editado com sucesso!!!, continuando com o script...\n"
sleep 5
#
_Logo_Empresa
echo -e "Editando o arquivo de configuração hosts, pressione <Enter> para continuar."
	# opção do comando read: -s (Do not echo keystrokes)
	read -s
	vim /etc/hosts
_Logo_Empresa
echo -e "Arquivo editado com sucesso!!!, continuando com o script...\n"
sleep 5
#
_Logo_Empresa
echo -e "Editando o arquivo de configuração nsswitch.conf, pressione <Enter> para continuar."
	# opção do comando read: -s (Do not echo keystrokes)
	read -s
	vim /etc/nsswitch.conf
_Logo_Empresa
echo -e "Arquivo editado com sucesso!!!, continuando com o script...\n"
sleep 5
#
_Logo_Empresa
echo -e "Editando o arquivo de configuração sshd_config, pressione <Enter> para continuar."
	# opção do comando: &>> (redirecionar a saída padrão)
	# opção do comando read: -s (Do not echo keystrokes)
	# opção do comando sshd: -t (text mode check configuration)
	read -s
	vim /etc/ssh/sshd_config
	sshd -t &>> $_LOG
_Logo_Empresa
echo -e "Arquivo editado com sucesso!!!, continuando com o script...\n"
sleep 5
#
_Logo_Empresa
echo -e "Editando o arquivo de configuração hosts.allow, pressione <Enter> para continuar."
	# opção do comando read: -s (Do not echo keystrokes)
	read -s
	vim /etc/hosts.allow
_Logo_Empresa
echo -e "Arquivo editado com sucesso!!!, continuando com o script...\n"
sleep 5
#
_Logo_Empresa
echo -e "Editando o arquivo de configuração hosts.deny, pressione <Enter> para continuar."
	# opção do comando read: -s (Do not echo keystrokes)
	read -s
	vim /etc/hosts.deny
_Logo_Empresa
echo -e "Arquivo editado com sucesso!!!, continuando com o script...\n"
sleep 5
#
_Logo_Empresa
echo -e "Editando o arquivo de configuração issue.net, pressione <Enter> para continuar."
	# opção do comando read: -s (Do not echo keystrokes)
	read -s
	vim /etc/issue.net


_Logo_Empresa
echo -e "Arquivo editado com sucesso!!!, continuando com o script...\n"
sleep 5


_Logo_Empresa
echo -e "Editando o arquivo de configuração shellinabox, pressione <Enter> para continuar."
	# opção do comando read: -s (Do not echo keystrokes)
	read -s
	vim /etc/default/shellinabox

_Logo_Empresa
echo -e "Arquivo editado com sucesso!!!, continuando com o script...\n"
sleep 5
#

_Logo_Empresa
echo -e "Editando o arquivo de configuração config.conf, pressione <Enter> para continuar."
	# opção do comando read: -s (Do not echo keystrokes)
	read -s
	vim /etc/neofetch/config.conf

_Logo_Empresa
echo -e "Arquivo editado com sucesso!!!, continuando com o script...\n"
sleep 5
#

_Logo_Empresa
echo -e "Editando o arquivo de configuração neofetch-cron, pressione <Enter> para continuar."
	# opção do comando read: -s (Do not echo keystrokes)
	read -s
	vim /etc/cron.d/neofetch-cron

_Logo_Empresa
echo -e "Arquivo editado com sucesso!!!, continuando com o script...\n"
sleep 5
#

_Logo_Empresa
echo -e "Editando o arquivo de configuração 50-default.conf, pressione <Enter> para continuar."
	# opção do comando read: -s (Do not echo keystrokes)
	read -s
	vim /etc/rsyslog.d/50-default.conf

_Logo_Empresa
echo -e "Arquivo editado com sucesso!!!, continuando com o script...\n"
sleep 5
#

_Logo_Empresa
echo -e "Criando o arquivo personalizado de Banner em: /etc/motd, aguarde..."
	# opção do comando: &>> (redirecionar a saída padrão)
	# opção do comando chmod: -v (verbose), -x (remove executable)
	neofetch --config /etc/neofetch/config.conf > /etc/motd
	chmod -v -x /etc/update-motd.d/* &>> $_LOG
_Logo_Empresa
echo -e "Arquivo criado com sucesso!!!, continuando com o script...\n"
sleep 5
#

_Logo_Empresa
echo -e "Aplicando as mudanças da Placa de Rede do Netplan, aguarde..."
	# opção do comando: &>> (redirecionar a saída padrão)
	netplan --debug apply &>> $_LOG

_Logo_Empresa
echo -e "Mudanças aplicadas com sucesso!!!, continuando com o script...\n"
sleep 5
#

_Logo_Empresa
echo -e "Reinicializando os serviços do OpenSSH Server e do Shell-In-a-Box, aguarde..."
	# opção do comando: &>> (redirecionar a saída padrão)
	systemctl restart sshd &>> $_LOG
	systemctl restart shellinabox &>> $_LOG

_Logo_Empresa
echo -e "Serviços reinicializados com sucesso!!!, continuando com o script...\n"
sleep 5
#

_Logo_Empresa
echo -e "Verificando os serviços do OpenSSH Server e do Shell-In-a-Box, aguarde..."
	echo -e "OpenSSH....: $(systemctl status sshd | grep Active)"
	echo -e "Shellinabox: $(systemctl status shellinabox | grep Active)"

_Logo_Empresa
echo -e "Serviços verificados com sucesso!!!, continuando com o script...\n"
sleep 5
#

_Logo_Empresa
echo -e "Verificando as portas de conexões do OpenSSH Server e do Shell-In-a-Box, aguarde..."
	# opção do comando lsof: -n (inhibits the conversion of network numbers to host names for 
	# network files), -P (inhibits the conversion of port numbers to port names for network files), 
	# -i (selects the listing of files any of whose Internet address matches the address specified 
	# in i), -s (alone directs lsof to display file size at all times)
	lsof -nP -iTCP:'22,4200' -sTCP:LISTEN
_Logo_Empresa
echo -e "Portas verificadas com sucesso!!!, continuando com o script...\n"
sleep 5
#

_Logo_Empresa
echo -e "Configuração do OpenSSH Server feita com Sucesso!!!."
	# script para calcular o tempo gasto (SCRIPT MELHORADO, CORRIGIDO FALHA DE HORA:MINUTO:SEGUNDOS)
	# opção do comando date: +%T (Time)
	HORAFINAL=$(date +%T)
	# opção do comando date: -u (utc), -d (date), +%s (second since 1970)
	HORAINICIAL01=$(date -u -d "$HORAINICIAL" +"%s")
	HORAFINAL01=$(date -u -d "$HORAFINAL" +"%s")
	# opção do comando date: -u (utc), -d (date), 0 (string command), sec (force second), +%H (hour), %M (minute), %S (second), 
	TEMPO=$(date -u -d "0 $HORAFINAL01 sec - $HORAINICIAL01 sec" +"%H:%M:%S")
	# $0 (variável de ambiente do nome do comando)

_Logo_Empresa
	echo -e "Tempo gasto para execução do script $0: $TEMPO"
echo -e "Pressione <Enter> para concluir o processo."
# opção do comando date: + (format), %d (day), %m (month), %Y (year 1970), %H (hour 24), %M (minute 60)
echo -e "Fim do script $0 em: $(date +%d/%m/%Y-"("%H:%M")")\n" &>> $_LOG
read
exit 1
