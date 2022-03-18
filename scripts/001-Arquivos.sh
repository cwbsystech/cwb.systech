#!/usr/bin/env bash
source 002-parametros.sh


_Logo_Empresa () {
	clear
	echo -e " \e[1;31m ======================================================================== \e[m ";
	figlet -c "$_Empresa"
	echo -e " \e[1;31m ======================================================================== \e[m ";
	echo ""
	echo ""
	return
}

_Arquivo_Shellinabox () {

	# Gerado pelo script: 			cwb.systech.com.br -- Soluçoes em TI
	# Autor:						Jensy Gregorio Gomez
	# Bio:							Têcnico em Informatica e Eletronica
	# WhatsApp:						(41) 99896-2670    /    99799-3164
	# Date:							01/01/2022
	# Versão:						0.01
	#

	# Testado e homologado para a versão do Ubuntu Server 20.04.x LTS x64
	# Testado e homologado para a versão do OpenSSH Server v8.2.x
	# Testado e homologado para a versão do Shell-In-a-Box v2.x
	#
	# Configuração do inicialização automática do Shell-In-a-Box como serviço
	SHELLINABOX_DAEMON_START=1
	#
	# Porta padrão utilizada pelo Webservice do Shell-In-a-Box
	SHELLINABOX_PORT=$_PortShellInbox
	#
	# Configuração do Usuário e Grupo padrão do serviço do Shell-In-a-Box
	SHELLINABOX_USER=shellinabox
	SHELLINABOX_GROUP=shellinabox
	#
	# Localização padrão do diretório de informações de acesso do Shell-In-a-Box
	SHELLINABOX_DATADIR=/var/lib/shellinabox
	#
	# Configurações dos argumentos utilizados pelo Shell-In-a-Box
	# --no-beep: bipes são desativados devido a relatos de falha do plug-in VLC no Firefox
	# --service=/:SSH: configuração do endereço IPv4 do servidor de OpenSSH Server
	# Mais opções de argumentos veja a documentação oficial do Shell-In-a-Box no Link:
	# https://manpages.debian.org/unstable/shellinabox/shellinaboxd.1.en.html
	SHELLINABOX_ARGS="--no-beep --service=/:SSH:$_Ip_V4_Servidor"

}

_Arquivo_Installer_Conf_Yaml () {
	cat <<EOF > conf/ubuntu/00-installer-config.yaml
	
	# Gerado pelo script: 			cwb.systech.com.br -- Soluçoes em TI
	# Autor:						Jensy Gregorio Gomez
	# Bio:							Têcnico em Informatica e Eletronica
	# WhatsApp:						(41) 99896-2670    /    99799-3164
	# Date:							01/01/2022
	# Versão:						0.01
	#

	# Testado e homologado para a versão do Ubuntu Server 20.04.x LTS x64

	# Mais informações veja o arquivo: scripts/settings/04-ConfiguracaoDoNetplan.sh
	# Após as configuração do endereço IPv4 digitar o comando: netplan --debug apply
	#
	# Configuração do Endereço IPv4 do Ubuntu Server
network:
  #
  # Configuração do Protocolo Ethernet do Ubuntu Server
  ethernets:
    #
    # Configuração do Nome da Placa de Rede do Ubuntu Server
    $_Interface_Lan:
      #
      # Configuração do Endereço IPv4 Dinâmico via DHCP do Ubuntu Server
      # OBSERVAÇÃO: por padrão o endereço IPv4 dinâmico em servidores não é utilizado
      #dhcp4: true
      #
      # Configuração do Endereço IPv4 e CIDR Estático do Ubuntu Server
      addresses:
      - $_Ip_V4_Servidor/$_Mascara
      #
      # Configuração do Endereço de Gateway IPv4 do Ubuntu Server
      gateway4: $_Gateway
      #
      # Configuração dos Endereços de DNS Server IPv4 do Ubuntu Server
      nameservers:
        addresses:
        #- 172.16.1.20
        - $_Gateway
        #- 8.8.8.8
        #- 8.8.8.8
        #
        # Configuração do Nome de Pesquisa DNS do Ubuntu Server
        search:
        - $_Nome_Dominio_FQDN
        #
  # Configuração da versão do Protocolo Ethernet do Ubuntu Server
  version: 2
EOF
}


_Arquivo_Hostname () {
	cat <<EOF > conf/ubuntu/hostname

	# Gerado pelo script: 			cwb.systech.com.br -- Soluçoes em TI
	# Autor:						Jensy Gregorio Gomez
	# Bio:							Têcnico em Informatica e Eletronica
	# WhatsApp:						(41) 99896-2670    /    99799-3164
	# Date:							01/01/2022
	# Versão:						0.01
	#

	$_Nome_Servidor.$_Nome_Dominio_FQDN
EOF
}


_Arquivo_Hosts () {
	cat << EOF > conf/ubuntu/hosts

	# Gerado pelo script: 			cwb.systech.com.br -- Soluçoes em TI
	# Autor:						Jensy Gregorio Gomez
	# Bio:							Têcnico em Informatica e Eletronica
	# WhatsApp:						(41) 99896-2670    /    99799-3164
	# Date:							01/01/2022
	# Versão:						0.01
	#


	# Configuração do Banco de Dados de DNS Estático IPv4 do Servidor Local
	# IPv4		FQDN                    CNAME	
	127.0.0.1 	localhost.localdomain	localhost
	127.0.1.1 	$_Nome_Servidor.$_Nome_Dominio_FQDN $_Nome_Servidor
	$_Ip_V4_Servidor	$_Nome_Servidor.$_Nome_Dominio_FQDN	$_Nome_Servidor


	# Configuração do Banco de Dados de DNS Estático IPv6 do Servidor Local

	# IPV6	    FQDN                    CNAME
	::1 	    ip6-localhost           ip6-loopback
	fe00::0     ip6-localnet
	ff00::0     ip6-mcastprefix
	ff02::1     ip6-allnodes
	ff02::2     ip6-allrouters
EOF
}

_Arquivo_Hosts_Allow () {
	cat << EOF > conf/ubuntu/hosts.allow
	
	# Gerado pelo script: 			cwb.systech.com.br -- Soluçoes em TI
	# Autor:						Jensy Gregorio Gomez
	# Bio:							Têcnico em Informatica e Eletronica
	# WhatsApp:						(41) 99896-2670    /    99799-3164
	# Date:							01/01/2022
	# Versão:						0.01
	#


	# Comando utilizado para verificar se o serviço (daemon) de rede tem suporte ao 
	# TCPWrappers: ldd /usr/sbin/sshd | grep libwrap (Biblioteca LibWrap)
	# Logando todas as informações de acesso nos arquivos de Log's de cada serviço
	# em: /var/log/tcpwrappers-allow-*.log (* nome do serviço)
	#
	# Permitindo a Rede $_Network/$_Mascara se autenticar remotamente no Servidor de OpenSSH
	# DAEMON   CLIENT     OPTION
	sshd: $_Network/$_Mascara: spawn /bin/echo "$(date) - SSH - IP %a" >> /var/log/tcpwrappers-allow-ssh.log
	#
	# Permitindo a Rede $_Network/$_Mascara se autenticar remotamente no Servidor de MySQL
	# DAEMON   CLIENT     OPTION
	mysqld: $_Network/$_Mascara: spawn /bin/echo "$(date) - MySQL - IP %a" >> /var/log/tcpwrappers-allow-mysql.log
	#
	# Permitindo a Rede $_Network/$_Mascara se autenticar remotamente no Servidor de Telnet
	# DAEMON   CLIENT     OPTION
	in.telnetd: $_Network/$_Mascara: spawn /bin/echo "$(date) - Telnet - IP %a" >> /var/log/tcpwrappers-allow-telnet.log
	#
	# Permitindo a Rede $_Network/$_Mascara se autenticar remotamente no Servidor de FTP
	# DAEMON   CLIENT     OPTION
	vsftpd: $_Network/$_Mascara: spawn /bin/echo "$(date) - Vsftpd - IP %a" >> /var/log/tcpwrappers-allow-vsftpd.log
	#
	# Permitindo a Rede $_Network/$_Mascara se conectar remotamente no Servidor de TFTP
	# DAEMON   CLIENT     OPTION
	in.tftpd: $_Network/$_Mascara: spawn /bin/echo "$(date) - Tftpd - IP %a" >> /var/log/tcpwrappers-allow-tftpd.log
	#
	# Permitindo a Rede $_Network/$_Mascara se autenticar remotamente no Servidor de NFS
	# DAEMON		CLIENT			OPTION
	portmap: $_Network/$_Mascara: spawn /bin/echo "$(date) - Portmap - IP %a" >> /var/log/tcpwrappers-allow-nfs.log
	lockd: $_Network/$_Mascara: spawn /bin/echo "$(date) - Lockd - IP %a" >> /var/log/tcpwrappers-allow-nfs.log
	rquotad: $_Network/$_Mascara: spawn /bin/echo "$(date) - Rquotad - IP %a" >> /var/log/tcpwrappers-allow-nfs.log
	mountd: $_Network/$_Mascara: spawn /bin/echo "$(date) - Mountd - IP %a" >> /var/log/tcpwrappers-allow-nfs.log
	statd: $_Network/$_Mascara: spawn /bin/echo "$(date) - Statd - IP %a" >> /var/log/tcpwrappers-allow-nfs.log
	#
	# Permitindo que todas as redes acesse os serviços remotos do Servidor Bacula
	# DAEMON   CLIENT     OPTION
	bacula-fd: ALL: spawn /bin/echo "$(date) - Bacula-FD - IP %a" >> /var/log/tcpwrappers-allow-bacula.log
	bacula-sd: ALL: spawn /bin/echo "$(date) - Bacula-SD - IP %a" >> /var/log/tcpwrappers-allow-bacula.log
	bacula-dir: ALL: spawn /bin/echo "$(date) - Bacula-DIR - IP %a" >> /var/log/tcpwrappers-allow-bacula.log
	$_Nome_Servidor.$_Nome_Dominio_FQDN-fd: ALL: spawn /bin/echo "$(date) - Bacula-FD - IP %a" >> /var/log/tcpwrappers-allow-bacula.log
	$_Nome_Servidor.$_Nome_Dominio_FQDN-mon: ALL: spawn /bin/echo "$(date) - Bacula-MON - IP %a" >> /var/log/tcpwrappers-allow-bacula.log
	$_Nome_Servidor.$_Nome_Dominio_FQDN-dir: ALL: spawn /bin/echo "$(date) - Bacula-DIR - IP %a" >> /var/log/tcpwrappers-allow-bacula.log
	#
	# Exemplos de configuração do TCPWrappers do arquivo hosts.allow:
	# Permitindo uma Subrede ou nome de domínio FQDN
	# DAEMON   CLIENT     OPTION
	#sshd: 192.168.1. : spawn /bin/echo "$(date) Conexão Liberada - SSH - IP %a" >> /var/log/tcpwrappers-allow-ssh.log
	#sshd: 192.168.1.0/255.255.255.0: spawn /bin/echo "$(date) Conexão Liberada - SSH - IP %a" >> /var/log/tcpwrappers-allow-ssh.log
	#sshd: 192.168.1.0/$_Mascara: spawn /bin/echo "$(date) Conexão Liberada - SSH - IP %a" >> /var/log/tcpwrappers-allow-ssh.log
	#sshd: *.$_Nome_Dominio_FQDN: spawn /bin/echo "$(date) Conexão Liberada - SSH - IP %a" >> /var/log/tcpwrappers-allow-ssh.log
	#sshd: 192.168.1. EXCEPT 192.168.1.11: spawn /bin/echo "$(date) Conexão Liberada - SSH - IP %a" >> /var/log/tcpwrappers-allow-ssh.log

EOF
}


_Arquivo_Hosts_Deny () {
	cat << EOF > conf/ubuntu/hosts.deny
	
	# Gerado pelo script: 			cwb.systech.com.br -- Soluçoes em TI
	# Autor:						Jensy Gregorio Gomez
	# Bio:							Têcnico em Informatica e Eletronica
	# WhatsApp:						(41) 99896-2670    /    99799-3164
	# Date:							01/01/2022
	# Versão:						0.01
	#

	# Comando utilizado para verificar se o serviço (daemon) de rede tem suporte 
	# ao TCPWrappers: ldd /usr/sbin/sshd | grep libwrap (Biblioteca LibWrap)
	# Negando todas as redes acessarem os serviços remotamente do Ubuntu Server, 
	# somente os serviços e redes configuradas no arquivo host.allow estão liberados 
	# para acessar o servidor.
	# Logando todas as informações de acesso negado de todos os serviços no arquivos 
	# de Log em: /var/log/tcpwrappers-deny-.log
	#
	# Negando todas as Redes de acessar remotamente os serviços no Servidor Ubuntu
	# DAEMON		CLIENT		OPTION
	ALL: ALL: spawn /bin/echo "$(date) Conexão Recusada - IP %a" >> /var/log/tcpwrappers-deny.log
	#
	# Exemplos de configuração do TCPWrappers do arquivo hosts.deny:
	# Negando uma subrede ou nome de domínio FQDN para um serviço
	#sshd: 192.168.1. : spawn /bin/echo "$(date) Conexão Recusada - SSH - IP %a" >> /var/log/tcpwrappers-deny.log
	#sshd: 192.168.1.0/255.255.255.0: spawn /bin/echo "$(date) Conexão Recusada - SSH - IP %a" >> /var/log/tcpwrappers-deny.logg
	#sshd: *.systech.brz: spawn /bin/echo "$(date) Conexão Recusada - SSH - IP %a" >> /var/log/tcpwrappers-deny.log
	#sshd: 192.168.1. EXCEPT 192.168.1.11: spawn /bin/echo "$(date) Conexão Recusada - SSH - IP %a" >> /var/log/tcpwrappers-deny.log
EOF
}


_Arquivo_Issue_Net () {
	cat << EOF > conf/ubuntu/issue.net
	
	
	**************************************************************************
	##########################################################################
	##          Acesso ao Servidor Remoto utilizando o OpenSSH              ##
	##########################################################################
	**************************************************************************
    	 _____               _   _    _____   ______   _____    _   _   _ 
    	|  __ \      /\     | \ | |  / ____| |  ____| |  __ \  | | | | | |
    	| |  | |    /  \    |  \| | | |  __  | |__    | |__) | | | | | | |
    	| |  | |   / /\ \   | . ` | | | |_ | |  __|   |  _  /  | | | | | |
    	| |__| |  / ____ \  | |\  | | |__| | | |____  | | \ \  |_| |_| |_|
    	|_____/  /_/    \_\ |_| \_|  \_____| |______| |_|  \_\ (_) (_) (_)

	AVISO: O acesso nao autorizado a este sistema e proibido e sera processado
	conforme a lei.  Ao se conectar nesse sistema,  voce concorda que todas as
	suas acoes  serao monitoradas, caso  seja  verificado  o uso  indevido dos 
	recursos de acesso remoto nesse servidor, sera aplicado a lei vigente  com
	base nas diretivas da LGPD (Lei Geral de Protecao de Dados n: 13.709/2018)

		# Gerado pelo script: 			cwb.systech.com.br -- Soluçoes em TI
		# Autor:						Jensy Gregorio Gomez
		# Bio:							Têcnico em Informatica e Eletronica
		# WhatsApp:						(41) 99896-2670    /    99799-3164
		# Date:							01/01/2022

	**************************************************************************
	##########################################################################
	**************************************************************************
EOF
}


_Arquivo_Nsswitch_Conf () {
	cat << EOF > conf/ubuntu/nsswitch.conf

	# Gerado pelo script: 			cwb.systech.com.br -- Soluçoes em TI
	# Autor:						Jensy Gregorio Gomez
	# Bio:							Têcnico em Informatica e Eletronica
	# WhatsApp:						(41) 99896-2670    /    99799-3164
	# Date:							01/01/2022
	# Versão:						0.01
	#


	# Configuração do acesso a informações de usuários, grupos e senhas.
	# Padrão consultar primeiro os arquivos (files) depois o sistema (systemd)
	# DATABASE       SERVICE
	passwd:          files systemd
	group:           files systemd
	shadow:          files
	gshadow:         files
	#
	# Configuração da forma de resolução de nomes de computadores.
	# Padrão consultar primeiro os arquivos (files) depois o serviço de DNS
	# DATABASE       SERVICE
	hosts:           files dns
	networks:        files
	#
	# Configuração da consultada dos serviços de rede
	# Padrão consultar primeiro o banco de dados local (db) depois os arquivos (files)
	# DATABASE       SERVICE
	protocols:       db files
	services:        db files
	ethers:          db files
	rpc:             db files
	#
	# Configuração da consulta de resolução do serviço de Grupos de Rede
	# Padrão consultar primeiro os serviço de rede NIS (Network Information Service)
	# DATABASE       SERVICE
	netgroup:        nis
EOF
}