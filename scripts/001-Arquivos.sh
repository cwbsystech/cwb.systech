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

_Arquivo_Hostname () {
	rmdir -p conf/ubuntu/hostname
	touch conf/ubuntu/hostname
	cat <<EOF > conf/ubuntu/hostname

	# Gerado:				cwb.systech.com.br -- Soluçoes em TI
	# Autor:				Jensy Gregorio Gomez
	# Bio:					Têcnico em Informatica e Eletronica
	# WhatsApp:				(41) 99896-2670    /    99799-3164
	# Date:					01/01/2022
	# Versão:				0.01
	#

	$_Nome_Servidor.$_Nome_Dominio_FQDN
EOF
sleep 2
}


_Arquivo_Hosts () {
	rmdir -p conf/ubuntu/hosts
	touch conf/ubuntu/hosts

	cat << EOF > conf/ubuntu/hosts

	# Gerado:			cwb.systech.com.br -- Soluçoes em TI
	# Autor:			Jensy Gregorio Gomez
	# Bio:				Têcnico em Informatica e Eletronica
	# WhatsApp:			(41) 99896-2670    /    99799-3164
	# Date:				01/01/2022
	# Versão:			0.01
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
sleep 2
}


_Arquivo_Hosts_Allow () {
	rmdir -p conf/ubuntu/hosts.allow
	touch conf/ubuntu/hosts.allow
	cat << EOF > conf/ubuntu/hosts.allow
	
	# Gerado:			cwb.systech.com.br -- Soluçoes em TI
	# Autor:			Jensy Gregorio Gomez
	# Bio:				Têcnico em Informatica e Eletronica
	# WhatsApp:			(41) 99896-2670    /    99799-3164
	# Date:				01/01/2022
	# Versão:			0.01
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
sleep 2
}



_Arquivo_Hosts_Deny () {
	rmdir -p conf/ubuntu/hosts.deny
	touch conf/ubuntu/hosts.deny

	cat << EOF > conf/ubuntu/hosts.deny
	# Gerado:			cwb.systech.com.br -- Soluçoes em TI
	# Autor:			Jensy Gregorio Gomez
	# Bio:				Têcnico em Informatica e Eletronica
	# WhatsApp:			(41) 99896-2670    /    99799-3164
	# Date:				01/01/2022
	# Versão:			0.01
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
sleep 2
}


_Arquivo_Issue_Net () {
	rmdir -p conf/ubuntu/issue.net
	touch conf/ubuntu/issue.net

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

	# Gerado:				cwb.systech.com.br -- Soluçoes em TI
	# Autor:				Jensy Gregorio Gomez
	# Bio:					Têcnico em Informatica e Eletronica
	# WhatsApp:				(41) 99896-2670    /    99799-3164
	# Date:					01/01/2022
	# Versão:				0.01
	#

	**************************************************************************
	##########################################################################
	**************************************************************************
EOF
sleep 2
}


_Arquivo_Nsswitch_Conf () {
	rmdir -p conf/ubuntu/nsswitch.conf
	touch conf/ubuntu/nsswitch.conf

	cat << EOF > conf/ubuntu/nsswitch.conf

	# Gerado:			cwb.systech.com.br -- Soluçoes em TI
	# Autor:			Jensy Gregorio Gomez
	# Bio:				Têcnico em Informatica e Eletronica
	# WhatsApp:			(41) 99896-2670    /    99799-3164
	# Date:				01/01/2022
	# Versão:			0.01
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
sleep 2
}

_Arquivo_Sshd_Config () {
	rmdir -p conf/ssh/sshd_config
	touch conf/ssh/sshd_config

	cat << EOF > conf/ssh/sshd_config
	# Testado e homologado para a versão do OpenSSH Server v8.2.x
	#
	# Incluindo o diretório de configuração personalizada do OpenSSH Server
	Include /etc/ssh/sshd_config.d/*.conf
	#
	# Porta de conexão padrão do Servidor de OpenSSH, por segurança é recomendado mudar 
	# o número da porta. Caso você mude o número da porta, no cliente você precisa usar 
	# o comando: ssh -p porta usuário@ip_do_servidor
	Port $_PortSsh
	#
	# Versão do protocolo padrão do Servidor de OpenSSH
	Protocol 2
	#
	# Endereço IPv4 do Servidor de OpenSSH que está liberado para permitir conexões remotas 
	# via protocolo SSH
	ListenAddress $_Ip_V4_Servidor
	#
	# Métodos de Autenticação do OpenSSH, utilizar chaves públicas e autenticação por senha
	# Por padrão o Servidor de OpenSSH não trabalhar com Chaves Pública para autenticação, 
	# utilizando o arquivo /etc/passwd para se autenticar no servidor, por motivos de segurança, 
	# é recomendado utilizar chaves públicas e senhas para se autenticar no servidor
	# Descomentar essa opção depois de configurar a chave pública no client e no servidor
	# OBSERVAÇÃO: O Shell-In-a-Box não tem suporte a autenticação via Chave Pública somente 
	# autenticação padrão, para esse cenário é recomendado utilizar a solução Bastillion 
	# (https://www.bastillion.io/)
	#AuthenticationMethods publickey,password
	AuthenticationMethods password
	#
	# Autenticação utilizando chaves públicas geradas no cliente com o comando: ssh-keygen 
	# e exportada para o servidor com o comando: ssh-copy-id, chaves localizadas no diretório: 
	# /home/nome_usuário/.ssh/authorized_keys. Essa opção será utiliza em conjunto com a 
	# opção: AuthenticationMethods para verificar a chave pública.
	PubkeyAuthentication yes
	#
	# Especifica se a autenticação por senha é permitida. O padrão é yes. Não é recomendado 
	# alterar essa opção.
	PasswordAuthentication yes
	#
	# Configuração do diretório de chaves públicas para autenticar os usuários, as chaves 
	# devem ser exportada para o Servidor de OpenSSH utilizando o comando: ssh-copy-id
	AuthorizedKeysFile .ssh/authorized_keys
	#
	# Evitar o uso de diretórios residenciais inseguros e permissões de arquivos de chaves 
	# não confiáveis
	StrictModes yes
	#
	# Localização das configurações das Chaves Públicas e Privadas do Servidor de OpenSSH
	HostKey /etc/ssh/ssh_host_rsa_key
	HostKey /etc/ssh/ssh_host_dsa_key
	HostKey /etc/ssh/ssh_host_ecdsa_key
	HostKey /etc/ssh/ssh_host_ed25519_key
	#
	# Limite as cifras àquelas aprovadas pelo FIPS e use somente cifras no modo contador (CTR).
	Ciphers aes128-ctr,aes192-ctr,aes256-ctr
	#
	# Configuração dos Log's do Servidor de OpenSSH, recomendado utilizar junto com os 
	# arquivos de configuração: hosts.allow e hosts.deny para geração de log´s detalhados 
	# das conexões ao Servidor de OpenSSH.
	# Log's de autenticação do OpenSSH: sudo cat -n /var/log/auth.log | grep -i sshd
	# Log's de serviço do OpenSSH: sudo cat -n /var/log/syslog | grep -i ssh
	# Log's do TCPWrappers Allow: sudo cat -n /var/log/tcpwrappers-allow-ssh.log
	# Log's do TCPWrappers Deny: sudo cat -n /var/log/tcpwrappers-deny-ssh.log
	SyslogFacility AUTH
	LogLevel INFO
	#
	# Negar o acesso remoto ao Servidor de OpenSSH para o usuário ROOT
	PermitRootLogin no
	#
	# Usuários que tem permissão de acesso remoto ao Servidor de OpenSSH, separados por 
	# espaço, deve existir no servidor. Usuários listados no arquivo /etc/passwd
	AllowUsers $_UsuarioDefault
	#
	# Grupos que tem permissão de acesso remoto ao Servidor de OpenSSH, cuidado, se você 
	# usar a variável AllowUsers o grupo padrão do usuário precisa está liberado na linha 
	# AllowGroups, separados por espaço, deve existir no servidor. Grupos listados no 
	# arquivo /etc/group
	AllowGroups $_UsuarioDefault
	#
	# Usuários que não tem permissão de acesso remoto ao Servidor de OpenSSH, separados 
	# por espaço, deve existir no servidor. Usuários listados no arquivo /etc/passwd
	DenyUsers root
	#
	# Grupos que não tem permissão de acesso remoto ao Servidor de OpenSSH, cuidado, se 
	# você usar a variável DenyUsers o grupo padrão do usuário precisa está bloqueado 
	# na linha DenyGroups, separados por espaço, deve existir no servidor. Grupos 
	# listados no arquivo /etc/group
	DenyGroups root
	#
	# Banner que será apresentado no momento do acesso remoto ao Servidor de OpenSSH, 
	# não é recomendado utilizar acentuação
	Banner /etc/issue.net
	#
	# Tempo após o qual o servidor será desconectado se o usuário não tiver efetuado 
	# login com êxito.
	LoginGraceTime 60
	#
	# Tempo de inatividade em segundos para que os usuários logados na sessão do 
	# Servidor de OpenSSH sejam desconectados. Se você utiliza o recurso do Visual 
	# Studio Code VSCode com Remote SSH, recomendo comentar ou aumentar o tempo da sessão
	ClientAliveInterval 1800
	ClientAliveCountMax 3
	#
	# Tentativa máxima de conexões simultâneas no Servidor de OpenSSH
	MaxAuthTries 3
	#
	# Número de usuários ou sessões que podem se conectar remotamente no Servidor de OpenSSH
	MaxSessions 3
	#
	# Especifica o número máximo de conexões simultâneas não autenticadas com o OpenSSH 
	# para ser rejeitado a conexão. 5=conexão não autenticada | 60=rejeitar 60% das conexões 
	# | 10=tentativas de conexão
	MaxStartups 5:60:10
	#
	# Especifica qual família de endereços IP o OpenSSH deve suportar.
	# Os argumentos válidos são: any (IPv4 e IPV6), inet (somente IPv4), inet6 (somente IPv6)
	AddressFamily inet
	#
	# Não ler os arquivos de configurações ~/.rhosts e ~/.shosts
	IgnoreRhosts yes
	HostbasedAuthentication no
	#
	# Não permitir que usuários sem senhas se autentique remotamente no Servidor de OpenSSH
	PermitEmptyPasswords no
	#
	# Não permitir que os usuários definam opções de ambiente, utilizar os pré-definidos
	PermitUserEnvironment no
	#
	# Especifica se o encaminhamento de TCP é permitido. O padrão é yes. Se você utiliza o 
	# recurso do Visual Studio Code VSCode com Remote SSH, recomendo deixar yes
	AllowTcpForwarding no
	#
	# Não permitir encaminhamento de portas via Servidor de OpenSSH para os serviços de 
	# X11 (ambiente gráfico)
	X11Forwarding no
	#
	# Especifica o primeiro número de exibição disponível para encaminhamento X11 do 
	# sshd. Isso evita que o sshd interfira nos servidores X11 reais. O padrão é 10.
	X11DisplayOffset 10
	#
	# Controla o suporte para o esquema de autenticação "keyboard-interactive" definido 
	# no RFC-4256. Utilizar um desafio para se autenticar, muito utilizado com QRCode
	ChallengeResponseAuthentication no
	#
	# Utilizar autenticação de usuário via PAM (Linux Pluggable Authentication), essa 
	# opção só vai funcionar se o Serviço do PAM esteja configurado no Servidor
	UsePAM yes
	#
	# Imprimir na tela a mensagem de boas vindas do dia no login do OpenSSH
	PrintMotd no
	#
	# Imprimir na tela o Log da última autenticação válida da sessão do OpenSSH na tela
	PrintLastLog yes
	#
	# Especifica quais variáveis de ambiente enviadas pelo cliente serão copiadas para 
	# o ambiente da sessão após se autenticar no SSH
	AcceptEnv LANG LC_*
	#
	# Configura um subsistema externo (por exemplo, daemon de transferência de arquivo). 
	# Os argumentos devem ser um nome de subsistema e um comando (com argumentos opcionais) 
	# para executar mediante solicitação do subsistema.
	Subsystem sftp /usr/lib/openssh/sftp-server
	#
	# Especifica se o sistema deve enviar mensagens de manutenção de atividade TCP para o 
	# outro lado. Se forem enviados, será devidamente notado a morte da conexão ou travamento 
	# de uma das máquinas.
	TCPKeepAlive yes
	#
	# Desativar os mecanismos de autenticação desnecessários para fins de segurança
	KerberosAuthentication no
	GSSAPIAuthentication no
	#
	# Ativar a compactação após autenticação bem-sucedida (aumentar a segurança e desempenho)
	Compression delayed
	#
	# Não procure o nome do host remoto utilizando o serviço do DNS
	UseDNS no
EOF
sleep 2
}

_Arquivo_Shellinabox () {

	rmdir -p conf/ssh/shellinabox
	touch conf/ssh/shellinabox
	#cat <<EOF > conf/ssh/shellinabox
	# Gerado:			cwb.systech.com.br -- Soluçoes em TI
	# Autor:			Jensy Gregorio Gomez
	# Bio:				Têcnico em Informatica e Eletronica
	# WhatsApp:			(41) 99896-2670    /    99799-3164
	# Date:				01/01/2022
	# Versão:			0.01
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
EOF
sleep 2
}

_Arquivo_Installer_Conf_Yaml () {
	rmdir -p conf/ubuntu/00-installer-config.yaml
	touch conf/ubuntu/00-installer-config.yaml
	#cat <<EOF > conf/ubuntu/00-installer-config.yaml
	
	# Gerado:			cwb.systech.com.br -- Soluçoes em TI
	# Autor:			Jensy Gregorio Gomez
	# Bio:				Têcnico em Informatica e Eletronica
	# WhatsApp:			(41) 99896-2670    /    99799-3164
	# Date:				01/01/2022
	# Versão:			0.01
	#

	# Testado e homologado para a versão do Ubuntu Server 20.04.x LTS x64

	# Mais informações veja o arquivo: scripts/settings/04-ConfiguracaoDoNetplan.sh
	# Após as configuração do endereço IPv4 digitar o comando: netplan --debug apply
	#
	# Configuração do Endereço IPv4 do Ubuntu Server
network:
	ethernets:
		$_Interface_Lan:
			dhcp4: false
			addresses: [$_Ip_V4_Servidor/$_Mascara]
			gateway4: $_Gateway
			nameservers:
				addresses: [$_Gateway, 8.8.8.8, 8.8.4.4]
				search: [$_Nome_Dominio_FQDN]
	version: 2
EOF
}
















_Arquivo_Sshd_Config () {
	cat << EOF > conf/ssh/sshd_config
	# Gerado:				cwb.systech.com.br -- Soluçoes em TI
	# Autor:				Jensy Gregorio Gomez
	# Bio:					Têcnico em Informatica e Eletronica
	# WhatsApp:				(41) 99896-2670    /    99799-3164
	# Date:					01/01/2022
	# Versão:				0.01
	#
	# Testado e homologado para a versão do OpenSSH Server v8.2.x
	#
	# Incluindo o diretório de configuração personalizada do OpenSSH Server
	Include /etc/ssh/sshd_config.d/*.conf
	#
	# Porta de conexão padrão do Servidor de OpenSSH, por segurança é recomendado mudar 
	# o número da porta. Caso você mude o número da porta, no cliente você precisa usar 
	# o comando: ssh -p porta usuário@ip_do_servidor
	Port $_PortSsh
	#
	# Versão do protocolo padrão do Servidor de OpenSSH
	Protocol 2
	#
	# Endereço IPv4 do Servidor de OpenSSH que está liberado para permitir conexões remotas 
	# via protocolo SSH
	ListenAddress $_Ip_V4_Servidor
	#
	# Métodos de Autenticação do OpenSSH, utilizar chaves públicas e autenticação por senha
	# Por padrão o Servidor de OpenSSH não trabalhar com Chaves Pública para autenticação, 
	# utilizando o arquivo /etc/passwd para se autenticar no servidor, por motivos de segurança, 
	# é recomendado utilizar chaves públicas e senhas para se autenticar no servidor
	# Descomentar essa opção depois de configurar a chave pública no client e no servidor
	# OBSERVAÇÃO: O Shell-In-a-Box não tem suporte a autenticação via Chave Pública somente 
	# autenticação padrão, para esse cenário é recomendado utilizar a solução Bastillion 
	# (https://www.bastillion.io/)
	#AuthenticationMethods publickey,password
	AuthenticationMethods password
	#
	# Autenticação utilizando chaves públicas geradas no cliente com o comando: ssh-keygen 
	# e exportada para o servidor com o comando: ssh-copy-id, chaves localizadas no diretório: 
	# /home/nome_usuário/.ssh/authorized_keys. Essa opção será utiliza em conjunto com a 
	# opção: AuthenticationMethods para verificar a chave pública.
	PubkeyAuthentication yes
	#
	# Especifica se a autenticação por senha é permitida. O padrão é yes. Não é recomendado 
	# alterar essa opção.
	PasswordAuthentication yes
	#
	# Configuração do diretório de chaves públicas para autenticar os usuários, as chaves 
	# devem ser exportada para o Servidor de OpenSSH utilizando o comando: ssh-copy-id
	AuthorizedKeysFile .ssh/authorized_keys
	#
	# Evitar o uso de diretórios residenciais inseguros e permissões de arquivos de chaves 
	# não confiáveis
	StrictModes yes
	#
	# Localização das configurações das Chaves Públicas e Privadas do Servidor de OpenSSH
	HostKey /etc/ssh/ssh_host_rsa_key
	HostKey /etc/ssh/ssh_host_dsa_key
	HostKey /etc/ssh/ssh_host_ecdsa_key
	HostKey /etc/ssh/ssh_host_ed25519_key
	#
	# Limite as cifras àquelas aprovadas pelo FIPS e use somente cifras no modo contador (CTR).
	Ciphers aes128-ctr,aes192-ctr,aes256-ctr
	#
	# Configuração dos Log's do Servidor de OpenSSH, recomendado utilizar junto com os 
	# arquivos de configuração: hosts.allow e hosts.deny para geração de log´s detalhados 
	# das conexões ao Servidor de OpenSSH.
	# Log's de autenticação do OpenSSH: sudo cat -n /var/log/auth.log | grep -i sshd
	# Log's de serviço do OpenSSH: sudo cat -n /var/log/syslog | grep -i ssh
	# Log's do TCPWrappers Allow: sudo cat -n /var/log/tcpwrappers-allow-ssh.log
	# Log's do TCPWrappers Deny: sudo cat -n /var/log/tcpwrappers-deny-ssh.log
	SyslogFacility AUTH
	LogLevel INFO
	#
	# Negar o acesso remoto ao Servidor de OpenSSH para o usuário ROOT
	PermitRootLogin no
	#
	# Usuários que tem permissão de acesso remoto ao Servidor de OpenSSH, separados por 
	# espaço, deve existir no servidor. Usuários listados no arquivo /etc/passwd
	AllowUsers $_UsuarioDefault
	#
	# Grupos que tem permissão de acesso remoto ao Servidor de OpenSSH, cuidado, se você 
	# usar a variável AllowUsers o grupo padrão do usuário precisa está liberado na linha 
	# AllowGroups, separados por espaço, deve existir no servidor. Grupos listados no 
	# arquivo /etc/group
	AllowGroups $_UsuarioDefault
	#
	# Usuários que não tem permissão de acesso remoto ao Servidor de OpenSSH, separados 
	# por espaço, deve existir no servidor. Usuários listados no arquivo /etc/passwd
	DenyUsers root
	#
	# Grupos que não tem permissão de acesso remoto ao Servidor de OpenSSH, cuidado, se 
	# você usar a variável DenyUsers o grupo padrão do usuário precisa está bloqueado 
	# na linha DenyGroups, separados por espaço, deve existir no servidor. Grupos 
	# listados no arquivo /etc/group
	DenyGroups root
	#
	# Banner que será apresentado no momento do acesso remoto ao Servidor de OpenSSH, 
	# não é recomendado utilizar acentuação
	Banner /etc/issue.net
	#
	# Tempo após o qual o servidor será desconectado se o usuário não tiver efetuado 
	# login com êxito.
	LoginGraceTime 60
	#
	# Tempo de inatividade em segundos para que os usuários logados na sessão do 
	# Servidor de OpenSSH sejam desconectados. Se você utiliza o recurso do Visual 
	# Studio Code VSCode com Remote SSH, recomendo comentar ou aumentar o tempo da sessão
	ClientAliveInterval 1800
	ClientAliveCountMax 3
	#
	# Tentativa máxima de conexões simultâneas no Servidor de OpenSSH
	MaxAuthTries 3
	#
	# Número de usuários ou sessões que podem se conectar remotamente no Servidor de OpenSSH
	MaxSessions 3
	#
	# Especifica o número máximo de conexões simultâneas não autenticadas com o OpenSSH 
	# para ser rejeitado a conexão. 5=conexão não autenticada | 60=rejeitar 60% das conexões 
	# | 10=tentativas de conexão
	MaxStartups 5:60:10
	#
	# Especifica qual família de endereços IP o OpenSSH deve suportar.
	# Os argumentos válidos são: any (IPv4 e IPV6), inet (somente IPv4), inet6 (somente IPv6)
	AddressFamily inet
	#
	# Não ler os arquivos de configurações ~/.rhosts e ~/.shosts
	IgnoreRhosts yes
	HostbasedAuthentication no
	#
	# Não permitir que usuários sem senhas se autentique remotamente no Servidor de OpenSSH
	PermitEmptyPasswords no
	#
	# Não permitir que os usuários definam opções de ambiente, utilizar os pré-definidos
	PermitUserEnvironment no
	#
	# Especifica se o encaminhamento de TCP é permitido. O padrão é yes. Se você utiliza o 
	# recurso do Visual Studio Code VSCode com Remote SSH, recomendo deixar yes
	AllowTcpForwarding no
	#
	# Não permitir encaminhamento de portas via Servidor de OpenSSH para os serviços de 
	# X11 (ambiente gráfico)
	X11Forwarding no
	#
	# Especifica o primeiro número de exibição disponível para encaminhamento X11 do 
	# sshd. Isso evita que o sshd interfira nos servidores X11 reais. O padrão é 10.
	X11DisplayOffset 10
	#
	# Controla o suporte para o esquema de autenticação "keyboard-interactive" definido 
	# no RFC-4256. Utilizar um desafio para se autenticar, muito utilizado com QRCode
	ChallengeResponseAuthentication no
	#
	# Utilizar autenticação de usuário via PAM (Linux Pluggable Authentication), essa 
	# opção só vai funcionar se o Serviço do PAM esteja configurado no Servidor
	UsePAM yes
	#
	# Imprimir na tela a mensagem de boas vindas do dia no login do OpenSSH
	PrintMotd no
	#
	# Imprimir na tela o Log da última autenticação válida da sessão do OpenSSH na tela
	PrintLastLog yes
	#
	# Especifica quais variáveis de ambiente enviadas pelo cliente serão copiadas para 
	# o ambiente da sessão após se autenticar no SSH
	AcceptEnv LANG LC_*
	#
	# Configura um subsistema externo (por exemplo, daemon de transferência de arquivo). 
	# Os argumentos devem ser um nome de subsistema e um comando (com argumentos opcionais) 
	# para executar mediante solicitação do subsistema.
	Subsystem sftp /usr/lib/openssh/sftp-server
	#
	# Especifica se o sistema deve enviar mensagens de manutenção de atividade TCP para o 
	# outro lado. Se forem enviados, será devidamente notado a morte da conexão ou travamento 
	# de uma das máquinas.
	TCPKeepAlive yes
	#
	# Desativar os mecanismos de autenticação desnecessários para fins de segurança
	KerberosAuthentication no
	GSSAPIAuthentication no
	#
	# Ativar a compactação após autenticação bem-sucedida (aumentar a segurança e desempenho)
	Compression delayed
	#
	# Não procure o nome do host remoto utilizando o serviço do DNS
	UseDNS no
EOF

}