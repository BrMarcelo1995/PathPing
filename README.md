# PathPing
Ferramenta de monitoramento de rede para Windows com análise de caminho ICMP hop-a-hop e sonda TCP fim-a-fim


**pathping**
Monitor de rede para Windows que combina análise de caminho ICMP (estilo MTR) com sonda TCP fim-a-fim, monitoramento contínuo e log CSV com rotação diária.
Funcionalidades

**Análise hop-a-hop via ICMP** — descobre cada salto até o destino variando o TTL, coletando RTT mín/médio/máx/último e percentual de perda acumulado por hop
Multithreading — todos os saltos são sondados em paralelo, então uma rodada dura o tempo do hop mais lento, não a soma de todos.

**Sonda TCP fim-a-fim (-p)** — mede a saúde do caminho real atravessando firewall, na porta da aplicação (SIP, HTTPS, etc.), independente de bloqueio de ICMP
**Modo contínuo (-l)** — estatística acumula entre rodadas, revelando perda intermitente invisível a medições únicas
**Controle de rate-limiting (-w)** — espaça as sondas do mesmo hop para evitar falsa perda por limitação de geração de ICMP nos roteadores
**Log CSV com rotação diária (-o)** — gera um arquivo por dia (nome_AAAA-MM-DD.csv), trocando automaticamente à meia-noite
**Retenção de logs (-r)** — apaga automaticamente arquivos mais antigos que N dias
**Background (-b)** — relança o processo destacado do terminal, continuando após fechar o console
Gerência de processo (-P / --stop) — grava o PID em arquivo e permite parar o monitoramento sem anotar número

**Compilar**
gcc -O2 -Wall -o pathping.exe pathping_win.c -lws2_32 -liphlpapi
Requer MinGW-w64, MSYS2 ou w64devkit. Não precisa de privilégio de administrador.

**Uso rápido**
pathping.exe 8.8.8.8 -c 3 -w 80
pathping.exe 10.0.0.1 -l -c 1 -i 1000 -p 5060 -o voz.csv -r 30 -P voz.pid -b
pathping.exe --stop voz.pid
pathping.exe -?
