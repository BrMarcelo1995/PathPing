/*
 * pathping (Windows) - ping com analise de caminho via ICMP
 * Versao MULTITHREAD: cada salto e sondado em paralelo, entao a rodada
 * dura ~o tempo do hop mais lento, em vez da soma de todos os timeouts.
 *
 * Acumula por hop: RTT ultimo/min/avg/max e perda. Modo continuo (-l)
 * com estatistica acumulando entre rodadas (estilo mtr). Ctrl+C encerra.
 *
 * Compilar (MinGW-w64 / MSYS2 / w64devkit):
 *   gcc -O2 -Wall -o pathping.exe pathping_win.c -lws2_32 -liphlpapi
 *
 * Compilar (MSVC, "x64 Native Tools Command Prompt"):
 *   cl pathping_win.c ws2_32.lib iphlpapi.lib
 *
 * Uso:
 *   pathping.exe <host> [-c sondas] [-m max_hops] [-t timeout_ms]
 *                       [-l] [-i intervalo_ms]
 *   pathping.exe 8.8.8.8 -l -c 1 -i 1000
 *
 * Plataforma: Windows. IPv4. Nao precisa de admin.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <process.h>     /* _beginthreadex */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEF_PROBES   3
#define DEF_MAXHOPS  30
#define DEF_TIMEOUT  1000
#define DEF_INTERVAL 1000
#define DEF_PROBEGAP 0      /* pausa entre sondas do MESMO hop (ms) */
#define PAYLOAD_SIZE 32

typedef struct {
    char   addr[64];
    int    seen;
    int    sent;
    int    responded;
    double rtt_min;
    double rtt_max;
    double rtt_sum;
    double rtt_last;
    int    reached_dest;
    /* contadores POR RODADA (resetados a cada ciclo) para o log CSV */
    int    sent_r;
    int    recv_r;
    double rtt_sum_r;
    double rtt_min_r;
    double rtt_max_r;
} hop_stat_t;

/* Argumento passado a cada thread-worker (uma por hop) */
typedef struct {
    HANDLE         hIcmp;     /* handle ICMP proprio da thread     */
    LPVOID         reply_buf; /* buffer de resposta proprio        */
    DWORD          reply_sz;
    IPAddr         dest;
    int            ttl;
    int            probes;
    int            timeout;
    int            probe_gap;  /* ms entre sondas do mesmo hop      */
    LARGE_INTEGER  freq;
    char          *send_data;
    int            send_size;
    hop_stat_t    *h;         /* aponta para hops[ttl] - dono unico */
} worker_arg_t;

static volatile BOOL g_running = TRUE;

static BOOL WINAPI console_handler(DWORD signal)
{
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        g_running = FALSE;
        return TRUE;
    }
    return FALSE;
}

static void enable_vt(void)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

static void fmt_ip(IPAddr addr, char *out, size_t outlen)
{
    unsigned char *b = (unsigned char *)&addr;
    snprintf(out, outlen, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

/* Timestamp local "AAAA-MM-DD HH:MM:SS" para o log CSV */
static void now_str(char *out, size_t n)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(out, n, "%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

/* Data local de hoje "AAAA-MM-DD" */
static void today_date(char *out, size_t n)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(out, n, "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
}

/* Data de N dias atras "AAAA-MM-DD" (para o corte de retencao) */
static void date_minus_days(int days, char *out, size_t n)
{
    time_t t = time(NULL) - (time_t)days * 86400;
    struct tm *lt = localtime(&t);
    snprintf(out, n, "%04d-%02d-%02d",
             lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday);
}

/*
 * A partir de um caminho-base (ex.: "voz.csv" ou "C:\logs\voz.csv") e uma
 * data, monta o nome diario inserindo "_AAAA-MM-DD" antes da extensao:
 *   voz.csv  +  2026-06-28  ->  voz_2026-06-28.csv
 * Sem extensao, apenas anexa: "voz" -> "voz_2026-06-28".
 */
static void daily_path(const char *base, const char *date,
                       char *out, size_t n)
{
    const char *s1 = strrchr(base, '\\');
    const char *s2 = strrchr(base, '/');
    const char *slash = (s2 > s1) ? s2 : s1;
    const char *fname = slash ? slash + 1 : base;
    const char *dot   = strrchr(fname, '.');
    int dirlen = (int)(fname - base);

    if (dot) {
        int stemlen = (int)(dot - fname);
        snprintf(out, n, "%.*s%.*s_%s%s",
                 dirlen, base, stemlen, fname, date, dot);
    } else {
        snprintf(out, n, "%s_%s", base, date);
    }
}

/*
 * Retencao: apaga os logs diarios cuja data no nome seja anterior ao corte
 * (hoje - keep_days). Como AAAA-MM-DD ordena cronologicamente, basta comparar
 * as strings de data. keep_days <= 0 desabilita (mantem tudo).
 */
static void cleanup_old_logs(const char *base, int keep_days)
{
    if (keep_days <= 0) return;

    char cutoff[16];
    date_minus_days(keep_days, cutoff, sizeof(cutoff));

    const char *s1 = strrchr(base, '\\');
    const char *s2 = strrchr(base, '/');
    const char *slash = (s2 > s1) ? s2 : s1;
    const char *fname = slash ? slash + 1 : base;
    int dirlen = (int)(fname - base);

    char dir[MAX_PATH];
    snprintf(dir, sizeof(dir), "%.*s", dirlen, base);   /* vazio = dir atual */

    const char *dot = strrchr(fname, '.');
    char stem[MAX_PATH], ext[64];
    if (dot) {
        snprintf(stem, sizeof(stem), "%.*s", (int)(dot - fname), fname);
        snprintf(ext, sizeof(ext), "%s", dot);
    } else {
        snprintf(stem, sizeof(stem), "%s", fname);
        ext[0] = '\0';
    }

    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s%s_*%s", dir, stem, ext);

    WIN32_FIND_DATAA fd;
    HANDLE hf = FindFirstFileA(pattern, &fd);
    if (hf == INVALID_HANDLE_VALUE) return;

    int stemlen = (int)strlen(stem);
    do {
        const char *fn = fd.cFileName;
        if ((int)strlen(fn) < stemlen + 1 + 10) continue;

        /* extrai a data logo apos "stem_" */
        char datebuf[11];
        memcpy(datebuf, fn + stemlen + 1, 10);
        datebuf[10] = '\0';

        /* validacao leve do formato dddd-dd-dd */
        int valid = (datebuf[4] == '-' && datebuf[7] == '-');
        for (int k = 0; valid && k < 10; k++)
            if (k != 4 && k != 7 && (datebuf[k] < '0' || datebuf[k] > '9'))
                valid = 0;
        if (!valid) continue;

        if (strcmp(datebuf, cutoff) < 0) {
            char full[MAX_PATH];
            snprintf(full, sizeof(full), "%s%s", dir, fn);
            DeleteFileA(full);
        }
    } while (FindNextFileA(hf, &fd));

    FindClose(hf);
}

/* Le um pidfile e encerra o processo correspondente (comando --stop) */
static int do_stop(const char *pidfile)
{
    FILE *f = fopen(pidfile, "r");
    if (!f) {
        fprintf(stderr, "Nao foi possivel abrir o pidfile '%s'\n", pidfile);
        return 1;
    }
    unsigned long pid = 0;
    int got = fscanf(f, "%lu", &pid);
    fclose(f);
    if (got != 1 || pid == 0) {
        fprintf(stderr, "pidfile invalido: '%s'\n", pidfile);
        return 1;
    }

    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
    if (!h) {
        fprintf(stderr, "Nao foi possivel abrir o processo %lu (erro %lu). "
                "Talvez ja tenha encerrado.\n", pid, GetLastError());
        DeleteFileA(pidfile);   /* limpa pidfile orfao */
        return 1;
    }
    BOOL ok = TerminateProcess(h, 0);
    CloseHandle(h);
    if (ok) {
        printf("Processo %lu encerrado.\n", pid);
        DeleteFileA(pidfile);
        return 0;
    }
    fprintf(stderr, "Falha ao encerrar o processo %lu (erro %lu)\n",
            pid, GetLastError());
    return 1;
}

#define CSV_HEADER \
    "timestamp,round,hop,address,sent,recv," \
    "loss_pct,rtt_avg_ms,rtt_min_ms,rtt_max_ms\n"

/*
 * Abre/roda o log diario. Se a data mudou (ou ainda nao ha arquivo aberto),
 * fecha o atual, abre o arquivo do dia de hoje (cabecalho se for novo) e
 * dispara a limpeza de retencao. Chamada barata: retorna cedo se o dia e o
 * mesmo do arquivo ja aberto.
 */
static void rotate_daily_log(const char *base, int keep_days,
                             FILE **log, char *curdate, size_t curdate_n)
{
    char today[16];
    today_date(today, sizeof(today));
    if (*log && strcmp(today, curdate) == 0) return;   /* mesmo dia */

    if (*log) { fclose(*log); *log = NULL; }

    char path[MAX_PATH];
    daily_path(base, today, path, sizeof(path));

    long existing = 0;
    FILE *chk = fopen(path, "rb");
    if (chk) { fseek(chk, 0, SEEK_END); existing = ftell(chk); fclose(chk); }

    *log = fopen(path, "a");
    if (!*log) {
        fprintf(stderr, "Nao foi possivel abrir o log '%s'\n", path);
    } else if (existing == 0) {
        fputs(CSV_HEADER, *log);
    }

    snprintf(curdate, curdate_n, "%s", today);
    cleanup_old_logs(base, keep_days);
}

/*
 * Corpo de cada thread: sonda UM hop (TTL fixo) com 'probes' envios.
 * Escreve apenas em a->h, que e exclusivo desta thread -> sem locks.
 */
static unsigned __stdcall worker(void *param)
{
    worker_arg_t *a = (worker_arg_t *)param;
    hop_stat_t   *h = a->h;

    IP_OPTION_INFORMATION opt;
    memset(&opt, 0, sizeof(opt));
    opt.Ttl = (UCHAR)a->ttl;

    h->seen = 1;

    for (int p = 0; p < a->probes && g_running; p++) {
        h->sent++;
        h->sent_r++;

        LARGE_INTEGER t0, t1;
        QueryPerformanceCounter(&t0);

        DWORD n = IcmpSendEcho(a->hIcmp, a->dest,
                               a->send_data, (WORD)a->send_size,
                               &opt, a->reply_buf, a->reply_sz,
                               (DWORD)a->timeout);

        QueryPerformanceCounter(&t1);
        double rtt = (double)(t1.QuadPart - t0.QuadPart) * 1000.0
                     / (double)a->freq.QuadPart;

        if (n > 0) {
            PICMP_ECHO_REPLY rep = (PICMP_ECHO_REPLY)a->reply_buf;
            if (rep->Status == IP_SUCCESS ||
                rep->Status == IP_TTL_EXPIRED_TRANSIT) {

                h->responded++;
                fmt_ip(rep->Address, h->addr, sizeof(h->addr));
                h->rtt_last = rtt;
                if (rtt < h->rtt_min) h->rtt_min = rtt;
                if (rtt > h->rtt_max) h->rtt_max = rtt;
                h->rtt_sum += rtt;

                /* acumuladores da rodada atual */
                h->recv_r++;
                if (rtt < h->rtt_min_r) h->rtt_min_r = rtt;
                if (rtt > h->rtt_max_r) h->rtt_max_r = rtt;
                h->rtt_sum_r += rtt;

                if (rep->Status == IP_SUCCESS) h->reached_dest = 1;
            }
        }

        /*
         * Espaca a proxima sonda do MESMO hop para nao chegar em rajada
         * ao roteador e disparar o rate-limiting de geracao de ICMP.
         * Nao dorme depois da ultima sonda. Pausa picada para o Ctrl+C.
         */
        if (a->probe_gap > 0 && p + 1 < a->probes && g_running) {
            int slept = 0;
            while (slept < a->probe_gap && g_running) {
                int step = (a->probe_gap - slept > 50) ? 50 : (a->probe_gap - slept);
                Sleep(step);
                slept += step;
            }
        }
    }
    return 0;
}

/* Espera um vetor de threads terminar, em lotes de 64 (limite da API) */
static void join_all(HANDLE *handles, int n)
{
    int i = 0;
    while (i < n) {
        int chunk = (n - i > MAXIMUM_WAIT_OBJECTS)
                    ? MAXIMUM_WAIT_OBJECTS : (n - i);
        WaitForMultipleObjects(chunk, &handles[i], TRUE, INFINITE);
        i += chunk;
    }
}

/* Argumento da sonda TCP fim-a-fim (apenas o destino) */
typedef struct {
    IPAddr        dest;
    int           port;
    int           probes;
    int           timeout;
    int           probe_gap;
    LARGE_INTEGER freq;
    hop_stat_t   *h;
} tcp_arg_t;

/*
 * Sonda TCP no destino via connect() nao-bloqueante.
 * Mede alcancabilidade fim-a-fim: SYN-ACK (porta aberta) E RST (porta
 * fechada) contam como "alcancado", pois ambos provam que o caminho
 * esta vivo. Apenas timeout/inalcancavel conta como perda.
 */
static unsigned __stdcall tcp_worker(void *param)
{
    tcp_arg_t  *a = (tcp_arg_t *)param;
    hop_stat_t *h = a->h;
    h->seen = 1;

    for (int p = 0; p < a->probes && g_running; p++) {
        h->sent++;
        h->sent_r++;

        LARGE_INTEGER t0, t1;
        QueryPerformanceCounter(&t0);

        int reached = 0;
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s != INVALID_SOCKET) {
            u_long nb = 1;
            ioctlsocket(s, FIONBIO, &nb);   /* nao-bloqueante */

            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family      = AF_INET;
            sa.sin_addr.s_addr = a->dest;
            sa.sin_port        = htons((u_short)a->port);

            int rc = connect(s, (struct sockaddr *)&sa, sizeof(sa));
            if (rc == 0) {
                reached = 1;   /* conectou de imediato (raro) */
            } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
                fd_set wf, ef;
                FD_ZERO(&wf); FD_ZERO(&ef);
                FD_SET(s, &wf); FD_SET(s, &ef);

                struct timeval tv;
                tv.tv_sec  = a->timeout / 1000;
                tv.tv_usec = (a->timeout % 1000) * 1000;

                if (select(0, NULL, &wf, &ef, &tv) > 0) {
                    int so_err = 0, len = sizeof(so_err);
                    getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&so_err, &len);
                    /* 0 = conectou ; CONNREFUSED = RST => host vivo */
                    if (so_err == 0 || so_err == WSAECONNREFUSED) reached = 1;
                }
                /* select()==0 -> timeout -> perda */
            } else if (WSAGetLastError() == WSAECONNREFUSED) {
                reached = 1;   /* RST imediato */
            }
            /*
             * Fecho abrupto: SO_LINGER com l_linger=0 faz o closesocket
             * enviar RST em vez de FIN, descartando o socket na hora sem
             * passar por TIME_WAIT. Evita esgotar portas efemeras quando a
             * sonda roda em alta frequencia. O RST e inofensivo: a conexao
             * de teste nao carrega dados, e o destino simplesmente o ignora.
             */
            struct linger lg;
            lg.l_onoff  = 1;
            lg.l_linger = 0;
            setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&lg, sizeof(lg));

            closesocket(s);
        }

        QueryPerformanceCounter(&t1);
        double rtt = (double)(t1.QuadPart - t0.QuadPart) * 1000.0
                     / (double)a->freq.QuadPart;

        if (reached) {
            h->responded++;
            h->rtt_last = rtt;
            if (rtt < h->rtt_min) h->rtt_min = rtt;
            if (rtt > h->rtt_max) h->rtt_max = rtt;
            h->rtt_sum += rtt;

            h->recv_r++;
            if (rtt < h->rtt_min_r) h->rtt_min_r = rtt;
            if (rtt > h->rtt_max_r) h->rtt_max_r = rtt;
            h->rtt_sum_r += rtt;

            h->reached_dest = 1;
        }

        if (a->probe_gap > 0 && p + 1 < a->probes && g_running) {
            int slept = 0;
            while (slept < a->probe_gap && g_running) {
                int step = (a->probe_gap - slept > 50) ? 50 : (a->probe_gap - slept);
                Sleep(step);
                slept += step;
            }
        }
    }
    return 0;
}

/* Ajuda detalhada, exibida com -? / -h / --help / /? */
static void print_help(const char *prog)
{
    printf(
"pathping - ping com analise de caminho (ICMP) + sonda TCP fim-a-fim\n"
"\n"
"USO:\n"
"  %s <host> [opcoes]\n"
"\n"
"OPCOES:\n"
"  -c <n>      Sondas por salto a cada rodada (padrao 3).\n"
"              No modo continuo, prefira -c 1 (estilo mtr): a estatistica\n"
"              acumula entre rodadas sem provocar rate-limit nos roteadores.\n"
"  -m <n>      TTL maximo / numero maximo de saltos (padrao 30).\n"
"  -t <ms>     Timeout por sonda em milissegundos (padrao 1000).\n"
"  -w <ms>     Intervalo entre sondas do MESMO salto (padrao 0).\n"
"              Espaca as sondas para nao chegarem em rajada ao roteador e\n"
"              evitar falsa perda por rate-limiting de ICMP. Tente 50-100.\n"
"  -l          Modo continuo (loop): repete e acumula ate Ctrl+C.\n"
"  -i <ms>     Intervalo entre rodadas no modo loop (padrao 1000).\n"
"  -p <porta>  Sonda TCP SYN no DESTINO nesta porta, em paralelo ao ICMP.\n"
"              Mede a saude fim-a-fim do trafego REAL (atravessa firewall,\n"
"              reflete o caminho que sua aplicacao usa). Ex.: -p 5060 (SIP),\n"
"              -p 443 (HTTPS). SYN-ACK e RST contam como alcancado.\n"
"  -o <arq>    Grava log CSV com ROTACAO DIARIA. O nome recebe a data:\n"
"              -o voz.csv  gera  voz_AAAA-MM-DD.csv (um arquivo por dia,\n"
"              trocando sozinho a meia-noite). Abre em append; cabecalho\n"
"              so e escrito quando o arquivo do dia e novo.\n"
"  -r <dias>   Retencao: apaga logs diarios mais antigos que <dias>.\n"
"              0 ou ausente = mantem tudo. Ex.: -r 30 guarda 30 dias.\n"
"  -P <arq>    Grava o PID do processo neste arquivo ao iniciar (pidfile).\n"
"              Permite parar depois com:  pathping --stop <arq>\n"
"  -b          Roda em BACKGROUND (destacado do terminal). O processo se\n"
"              relanca sem janela e continua mesmo apos fechar o console.\n"
"              EXIGE -o (sem console, o CSV e a unica saida). Use com -l.\n"
"              Para parar: --stop <pidfile>, ou taskkill /PID <pid> /F.\n"
"  --stop <arq>  Le o pidfile e encerra o processo correspondente. Sai.\n"
"  -? -h       Mostra esta ajuda.\n"
"\n"
"COLUNAS DA TABELA:\n"
"  ultimo/min/avg/max  RTT em ms (avg/min/max acumulados na sessao).\n"
"  perda               Percentual de perda acumulado.\n"
"  enviados/perdidos   Contadores absolutos acumulados (ICMP).\n"
"  Linha TCP           Aparece quando -p e usado: perda/RTT fim-a-fim na porta.\n"
"\n"
"INTERPRETANDO A PERDA (importante):\n"
"  - Perda REAL se propaga: se um hop perde, os seguintes e o destino tambem.\n"
"  - Perda ISOLADA num hop intermediario (que NAO propaga) geralmente e\n"
"    rate-limiting de ICMP, nao perda de verdade. Use -w para confirmar.\n"
"  - A metrica fim-a-fim confiavel e a linha TCP (-p) ou a perda do hop final.\n"
"  - ICMP costuma cair em fila de baixa prioridade no QoS; a sonda TCP na\n"
"    porta da aplicacao reflete melhor o que a voz/dados realmente sentem.\n"
"\n"
"EXEMPLOS:\n"
"  %s 8.8.8.8\n"
"  %s 8.8.8.8 -c 3 -w 80\n"
"  %s 10.0.0.1 -l -c 1 -i 1000 -o link_wan.csv\n"
"  %s sbc.provedor.com -l -c 1 -w 50 -p 5060 -o voz.csv\n"
"  %s 10.0.0.1 -l -c 1 -i 1000 -p 5060 -o voz.csv -b   (em background)\n"
"  %s 10.0.0.1 -l -c 1 -o voz.csv -r 30 -P voz.pid -b  (rotacao+retencao+pid)\n"
"  %s --stop voz.pid                                   (para o processo)\n",
    prog, prog, prog, prog, prog, prog, prog, prog);
}

/*
 * Relanca o programa destacado do terminal (background). O processo filho
 * herda os mesmos argumentos, exceto -b, e roda sem console (DETACHED_PROCESS),
 * continuando mesmo apos o terminal ser fechado. O pai exibe o PID e sai.
 */
static int relaunch_background(int argc, char *argv[])
{
    char exe[MAX_PATH];
    if (GetModuleFileNameA(NULL, exe, sizeof(exe)) == 0) {
        fprintf(stderr, "Nao foi possivel obter o caminho do executavel\n");
        return 1;
    }

    /* reconstroi a linha de comando, citando o que tiver espaco e tirando -b */
    char cmd[4096];
    int  pos = snprintf(cmd, sizeof(cmd), "\"%s\"", exe);
    for (int i = 1; i < argc && pos < (int)sizeof(cmd) - 1; i++) {
        if (!strcmp(argv[i], "-b")) continue;   /* remove a flag de background */
        const char *fmt = strchr(argv[i], ' ') ? " \"%s\"" : " %s";
        pos += snprintf(cmd + pos, sizeof(cmd) - pos, fmt, argv[i]);
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                             DETACHED_PROCESS, NULL, NULL, &si, &pi);
    if (!ok) {
        fprintf(stderr, "Falha ao iniciar em background (erro %lu)\n",
                GetLastError());
        return 1;
    }

    printf("Rodando em background (PID %lu).\n", pi.dwProcessId);
    printf("Para parar: taskkill /PID %lu /F\n", pi.dwProcessId);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

static void print_table(hop_stat_t *hops, int limit, int loop_mode,
                        const char *host, const char *dst_ip, long round,
                        hop_stat_t *tcp, int tcp_port)
{
    if (loop_mode) printf("\033[H\033[2J");

    printf("Analise de caminho ICMP para %s (%s)", host, dst_ip);
    if (loop_mode) printf("   [rodada %ld - Ctrl+C para parar]", round);
    printf("\n\n");

    printf("%-4s %-22s %8s %8s %8s %8s %7s %8s %8s\n",
           "Hop", "Endereco", "ultimo", "min", "avg", "max", "perda",
           "enviados", "perdidos");
    printf("------------------------------------------------------------------------------------------------\n");

    for (int ttl = 1; ttl <= limit; ttl++) {
        hop_stat_t *h = &hops[ttl];
        if (!h->seen) continue;

        double loss = h->sent ? 100.0 * (h->sent - h->responded) / h->sent : 0;
        int    lost = h->sent - h->responded;
        if (h->responded > 0) {
            double avg = h->rtt_sum / h->responded;
            printf("%-4d %-22s %7.2f %7.2f %7.2f %7.2f %6.0f%% %8d %8d\n",
                   ttl, h->addr, h->rtt_last, h->rtt_min, avg, h->rtt_max,
                   loss, h->sent, lost);
        } else {
            printf("%-4d %-22s %8s %8s %8s %8s %6.0f%% %8d %8d\n",
                   ttl, "*", "-", "-", "-", "-", loss, h->sent, lost);
        }
    }

    /* linha da sonda TCP fim-a-fim, se habilitada */
    if (tcp_port > 0 && tcp->seen) {
        double loss = tcp->sent ? 100.0 * (tcp->sent - tcp->responded) / tcp->sent : 0;
        int    lost = tcp->sent - tcp->responded;
        printf("------------------------------------------------------------------------------------------------\n");
        if (tcp->responded > 0) {
            double avg = tcp->rtt_sum / tcp->responded;
            printf("%-4s %-22s %7.2f %7.2f %7.2f %7.2f %6.0f%% %8d %8d\n",
                   "TCP", tcp->addr, tcp->rtt_last, tcp->rtt_min, avg,
                   tcp->rtt_max, loss, tcp->sent, lost);
        } else {
            printf("%-4s %-22s %8s %8s %8s %8s %6.0f%% %8d %8d\n",
                   "TCP", tcp->addr, "-", "-", "-", "-", loss, tcp->sent, lost);
        }
    }

    printf("------------------------------------------------------------------------------------------------\n");
    fflush(stdout);
}

int main(int argc, char *argv[])
{
    /* ajuda: -? -h --help /? em qualquer posicao */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-?")  || !strcmp(argv[i], "/?") ||
            !strcmp(argv[i], "-h")  || !strcmp(argv[i], "--help")) {
            print_help(argv[0]);
            return 0;
        }
    }

    /* comando de parada: --stop <pidfile> (nao exige host) */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--stop")) {
            if (i + 1 < argc) return do_stop(argv[i + 1]);
            fprintf(stderr, "Uso: %s --stop <pidfile>\n", argv[0]);
            return 1;
        }
    }

    if (argc < 2) {
        fprintf(stderr,
            "Uso: %s <host> [-c n] [-m n] [-t ms] [-l] [-i ms] [-w ms] "
            "[-p porta] [-o arquivo.csv] [-r dias] [-P pidfile] [-b]\n"
            "     %s -?   para ajuda detalhada\n", argv[0], argv[0]);
        return 1;
    }

    const char *host = argv[1];
    int probes    = DEF_PROBES;
    int max_hops  = DEF_MAXHOPS;
    int timeout   = DEF_TIMEOUT;
    int loop_mode = 0;
    int interval  = DEF_INTERVAL;
    int probe_gap = DEF_PROBEGAP;
    int tcp_port  = 0;          /* 0 = sonda TCP desabilitada */
    int background = 0;         /* 1 = relancar destacado do terminal */
    int keep_days = 0;          /* retencao de logs (0 = manter tudo) */
    const char *logpath = NULL;
    const char *pidfile = NULL;

    for (int i = 2; i < argc; i++) {
        if      (!strcmp(argv[i], "-c") && i + 1 < argc) probes    = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-m") && i + 1 < argc) max_hops  = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-t") && i + 1 < argc) timeout   = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-i") && i + 1 < argc) interval  = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-w") && i + 1 < argc) probe_gap = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-p") && i + 1 < argc) tcp_port  = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-o") && i + 1 < argc) logpath   = argv[++i];
        else if (!strcmp(argv[i], "-r") && i + 1 < argc) keep_days = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-P") && i + 1 < argc) pidfile   = argv[++i];
        else if (!strcmp(argv[i], "-l")) loop_mode = 1;
        else if (!strcmp(argv[i], "-b")) background = 1;
        else { fprintf(stderr, "Opcao desconhecida: %s\n", argv[i]); return 1; }
    }
    if (probes < 1) probes = 1;
    if (max_hops < 1 || max_hops > 255) max_hops = DEF_MAXHOPS;
    if (interval < 0) interval = 0;
    if (tcp_port < 0 || tcp_port > 65535) tcp_port = 0;
    if (probe_gap < 0) probe_gap = 0;
    if (keep_days < 0) keep_days = 0;

    /*
     * Background: o pai relanca uma copia destacada e sai. Exige -o, pois
     * sem console o CSV e a unica saida. Recomenda -l (senao roda uma vez).
     */
    if (background) {
        if (!logpath) {
            fprintf(stderr,
                "Erro: -b exige -o <arquivo.csv> (sem console, o CSV e a "
                "unica saida).\n");
            return 1;
        }
        if (!loop_mode) {
            fprintf(stderr,
                "Aviso: -b sem -l roda apenas uma rodada. Considere adicionar -l.\n");
        }
        return relaunch_background(argc, argv);
    }

    /* processo efetivo (inclui o filho de background): grava o pidfile */
    if (pidfile) {
        FILE *pf = fopen(pidfile, "w");
        if (pf) {
            fprintf(pf, "%lu\n", (unsigned long)GetCurrentProcessId());
            fclose(pf);
        } else {
            fprintf(stderr, "Aviso: nao foi possivel escrever o pidfile '%s'\n",
                    pidfile);
        }
    }

    SetConsoleCtrlHandler(console_handler, TRUE);
    if (loop_mode) enable_vt();

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "Falha em WSAStartup\n");
        return 1;
    }

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || res == NULL) {
        fprintf(stderr, "Nao foi possivel resolver '%s'\n", host);
        WSACleanup();
        return 1;
    }
    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    IPAddr dest = sin->sin_addr.s_addr;
    freeaddrinfo(res);

    char dst_ip[64];
    fmt_ip(dest, dst_ip, sizeof(dst_ip));

    char send_data[PAYLOAD_SIZE];
    memset(send_data, 0x42, sizeof(send_data));
    DWORD reply_sz = sizeof(ICMP_ECHO_REPLY) + PAYLOAD_SIZE + 8;

    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);

    /* recursos por hop, alocados uma vez e reusados entre rodadas.
     * threads tem +1 slot para a eventual sonda TCP em paralelo. */
    hop_stat_t   *hops    = calloc(max_hops + 1, sizeof(hop_stat_t));
    HANDLE       *handles = calloc(max_hops + 1, sizeof(HANDLE));   /* handle ICMP */
    LPVOID       *bufs    = calloc(max_hops + 1, sizeof(LPVOID));   /* reply buffer */
    worker_arg_t *args    = calloc(max_hops + 1, sizeof(worker_arg_t));
    HANDLE       *threads = calloc(max_hops + 2, sizeof(HANDLE));
    if (!hops || !handles || !bufs || !args || !threads) {
        fprintf(stderr, "Sem memoria\n");
        return 1;
    }

    /* estado da sonda TCP fim-a-fim (um unico, persiste entre rodadas) */
    hop_stat_t tcp;
    memset(&tcp, 0, sizeof(tcp));
    tcp.rtt_min = 1e9;
    tcp_arg_t  tcp_a;
    if (tcp_port > 0)
        snprintf(tcp.addr, sizeof(tcp.addr), "%s:%d", dst_ip, tcp_port);

    for (int i = 1; i <= max_hops; i++) {
        hops[i].rtt_min = 1e9;
        handles[i] = IcmpCreateFile();
        bufs[i]    = malloc(reply_sz);
        if (handles[i] == INVALID_HANDLE_VALUE || !bufs[i]) {
            fprintf(stderr, "Falha alocando recursos ICMP no hop %d\n", i);
            return 1;
        }
    }

    int  limit = max_hops;
    long round = 0;

    /* log com rotacao diaria; cabecalho escrito quando o arquivo do dia e novo */
    FILE *log = NULL;
    char log_date[16] = "";
    if (logpath)
        rotate_daily_log(logpath, keep_days, &log, log_date, sizeof(log_date));

    do {
        round++;
        int nthreads = 0;

        /* zera os contadores POR RODADA antes de medir */
        for (int ttl = 1; ttl <= limit; ttl++) {
            hops[ttl].sent_r    = 0;
            hops[ttl].recv_r    = 0;
            hops[ttl].rtt_sum_r = 0;
            hops[ttl].rtt_min_r = 1e9;
            hops[ttl].rtt_max_r = 0;
        }
        if (tcp_port > 0) {
            tcp.sent_r = 0; tcp.recv_r = 0;
            tcp.rtt_sum_r = 0; tcp.rtt_min_r = 1e9; tcp.rtt_max_r = 0;
        }

        for (int ttl = 1; ttl <= limit && g_running; ttl++) {
            worker_arg_t *a = &args[ttl];
            a->hIcmp     = handles[ttl];
            a->reply_buf = bufs[ttl];
            a->reply_sz  = reply_sz;
            a->dest      = dest;
            a->ttl       = ttl;
            a->probes    = probes;
            a->timeout   = timeout;
            a->probe_gap = probe_gap;
            a->freq      = freq;
            a->send_data = send_data;
            a->send_size = sizeof(send_data);
            a->h         = &hops[ttl];

            HANDLE th = (HANDLE)_beginthreadex(NULL, 0, worker, a, 0, NULL);
            if (th == 0) {
                /* falhou criar thread: roda este hop de forma sincrona */
                worker(a);
            } else {
                threads[nthreads++] = th;
            }
        }

        /* sonda TCP fim-a-fim, em paralelo aos hops ICMP */
        if (tcp_port > 0 && g_running) {
            tcp_a.dest      = dest;
            tcp_a.port      = tcp_port;
            tcp_a.probes    = probes;
            tcp_a.timeout   = timeout;
            tcp_a.probe_gap = probe_gap;
            tcp_a.freq      = freq;
            tcp_a.h         = &tcp;

            HANDLE th = (HANDLE)_beginthreadex(NULL, 0, tcp_worker, &tcp_a, 0, NULL);
            if (th == 0) tcp_worker(&tcp_a);
            else         threads[nthreads++] = th;
        }

        /* barreira: espera todos os hops desta rodada terminarem */
        join_all(threads, nthreads);
        for (int i = 0; i < nthreads; i++) CloseHandle(threads[i]);

        /* descobriu o destino? apara o caminho ate o primeiro hop que chegou */
        int dest_ttl = 0;
        for (int ttl = 1; ttl <= limit; ttl++) {
            if (hops[ttl].reached_dest) { dest_ttl = ttl; break; }
        }
        if (dest_ttl) {
            for (int ttl = dest_ttl + 1; ttl <= limit; ttl++) hops[ttl].seen = 0;
            limit = dest_ttl;
        }

        print_table(hops, limit, loop_mode, host, dst_ip, round, &tcp, tcp_port);

        /* verifica virada de dia antes de gravar (rotacao do log) */
        if (logpath)
            rotate_daily_log(logpath, keep_days, &log, log_date, sizeof(log_date));

        /* grava uma linha por hop com os valores DESTA rodada */
        if (log) {
            char ts[40];   /* folga p/ o pior caso que o compilador assume */
            now_str(ts, sizeof(ts));
            for (int ttl = 1; ttl <= limit; ttl++) {
                hop_stat_t *h = &hops[ttl];
                if (!h->seen) continue;
                double loss = h->sent_r
                    ? 100.0 * (h->sent_r - h->recv_r) / h->sent_r : 100.0;
                if (h->recv_r > 0) {
                    fprintf(log, "%s,%ld,%d,%s,%d,%d,%.0f,%.3f,%.3f,%.3f\n",
                            ts, round, ttl, h->addr, h->sent_r, h->recv_r,
                            loss, h->rtt_sum_r / h->recv_r,
                            h->rtt_min_r, h->rtt_max_r);
                } else {
                    /* sem resposta nesta rodada: RTT em branco */
                    fprintf(log, "%s,%ld,%d,%s,%d,%d,%.0f,,,\n",
                            ts, round, ttl, h->addr[0] ? h->addr : "*",
                            h->sent_r, h->recv_r, loss);
                }
            }
            /* linha da sonda TCP fim-a-fim: hop=0 marca a metrica end-to-end */
            if (tcp_port > 0 && tcp.seen) {
                double loss = tcp.sent_r
                    ? 100.0 * (tcp.sent_r - tcp.recv_r) / tcp.sent_r : 100.0;
                if (tcp.recv_r > 0) {
                    fprintf(log, "%s,%ld,0,%s/tcp,%d,%d,%.0f,%.3f,%.3f,%.3f\n",
                            ts, round, tcp.addr, tcp.sent_r, tcp.recv_r,
                            loss, tcp.rtt_sum_r / tcp.recv_r,
                            tcp.rtt_min_r, tcp.rtt_max_r);
                } else {
                    fprintf(log, "%s,%ld,0,%s/tcp,%d,%d,%.0f,,,\n",
                            ts, round, tcp.addr, tcp.sent_r, tcp.recv_r, loss);
                }
            }
            fflush(log);   /* garante dados no disco para leitura ao vivo */
        }

        if (loop_mode && g_running && interval > 0) {
            int slept = 0;
            while (slept < interval && g_running) {
                int step = (interval - slept > 100) ? 100 : (interval - slept);
                Sleep(step);
                slept += step;
            }
        }
    } while (loop_mode && g_running);

    if (loop_mode) {
        printf("\nEncerrado apos %ld rodada(s).\n", round);
        if (hops[limit].reached_dest)
            printf("Destino %s alcancado.\n", dst_ip);
    } else {
        if (hops[limit].reached_dest)
            printf("Destino %s alcancado.\n", dst_ip);
        else
            printf("Destino nao alcancado em %d saltos.\n", max_hops);
    }

    for (int i = 1; i <= max_hops; i++) {
        if (handles[i] && handles[i] != INVALID_HANDLE_VALUE)
            IcmpCloseHandle(handles[i]);
        free(bufs[i]);
    }
    free(hops); free(handles); free(bufs); free(args); free(threads);
    if (log) fclose(log);
    if (pidfile) DeleteFileA(pidfile);   /* remove pidfile em saida limpa */
    WSACleanup();
    return 0;
}
