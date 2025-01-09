/*
 ===============================================================
 PhantomGate (improved + auto-fix)
 Created by Vladislav Tislenko (keklick1337) in 2025
 A minimalistic C99 port spoofer to confuse port scanners,
 with enhanced error handling and auto-fix for invalid signatures.
 Original repository of python version: https://github.com/keklick1337/PhantomGate
 This repository: https://github.com/keklick1337/PhantomGateC99
 ===============================================================

 (C) 2025, Vladislav Tislenko (keklick1337)
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#ifdef __linux__

#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#endif

#define PHANTOMGATE_VERSION "0.1.3"
#define DEFAULT_SIGNATURES_FILE "signatures.txt"
#define DEFAULT_LISTEN_ADDR "127.0.0.1:8888"
#define BUFFER_SIZE 4096
#define DEFAULT_TERM_WIDTH 80

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_SILENT
} LogLevel;

static LogLevel g_log_level = LOG_LEVEL_WARNING;

static FILE *g_logfile = NULL;

static void phantom_log(LogLevel level, const char *fmt, ...) {
    if (level < g_log_level) {
        return;
    }

    const char *level_str = NULL;
    switch (level) {
        case LOG_LEVEL_DEBUG:    level_str = "[DEBUG] ";   break;
        case LOG_LEVEL_INFO:     level_str = "[INFO] ";    break;
        case LOG_LEVEL_WARNING:  level_str = "[WARNING] "; break;
        case LOG_LEVEL_ERROR:    level_str = "[ERROR] ";   break;
        default:                 level_str = "";           break;
    }

    va_list args;
    va_start(args, fmt);

    fprintf(stdout, "%s", level_str);
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");

    if (g_logfile) {
        time_t t_now = time(NULL);
        struct tm tm_buf;
        localtime_r(&t_now, &tm_buf);

        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);
        
        fprintf(g_logfile, "%s %s", time_str, level_str);
        vfprintf(g_logfile, fmt, args);
        fprintf(g_logfile, "\n");
        fflush(g_logfile);
    }

    va_end(args);
}

typedef enum {
    SIGTYPE_RAW = 0,
    SIGTYPE_REGEX
} SignatureType;

typedef struct {
    SignatureType type;
    char *data;
    size_t length;
} Signature;

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    Signature *signatures;
    int signatures_count;
    bool debug;
    bool verbose;
    bool report_clients;
} ClientThreadArgs;

/* ------------------ Function prototypes ------------------ */
static void print_usage(const char *progname);
static void parse_arguments(int argc, char **argv,
                            char **sign_file,
                            char **listen_str,
                            bool *debug,
                            bool *verbose,
                            bool *quiet,
                            bool *version
                            ,bool *report_clients
                            ,char **log_file
                            );
static Signature *parse_signatures(const char *file_path, int *out_count);
static char *unescape_string(const char *s);
static bool unescape_string_extended(const char *s, char **out_buf, size_t *out_len);
static char *generate_payload(Signature *sig, size_t *out_len);
static char *generate_regex_match(const char *regex_str, size_t *out_len);
static void *handle_client_thread(void *arg);
static void start_server(const char *host, int port,
                         Signature *signatures, int signatures_count,
                         bool debug, bool verbose, bool quiet
                         ,bool report_clients
                         );
static char *c99_strdup(const char *src);
static void auto_fix_regex(char *str);
static bool looks_like_regex(const char *line);
static bool is_printable_byte(unsigned char b);
static void format_signature_line(const char *data, size_t length, char *out_buf, size_t out_buf_size);
int get_terminal_width(void);

/* ------------------ Main function ------------------ */
int main(int argc, char **argv) {
    /* Ignore SIGPIPE to avoid crashing when sending to closed sockets */
    signal(SIGPIPE, SIG_IGN);

    /* Seed the RNG for random signatures */
    srand((unsigned int) time(NULL));

    char *sign_file = DEFAULT_SIGNATURES_FILE;
    char listen_buf[256];
    strncpy(listen_buf, DEFAULT_LISTEN_ADDR, sizeof(listen_buf) - 1);
    listen_buf[sizeof(listen_buf) - 1] = '\0';

    char *listen_str = listen_buf;
    bool debug = false;
    bool verbose = false;
    bool quiet = false;
    bool show_version = false;

    bool report_clients = false;
    char *log_file = NULL;

    parse_arguments(argc, argv,
                    &sign_file, &listen_str,
                    &debug, &verbose, &quiet, &show_version
                    ,&report_clients
                    ,&log_file
                    );

    if (show_version) {
        printf("PhantomGate version %s\n", PHANTOMGATE_VERSION);
        return 0;
    }

    if (report_clients) {
        debug = true;
    }

    if (debug) {
        g_log_level = LOG_LEVEL_DEBUG;
    } else if (verbose) {
        g_log_level = LOG_LEVEL_INFO;
    } else if (quiet) {
        g_log_level = LOG_LEVEL_ERROR;
    } else {
        g_log_level = LOG_LEVEL_WARNING;
    }

    if (log_file) {
        g_logfile = fopen(log_file, "a");
        if (!g_logfile) {
            phantom_log(LOG_LEVEL_ERROR, "Cannot open logfile '%s': %s", log_file, strerror(errno));
        } else {
            phantom_log(LOG_LEVEL_INFO, "Logging to '%s'", log_file);
        }
    }

    int signatures_count = 0;
    Signature *signatures = parse_signatures(sign_file, &signatures_count);
    if (!signatures || signatures_count == 0) {
        phantom_log(LOG_LEVEL_ERROR, "No valid signatures found. Exiting.");
        if (g_logfile) fclose(g_logfile);
        return 1;
    }

    /* Parse host:port from listen_str */
    char *sep = strchr(listen_str, ':');
    if (!sep) {
        phantom_log(LOG_LEVEL_ERROR, "Listen address must be in format 'host:port'.");
        free(signatures);
        if (g_logfile) fclose(g_logfile);
        return 1;
    }

    *sep = '\0';
    char *host = listen_str;
    char *port_str = sep + 1;
    int port = atoi(port_str);
    if (port <= 0 || port > 65535) {
        phantom_log(LOG_LEVEL_ERROR, "Invalid port number: %s", port_str);
        free(signatures);
        if (g_logfile) fclose(g_logfile);
        return 1;
    }

    start_server(host, port, signatures, signatures_count, debug, verbose, quiet, report_clients);

    /* Cleanup */
    for (int i = 0; i < signatures_count; i++) {
        free(signatures[i].data);
    }
    free(signatures);

    if (g_logfile) {
        fclose(g_logfile);
        g_logfile = NULL;
    }

    return 0;
}

/* ------------------ Usage info ------------------ */
static void print_usage(const char *progname) {
    printf("Usage: %s [options]\n", progname);
    printf("Options:\n");
    printf("  -s, --signatures <file>    Path to signature file (default: '%s')\n",
           DEFAULT_SIGNATURES_FILE);
    printf("  -l, --listen <host:port>   Host:port to listen on (default: '%s')\n",
           DEFAULT_LISTEN_ADDR);
    printf("  -d, --debug                Enable debug output.\n");
    printf("  -v, --verbose              Enable verbose output.\n");
    printf("  -q, --quiet                Only show error messages.\n");
    printf("  -V, --version              Show version and exit.\n");
    printf("  -r, --report-clients       Show which signature was sent (enables debug).\n");
    printf("  -f, --logfile <file>       Append logs to file with timestamps.\n");
    printf("\n  PhantomGate version %s\n", PHANTOMGATE_VERSION);
}

static void parse_arguments(int argc, char **argv,
                            char **sign_file,
                            char **listen_str,
                            bool *debug,
                            bool *verbose,
                            bool *quiet,
                            bool *version
                            ,bool *report_clients
                            ,char **log_file
                            )
{
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--signatures") == 0) && i + 1 < argc) {
            *sign_file = argv[++i];
        } else if ((strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--listen") == 0) && i + 1 < argc) {
            *listen_str = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
            *debug = true;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            *verbose = true;
        } else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            *quiet = true;
        } else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) {
            *version = true;
        }
        else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--report-clients") == 0) {
            *report_clients = true;
        } else if ((strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--logfile") == 0) && i + 1 < argc) {
            *log_file = argv[++i];
        }
        else {
            phantom_log(LOG_LEVEL_INFO, "Unknown argument: %s", argv[i]);
            print_usage(argv[0]);
            exit(0);
        }
    }
}

/*
 * Try to "auto-fix" incorrect parentheses or brackets in a regex string.
 * If we find an unmatched '(' or '[', we just treat them as literal characters.
 * Similarly, if there's an unmatched ')', ']', we do the same. We do not do a
 * real "full fix," but at least we prevent crashing logic in generate_regex_match().
 */
static void auto_fix_regex(char *str) {
    if (!str) return;

    size_t len = strlen(str);
    int open_paren = 0;
    int open_brack = 0;

    for (size_t i = 0; i < len; i++) {
        if (str[i] == '(') {
            open_paren++;
        } else if (str[i] == ')') {
            if (open_paren > 0) open_paren--;
            else {
                /* Turn it into a literal character: e.g. '_' or something safe */
                str[i] = '_';
            }
        } else if (str[i] == '[') {
            open_brack++;
        } else if (str[i] == ']') {
            if (open_brack > 0) open_brack--;
            else {
                str[i] = '_';
            }
        }
    }
    /* If at the end we have open_paren or open_brack > 0,
       we convert them to literal characters as well. */
    if (open_paren > 0 || open_brack > 0) {
        // second pass: just replace leftover '(' or '[' with '_' 
        for (size_t i = 0; i < len; i++) {
            if (open_paren && str[i] == '(') {
                str[i] = '_';
                open_paren--;
            }
            if (open_brack && str[i] == '[') {
                str[i] = '_';
                open_brack--;
            }
            if (!open_paren && !open_brack) break;
        }
    }
}

static bool looks_like_regex(const char *line)
{
    // This is just a simplistic heuristic:
    // If the line contains certain patterns like "\d", "\w", "(", "[", etc.,
    // we treat it as a naive regex.
    // Feel free to adjust this check as needed.
    if (strstr(line, "\\d") || strstr(line, "\\w") || strstr(line, "\\.") ||
        strchr(line, '(')   || strchr(line, '[')) 
    {
        return true;
    }
    return false;
}

/*
 * parse_signatures() now tries to auto-fix invalid parentheses or brackets in regex lines
 * instead of just ignoring them or crashing.
 */
static Signature *parse_signatures(const char *file_path, int *out_count) {
    struct stat sb;
    if (stat(file_path, &sb) != 0) {
        phantom_log(LOG_LEVEL_ERROR, "Could not open file: %s", file_path);
        return NULL;
    }

    FILE *fp = fopen(file_path, "r");
    if (!fp) {
        phantom_log(LOG_LEVEL_ERROR, "Could not open file: %s", file_path);
        return NULL;
    }

    size_t capacity = 32;
    size_t size = 0;
    Signature *sigs = malloc(capacity * sizeof(Signature));
    if (!sigs) {
        fclose(fp);
        return NULL;
    }

    char line[BUFFER_SIZE];
    int line_num = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        char *ptr = strchr(line, '\n');
        if (ptr) *ptr = '\0';

        // Trim leading/trailing whitespace
        char *start = line;
        while (*start && isspace((unsigned char)*start)) start++;
        char *end = start + strlen(start);
        while (end > start && isspace((unsigned char)*(end - 1))) {
            end--;
        }
        *end = '\0';

        if (strlen(start) == 0) {
            continue; // skip empty lines
        }

        // Increase array if needed
        if (size >= capacity) {
            capacity *= 2;
            Signature *temp = realloc(sigs, capacity * sizeof(Signature));
            if (!temp) {
                free(sigs);
                fclose(fp);
                phantom_log(LOG_LEVEL_ERROR, "Memory allocation error reading signatures.");
                return NULL;
            }
            sigs = temp;
        }

        sigs[size].data = NULL;

        if (looks_like_regex(start)) {
            sigs[size].type = SIGTYPE_REGEX;
            char *dup = c99_strdup(start);
            if (!dup) {
                phantom_log(LOG_LEVEL_WARNING, 
                    "Line %d: c99_strdup() failed. Skipping...", line_num);
                continue;
            }
            auto_fix_regex(dup);
            sigs[size].data   = dup;
            sigs[size].length = strlen(dup);
        } else {
            sigs[size].type = SIGTYPE_RAW;
            /* For RAW lines, we do extended unescape that gives us length. */
            char *raw_buf = NULL;
            size_t raw_len = 0;
            if (!unescape_string_extended(start, &raw_buf, &raw_len) || !raw_buf) {
                phantom_log(LOG_LEVEL_WARNING, 
                    "Line %d: unescape_string_extended() failed. Skipping...", line_num);
                continue;
            }
            sigs[size].data   = raw_buf;
            sigs[size].length = raw_len;
        }

        size++;
    }

    fclose(fp);

    if (size == 0) {
        free(sigs);
        phantom_log(LOG_LEVEL_ERROR, "Signature file is empty or invalid: %s", file_path);
        return NULL;
    }

    phantom_log(LOG_LEVEL_DEBUG, "Loaded %zu signatures from '%s'", size, file_path);
    *out_count = (int)size;
    return sigs;
}

static char *c99_strdup(const char *src) {
    if (!src) return NULL;
    size_t len = strlen(src);
    char *copy = malloc(len + 1);
    if (!copy) return NULL;
    memcpy(copy, src, len + 1);
    return copy;
}

/*
 *  unescape_string_extended() handles backslash escapes, including \0, \n, \r, \t,
 *  and \xNN. We allow raw zero bytes.
 *  returns the allocated buffer
 *  plus the length of the data (including any embedded zeros).
 */
static bool unescape_string_extended(const char *s, char **out_buf, size_t *out_len) {
    if (!s || !out_buf || !out_len) return false;
    *out_buf = NULL;
    *out_len = 0;

    size_t slen = strlen(s);
    size_t capacity = slen + 1;
    char *result = (char *)malloc(capacity);
    if (!result) return false;

    size_t ri = 0;

    for (size_t i = 0; i < slen; i++) {
        if (ri + 4 >= capacity) {
            capacity *= 2;
            char *temp = realloc(result, capacity);
            if (!temp) {
                free(result);
                return false;
            }
            result = temp;
        }

        if (s[i] == '\\' && (i + 1 < slen)) {
            char nxt = s[i + 1];
            if (nxt == 'x' && (i + 3 < slen)) {
                char hex_part[3];
                hex_part[0] = s[i + 2];
                hex_part[1] = s[i + 3];
                hex_part[2] = '\0';
                unsigned int val;
                if (sscanf(hex_part, "%x", &val) == 1) {
                    result[ri++] = (char)val;
                    i += 3;
                } else {
                    // invalid sequence, just store '\'
                    result[ri++] = '\\';
                }
            } else if (nxt == '0') {
                result[ri++] = '\0';
                i++;
            } else if (nxt == 'n') {
                result[ri++] = '\n';
                i++;
            } else if (nxt == 'r') {
                result[ri++] = '\r';
                i++;
            } else if (nxt == 't') {
                result[ri++] = '\t';
                i++;
            } else {
                // copy nxt as is
                result[ri++] = nxt;
                i++;
            }
        } else {
            result[ri++] = s[i];
        }
    }

    *out_buf = result;
    *out_len = ri;
    return true;
}

/*
 * generate_payload: returns a newly allocated string (may contain zero bytes if RAW).
 * We do not rely on strlen() for RAW internally — but sending with send() does.
 * UPD 0.1.2
 * We now return (char*, size_t*) so we can handle embedded zero bytes.
 * But if you prefer, we can just store the data in 'payload' and store the
 * length in 'out_len'. Then handle_client_thread() uses that length.
 */
static char *generate_payload(Signature *sig, size_t *out_len) {
    if (!sig || !sig->data) {
        *out_len = 0;
        return NULL;
    }

    if (sig->type == SIGTYPE_RAW) {
        // As before: copy all bytes, respecting sig->length
        if (sig->length == 0) {
            *out_len = 0;
            return NULL;
        }
        char *cpy = (char *)malloc(sig->length);
        if (!cpy) {
            *out_len = 0;
            return NULL;
        }
        memcpy(cpy, sig->data, sig->length);
        *out_len = sig->length;
        return cpy;

    } else if (sig->type == SIGTYPE_REGEX) {
        // New call to generate_regex_match with &reg_len
        size_t reg_len = 0;
        char *expanded = generate_regex_match(sig->data, &reg_len);
        if (!expanded || reg_len == 0) {
            *out_len = 0;
            return expanded;  // might be NULL
        }
        *out_len = reg_len;
        return expanded;
    }

    // fallback
    *out_len = 0;
    return NULL;
}


/*
 * Category of the last token we expanded, so that when we see '+' or '*',
 * we know *what* to generate more of.
 */
typedef enum {
    CAT_NONE = 0,
    CAT_DIGIT,      /* \d => digits [0-9] */
    CAT_WCHAR,      /* \w => [A-Za-z0-9_] */
    CAT_BRACKET,    /* [abc] => from that bracket set */
    CAT_PRINTABLE,  /* '.' => random ASCII 0x21..0x7E */
    CAT_LITERAL     /* a single literal char (e.g. \., or normal text) */
} Category;

static inline char pick_random_digit(void) {
    /* random digit [0..9] */
    return (char)('0' + (rand() % 10));
}

static inline char pick_random_wchar(void) {
    /* random from [A-Za-z0-9_] => 26 + 26 + 10 + 1 = 63 total */
    int r = rand() % 63;
    if (r < 26) {
        return (char)('a' + r);
    }
    r -= 26;
    if (r < 26) {
        return (char)('A' + r);
    }
    r -= 26;
    if (r < 10) {
        return (char)('0' + r);
    }
    return '_';
}

static inline char pick_random_printable(void) {
    /* random printable ASCII [0x21..0x7E] */
    int rnd = 33 + (rand() % (126 - 33 + 1));
    return (char)rnd;
}

/*
 * Expand bracket content from something like "\w._-" into all actual characters:
 *  - \w => [A-Za-z0-9_]
 *  - \d => [0-9]
 *  - \. => literal '.'
 *  - \xNN => literal char with hex code NN (optional if you want)
 *  - anything else after '\' => that literal char
 *
 * For example:
 *   "\w._-" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"
 *
 * Returns the number of characters in 'dst', or -1 if an error occurred.
 */
static int expand_bracket_expression(const char *src, size_t srclen, char *dst, size_t dstsize)
{
    size_t di = 0;  /* index for writing into dst */
    for (size_t i = 0; i < srclen; i++) {
        if (di + 64 >= dstsize) {
            // make sure we won't overflow if we add many characters
            return -1; 
        }

        char c = src[i];
        if (c == '\\' && (i + 1 < srclen)) {
            char nxt = src[i + 1];
            switch (nxt) {
                case 'w': {
                    // expand \w => A-Za-z0-9_
                    const char *word_chars = 
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
                    size_t wc_len = strlen(word_chars);
                    if (di + wc_len >= dstsize) return -1;
                    memcpy(&dst[di], word_chars, wc_len);
                    di += wc_len;
                    i++;
                    break;
                }
                case 'd': {
                    // expand \d => 0-9
                    const char *digits = "0123456789";
                    size_t dg_len = strlen(digits);
                    if (di + dg_len >= dstsize) return -1;
                    memcpy(&dst[di], digits, dg_len);
                    di += dg_len;
                    i++;
                    break;
                }
                case '.': {
                    // expand \. => literal '.'
                    dst[di++] = '.';
                    i++;
                    break;
                }
                case 'r': {
                    // expand \r => literal '\r'
                    dst[di++] = '\r';
                    i++;
                    break;
                }
                case 'n': {
                    // expand \n => literal '\n'
                    dst[di++] = '\n';
                    i++;
                    break;
                }
                case 't': {
                    // expand \t => literal '\t'
                    dst[di++] = '\t';
                    i++;
                    break;
                }
                // you can add more expansions if desired:
                // case 's': => maybe spaces, etc.
                default: {
                    // if it's something like \xNN or \- etc.
                    // For simplicity, we just output nxt literally,
                    // or you can parse \xNN. 
                    // Example partial approach:
                    if (nxt == 'x' && (i + 3 < srclen)) {
                        // parse two hex digits
                        char hx[3];
                        hx[0] = src[i + 2];
                        hx[1] = src[i + 3];
                        hx[2] = '\0';
                        unsigned int val;
                        if (sscanf(hx, "%x", &val) == 1) {
                            dst[di++] = (char)val;
                            i += 3;
                        } else {
                            // fallback, just output 'x'
                            dst[di++] = 'x';
                            i++;
                        }
                    } else {
                        // just output nxt as literal
                        dst[di++] = nxt;
                        i++;
                    }
                    break;
                }
            }
        } else {
            // normal character => copy to dst
            dst[di++] = c;
        }
    }

    dst[di] = '\0';
    return (int)di; // number of chars stored
}


/*
 * pick_random_bracket: picks one random char from bracket_buf (which has
 * already been "expanded"). We try to avoid repeating last_char, but if
 * there's only 1 or 2 characters, we might fail quickly.
 */
static char pick_random_bracket(const char *bracket_buf, int bracket_len, char last_char)
{
    if (bracket_len <= 0) return '?';
    for (int tries = 0; tries < 10; tries++) {
        int pick = rand() % bracket_len;
        char c = bracket_buf[pick];
        if (c != last_char) {
            return c;
        }
    }
    // fallback
    return bracket_buf[0];
}

/*
 * Given a "category," pick a random char from that category,
 * avoiding last_char if possible.
 */
static char pick_from_category(Category cat,
                               const char *bracket_buf, int bracket_len,
                               char last_char)
{
    for (int tries = 0; tries < 10; tries++) {
        char c;
        switch (cat) {
            case CAT_DIGIT:
                c = pick_random_digit();
                break;
            case CAT_WCHAR:
                c = pick_random_wchar();
                break;
            case CAT_BRACKET:
                /* bracket_buf may have length bracket_len */
                if (bracket_len <= 0) {
                    c = '?'; /* fallback if bracket is empty */
                } else {
                    c = pick_random_bracket(bracket_buf, bracket_len, last_char);
                }
                break;
            case CAT_PRINTABLE:
                c = pick_random_printable();
                break;
            case CAT_LITERAL:
            default:
                /* If we get here, we do some random printable fallback. */
                c = pick_random_printable();
                break;
        }

        if (c != last_char) {
            return c;
        }
    }

    /* fallback if we can't avoid duplication after many tries */
    return pick_random_printable();
}

/*
 * generate_regex_match: naive "regex-like" expansion that tries to avoid
 * consecutive identical characters and produce random expansions for + or *.
 *
 * - \. => literal dot (Category = CAT_LITERAL)
 * - \d => random digit [0..9] (Category = CAT_DIGIT)
 * - \w => random from [A-Za-z0-9_] (Category = CAT_WCHAR)
 * - \r => 0x0D
 * - \n => 0x0A
 * - \t => 0x09
 * - \0 => 0x00
 * - \xNN => parse two hex digits
 * - [abc] => pick one random char from 'abc' (Category = CAT_BRACKET)
 * - + => produce 1..6 new chars from the last category
 * - * => produce 0..5 new chars from the last category
 * - . => random printable ASCII (Category = CAT_PRINTABLE)
 * - everything else => literal char (Category = CAT_LITERAL)
 *
 * Only call srand() once in your main(), not in this function.
 */
char *generate_regex_match(const char *regex_str, size_t *out_len)
{
    if (!regex_str) {
        if (out_len) *out_len = 0;
        return NULL;
    }
    size_t len = strlen(regex_str);

    // Rough capacity guess to allow expansions (+, *, etc.)
    size_t capacity = len * 6 + 1;
    if (capacity < 64) {
        capacity = 64;
    }

    char *result = (char *)malloc(capacity);
    if (!result) {
        if (out_len) *out_len = 0;
        return NULL;
    }

    size_t ri = 0;           // write index into 'result'
    char last_char = '\0';   // the last character we wrote
    Category last_cat = CAT_NONE;
    char last_bracket_buf[256];
    int  last_bracket_len = 0;

    memset(last_bracket_buf, 0, sizeof(last_bracket_buf));

    for (size_t i = 0; i < len; i++) {
        // Expand the buffer if we're close to capacity
        if (ri + 16 >= capacity) {
            capacity *= 2;
            char *temp = (char *)realloc(result, capacity);
            if (!temp) {
                free(result);
                if (out_len) *out_len = 0;
                return NULL;
            }
            result = temp;
        }

        char c = regex_str[i];

        // Handle backslash-escaped sequences
        if (c == '\\' && (i + 1 < len)) {
            char nxt = regex_str[i + 1];
            Category cat = CAT_LITERAL;  // default to literal unless recognized
            bool wrote_char = false;     
            char outc = '\0';

            switch (nxt) {
                case '.':
                    // \. => literal dot
                    outc = '.';
                    i++;
                    cat = CAT_LITERAL;
                    break;
                case 'd':
                    // \d => random digit
                    outc = pick_random_digit();
                    i++;
                    cat = CAT_DIGIT;
                    break;
                case 'w':
                    // \w => random word-char [A-Za-z0-9_]
                    outc = pick_random_wchar();
                    i++;
                    cat = CAT_WCHAR;
                    break;
                case 'r':
                    // \r => 0x0D
                    outc = '\r';
                    i++;
                    cat = CAT_LITERAL;
                    break;
                case 'n':
                    // \n => 0x0A
                    outc = '\n';
                    i++;
                    cat = CAT_LITERAL;
                    break;
                case 't':
                    // \t => 0x09
                    outc = '\t';
                    i++;
                    cat = CAT_LITERAL;
                    break;
                case '0':
                    // \0 => 0x00
                    outc = '\0';
                    i++;
                    cat = CAT_LITERAL;
                    break;
                case 'x':
                    // \xNN => parse two hex digits
                    if (i + 3 < len) {
                        char hx[3];
                        hx[0] = regex_str[i + 2];
                        hx[1] = regex_str[i + 3];
                        hx[2] = '\0';
                        unsigned int val;
                        if (sscanf(hx, "%x", &val) == 1) {
                            outc = (char)val;
                            i += 3;
                            cat = CAT_LITERAL;
                            wrote_char = true;
                        }
                    }
                    // if parsing fails, treat it as literal 'x'
                    if (!wrote_char) {
                        outc = 'x';
                        i++;
                        cat = CAT_LITERAL;
                    }
                    break;
                default:
                    // \something => literal next char
                    outc = nxt;
                    i++;
                    cat = CAT_LITERAL;
                    break;
            }

            // Avoid consecutive duplicates if this is a "random" category
            if (!wrote_char) {
                if (outc == last_char && cat != CAT_LITERAL && outc != '\0') {
                    if (cat == CAT_DIGIT || cat == CAT_WCHAR || cat == CAT_PRINTABLE) {
                        char newc = pick_from_category(cat, NULL, 0, last_char);
                        outc = newc;
                    }
                }
            }

            result[ri++] = outc;
            last_char = outc;
            last_cat = cat;
            if (cat == CAT_BRACKET) {
                last_bracket_len = 0;
            } else {
                last_bracket_len = 0;
            }
            continue;
        }
        else if (c == '[') {
            // Collect everything until the closing ']'
            char raw_buf[256];
            int raw_len = 0;
            memset(raw_buf, 0, sizeof(raw_buf));

            size_t j = i + 1;
            while (j < len && regex_str[j] != ']') {
                if (raw_len < 255) {
                    raw_buf[raw_len++] = regex_str[j];
                }
                j++;
            }
            // expand_bracket_expression recognizes \w, \d, \xNN, etc.
            char expanded_buf[1024];
            memset(expanded_buf, 0, sizeof(expanded_buf));
            int expanded_len = expand_bracket_expression(raw_buf, raw_len,
                                                         expanded_buf, sizeof(expanded_buf));
            if (expanded_len < 1) {
                // fallback
                expanded_buf[0] = '?';
                expanded_buf[1] = '\0';
                expanded_len = 1;
            }
            // Pick a random character from expanded_buf
            Category cat = CAT_BRACKET;
            char outc = pick_random_bracket(expanded_buf, expanded_len, last_char);

            result[ri++] = outc;
            last_char = outc;
            last_cat = cat;

            // Store bracket info for potential repetition (+ or *)
            memset(last_bracket_buf, 0, sizeof(last_bracket_buf));
            memcpy(last_bracket_buf, expanded_buf, expanded_len);
            last_bracket_buf[expanded_len] = '\0';
            last_bracket_len = expanded_len;

            // jump past the ']'
            if (j < len) {
                i = j;
            }
            continue;
        }
        else if (c == '+') {
            // 1..6 repeats of the previous category
            int repeat_count = 1 + (rand() % 6);
            for (int rc = 0; rc < repeat_count; rc++) {
                char outc = pick_from_category(last_cat, 
                                               last_bracket_buf, last_bracket_len,
                                               last_char);
                result[ri++] = outc;
                last_char = outc;
            }
        }
        else if (c == '*') {
            // 0..5 repeats of the previous category
            int repeat_count = rand() % 6;
            for (int rc = 0; rc < repeat_count; rc++) {
                char outc = pick_from_category(last_cat, 
                                               last_bracket_buf, last_bracket_len,
                                               last_char);
                result[ri++] = outc;
                last_char = outc;
            }
        }
        else if (c == '.') {
            // Random printable character
            Category cat = CAT_PRINTABLE;
            char outc = pick_random_printable();
            if (outc == last_char) {
                outc = pick_from_category(cat, NULL, 0, last_char);
            }
            result[ri++] = outc;
            last_char = outc;
            last_cat = cat;
            last_bracket_len = 0;
        }
        else {
            // Normal literal character
            result[ri++] = c;
            last_char = c;
            last_cat = CAT_LITERAL;
            last_bracket_len = 0;
        }
    }

    // Write a trailing '\0' so we can inspect it as a C-string, 
    // but the real length is in 'ri'
    result[ri] = '\0';

    if (out_len) {
        *out_len = ri; // The real number of bytes, ignoring '\0' as terminator
    }
    return result;
}

#ifdef __linux__ 

int get_terminal_width(void)
{
    struct winsize ws;
    // If ioctl succeeds, return ws_col. Otherwise, return DEFAULT_TERM_WIDTH.
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        return ws.ws_col;
    }
    return DEFAULT_TERM_WIDTH;
}

#else 

int get_terminal_width(void)
{
    return DEFAULT_TERM_WIDTH;
}

#endif

static bool is_printable_byte(unsigned char b)
{
    if (b >= 32 && b <= 126) return true;   // standard ASCII
    if (b == 9 || b == 10 || b == 13) return true; // tab, newline, CR
    return false;
}

static void format_signature_line(const char *data, size_t length, char *out_buf, size_t out_buf_size)
{
    // Converts non-printable bytes to \xNN,
    // but specifically turns 0x0D (CR) -> "\r" and 0x0A (LF) -> "\n"
    // rather than real line breaks.
    if (!data || !out_buf || out_buf_size < 2) {
        return;
    }
    size_t wi = 0;
    for (size_t i = 0; i < length; i++) {
        unsigned char b = (unsigned char)data[i];
        if (wi + 5 >= out_buf_size) {
            break;
        }

        if (b == '\r') {
            if (wi + 3 < out_buf_size) {
                out_buf[wi++] = '\\';
                out_buf[wi++] = 'r';
            }
        } else if (b == '\n') {
            if (wi + 3 < out_buf_size) {
                out_buf[wi++] = '\\';
                out_buf[wi++] = 'n';
            }
        } else if (is_printable_byte(b)) {
            out_buf[wi++] = (char)b; 
        } else {
            if (wi + 4 < out_buf_size) {
                sprintf(&out_buf[wi], "\\x%02X", b);
                wi += 4;
            }
        }
    }
    out_buf[wi] = '\0';
}

/*
 * handle_client_thread: if the payload is invalid (NULL or empty),
 * we try a different signature instead of crashing. 
 */
static void *handle_client_thread(void *arg) {
    ClientThreadArgs *targs = (ClientThreadArgs *)arg;
    int fd = targs->client_fd;
    struct sockaddr_in addr = targs->client_addr;
    bool debug = targs->debug;
    bool verbose = targs->verbose;
    bool report_clients = targs->report_clients;

    // We might try a few times in case of repeated invalid signatures
    // (max 5 attempts).
    int attempts = 5;
    char *payload = NULL;
    size_t payload_len = 0;
    int idx = -1;

    Signature *chosen = NULL;

    while (attempts--) {
        idx = rand() % targs->signatures_count;
        chosen = &targs->signatures[idx];

        /* Now we generate the payload plus length. */
        payload = generate_payload(chosen, &payload_len);
        if (!payload || payload_len == 0) {
            phantom_log(LOG_LEVEL_WARNING, 
                        "Invalid or empty payload for signature %d. Trying another one.", idx);
            if (payload) free(payload);
            payload = NULL;
            payload_len = 0;
            continue;
        }
        break; /* We got a valid payload */
    }

    if (!payload) {
        // If we still have nothing after attempts, just close the client without sending
        phantom_log(LOG_LEVEL_ERROR, 
                    "Could not generate valid payload after multiple attempts. Closing connection.");
        close(fd);
        free(targs);
        return NULL;
    }

    /* Attempt to send all payload_len bytes (including any \0). */
    ssize_t sent = send(fd, payload, payload_len, MSG_NOSIGNAL);
    if (sent >= 0) {
        if (debug && !report_clients) {
            phantom_log(LOG_LEVEL_DEBUG,
                        "Sent payload (%zd bytes) to %s:%d [sig:%d]",
                        sent, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), idx);
        } else if (verbose) {
            phantom_log(LOG_LEVEL_INFO,
                        "Sent payload to %s:%d",
                        inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        }

        if (report_clients) {
            int term_width = get_terminal_width();

            char tmpbuf[term_width];

            memset(tmpbuf, 0, sizeof(tmpbuf));
            format_signature_line(chosen->data, chosen->length, tmpbuf, sizeof(tmpbuf));

            if ((int)strlen(tmpbuf) > term_width) {
                tmpbuf[term_width] = '\0';
            }

            phantom_log(LOG_LEVEL_DEBUG,
                        "Client %s:%d got signature index %d: %s",
                        inet_ntoa(addr.sin_addr), ntohs(addr.sin_port),
                        idx, tmpbuf);
        }

    } else {
        if (debug) {
            phantom_log(LOG_LEVEL_DEBUG,
                        "Connection reset by %s:%d (send error: %s) [sig:%d]",
                        inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), strerror(errno), idx);
        }
    }
    free(payload);

    close(fd);
    free(targs);
    return NULL;
}

/*
 * start_server: main accept loop; creates a thread per client.
 */
static void start_server(const char *host, int port,
                         Signature *signatures, int signatures_count,
                         bool debug, bool verbose, bool quiet
                         ,bool report_clients
                         )
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        phantom_log(LOG_LEVEL_ERROR, "Could not create socket: %s", strerror(errno));
        return;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        phantom_log(LOG_LEVEL_ERROR, "Could not set SO_REUSEADDR: %s", strerror(errno));
        close(server_fd);
        return;
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);

    if (strcmp(host, "0.0.0.0") == 0) {
        servaddr.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (inet_pton(AF_INET, host, &servaddr.sin_addr) <= 0) {
            phantom_log(LOG_LEVEL_ERROR, "Invalid host address: %s", host);
            close(server_fd);
            return;
        }
    }

    if (bind(server_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        phantom_log(LOG_LEVEL_ERROR, "Could not bind to %s:%d: %s", host, port, strerror(errno));
        close(server_fd);
        return;
    }

    if (listen(server_fd, 128) < 0) {
        phantom_log(LOG_LEVEL_ERROR, "Could not listen on %s:%d: %s", host, port, strerror(errno));
        close(server_fd);
        return;
    }

    if (!quiet) {
        phantom_log(LOG_LEVEL_INFO, "PhantomGate is listening on %s:%d", host, port);
    }

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR) {
                phantom_log(LOG_LEVEL_INFO, "Stopping the server (interrupted).");
                break;
            }
            phantom_log(LOG_LEVEL_ERROR, "Accept error: %s", strerror(errno));
            continue;
        }

        if (debug) {
            phantom_log(LOG_LEVEL_DEBUG, "Accepted connection from %s:%d",
                        inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        }

        pthread_t tid;
        ClientThreadArgs *args = (ClientThreadArgs *)malloc(sizeof(ClientThreadArgs));
        if (!args) {
            phantom_log(LOG_LEVEL_ERROR, "Memory allocation error.");
            close(client_fd);
            continue;
        }

        args->client_fd = client_fd;
        args->client_addr = client_addr;
        args->signatures = signatures;
        args->signatures_count = signatures_count;
        args->debug = debug;
        args->verbose = verbose;
        args->report_clients = report_clients;

        if (pthread_create(&tid, NULL, handle_client_thread, args) != 0) {
            phantom_log(LOG_LEVEL_ERROR, "Could not create thread: %s", strerror(errno));
            close(client_fd);
            free(args);
            continue;
        }

        pthread_detach(tid);
    }

    close(server_fd);
}
