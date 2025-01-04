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

#define PHANTOMGATE_VERSION "0.1.1"
#define DEFAULT_SIGNATURES_FILE "signatures.txt"
#define DEFAULT_LISTEN_ADDR "127.0.0.1:8888"
#define BUFFER_SIZE 4096

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_SILENT
} LogLevel;

static LogLevel g_log_level = LOG_LEVEL_WARNING;

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

    va_end(args);
}

typedef enum {
    SIGTYPE_RAW = 0,
    SIGTYPE_REGEX
} SignatureType;

typedef struct {
    SignatureType type;
    /*
     * data may contain zero bytes in RAW mode,
     * so do not rely on strlen() blindly if you're debugging.
     */
    char *data;
} Signature;

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
    Signature *signatures;
    int signatures_count;
    bool debug;
    bool verbose;
} ClientThreadArgs;

/* ------------------ Function prototypes ------------------ */
static void print_usage(const char *progname);
static void parse_arguments(int argc, char **argv,
                            char **sign_file,
                            char **listen_str,
                            bool *debug,
                            bool *verbose,
                            bool *quiet,
                            bool *version);
static Signature *parse_signatures(const char *file_path, int *out_count);
static char *unescape_string(const char *s);
static char *generate_payload(Signature *sig);
static char *generate_regex_match(const char *regex_str);
static void *handle_client_thread(void *arg);
static void start_server(const char *host, int port,
                         Signature *signatures, int signatures_count,
                         bool debug, bool verbose, bool quiet);
static char *c99_strdup(const char *src);

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

    parse_arguments(argc, argv, &sign_file, &listen_str, &debug, &verbose, &quiet, &show_version);

    if (show_version) {
        printf("PhantomGate version %s\n", PHANTOMGATE_VERSION);
        return 0;
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

    int signatures_count = 0;
    Signature *signatures = parse_signatures(sign_file, &signatures_count);
    if (!signatures || signatures_count == 0) {
        phantom_log(LOG_LEVEL_ERROR, "No valid signatures found. Exiting.");
        return 1;
    }

    /* Parse host:port from listen_str */
    char *sep = strchr(listen_str, ':');
    if (!sep) {
        phantom_log(LOG_LEVEL_ERROR, "Listen address must be in format 'host:port'.");
        free(signatures);
        return 1;
    }

    *sep = '\0';
    char *host = listen_str;
    char *port_str = sep + 1;
    int port = atoi(port_str);
    if (port <= 0 || port > 65535) {
        phantom_log(LOG_LEVEL_ERROR, "Invalid port number: %s", port_str);
        free(signatures);
        return 1;
    }

    start_server(host, port, signatures, signatures_count, debug, verbose, quiet);

    /* Cleanup */
    for (int i = 0; i < signatures_count; i++) {
        free(signatures[i].data);
    }
    free(signatures);

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
    printf("\n  PhantomGate version %s\n", PHANTOMGATE_VERSION);
}

static void parse_arguments(int argc, char **argv,
                            char **sign_file,
                            char **listen_str,
                            bool *debug,
                            bool *verbose,
                            bool *quiet,
                            bool *version)
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
        } else {
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
        strchr(line, '(')   || strchr(line, '[')   ||
        strstr(line, "\\x")) 
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
            sigs[size].data = c99_strdup(start);
            auto_fix_regex(sigs[size].data);
        } else {
            sigs[size].type = SIGTYPE_RAW;
            sigs[size].data = unescape_string(start);
            if (!sigs[size].data) {
                phantom_log(LOG_LEVEL_WARNING, 
                            "Line %d: unescape_string() failed. Skipping...", line_num);
                continue;
            }
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
 *  unescape_string() handles backslash escapes, including \0, \n, \r, \t,
 *  and \xNN. We allow raw zero bytes.
 */
static char *unescape_string(const char *s) {
    size_t len = strlen(s);

    // Initial buffer capacity: len+1, expand as necessary.
    size_t capacity = len + 1;
    char *result = (char *)malloc(capacity);
    if (!result) return NULL;

    size_t ri = 0;
    for (size_t i = 0; i < len; i++) {
        // Expand if near the end
        if (ri + 4 >= capacity) {
            capacity *= 2;
            char *temp = realloc(result, capacity);
            if (!temp) {
                free(result);
                return NULL;
            }
            result = temp;
        }

        if (s[i] == '\\' && (i + 1 < len)) {
            char nxt = s[i + 1];
            if (nxt == 'x' && (i + 3 < len)) {
                char hex_part[3] = { s[i + 2], s[i + 3], '\0' };
                unsigned int val = 0;
                if (sscanf(hex_part, "%x", &val) == 1) {
                    result[ri++] = (char)val;
                    i += 3;
                } else {
                    // Invalid sequence
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
                // Copy the next char as is
                result[ri++] = nxt;
                i++;
            }
        } else {
            // Normal character
            result[ri++] = s[i];
        }
    }

    result[ri] = '\0';
    return result;
}

/*
 * generate_payload: returns a newly allocated string (may contain zero bytes if RAW).
 * We do not rely on strlen() for RAW internally — but sending with send() does.
 */
static char *generate_payload(Signature *sig) {
    if (!sig || !sig->data) {
        return NULL;
    }
    if (sig->type == SIGTYPE_RAW) {
        /*
         * Return a copy. But be aware it may contain \0. 
         * For sending, we rely on the "apparent" length up to the first \0 if we use strlen().
         * If you want to send the entire length including zeros, you'd need another approach
         * that tracks the binary length. But let's keep it simple for now.
         */
        // safely duplicate, but might get truncated at \0 if we do just c99_strdup
        // For demonstration, let's do a custom copy that includes possible trailing bytes after \0
        // up to some maximum. However, if the signature has real embedded zeros in the middle,
        // 'strlen' won't see them.
        // 
        // We'll just do normal c99_strdup, meaning effectively we treat up to first \0 as payload.
        return c99_strdup(sig->data);
    } else if (sig->type == SIGTYPE_REGEX) {
        return generate_regex_match(sig->data);
    }
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
char *generate_regex_match(const char *regex_str)
{
    if (!regex_str) {
        return NULL;
    }
    size_t len = strlen(regex_str);

    /* A rough capacity guess to allow expansions. */
    size_t capacity = len * 6 + 1;
    if (capacity < 64) {
        capacity = 64;
    }

    char *result = (char *)malloc(capacity);
    if (!result) {
        return NULL;
    }

    size_t ri = 0; /* write index into result */
    char last_char = '\0'; /* track the last character we wrote */
    Category last_cat = CAT_NONE;
    char last_bracket_buf[256];
    int last_bracket_len = 0;

    memset(last_bracket_buf, 0, sizeof(last_bracket_buf));

    for (size_t i = 0; i < len; i++) {
        /* expand the buffer if near capacity */
        if (ri + 16 >= capacity) {
            capacity *= 2;
            char *temp = (char *)realloc(result, capacity);
            if (!temp) {
                free(result);
                return NULL;
            }
            result = temp;
        }

        char c = regex_str[i];

        /* check for backslash escapes */
        if (c == '\\' && (i + 1 < len)) {
            char nxt = regex_str[i + 1];
            Category cat = CAT_LITERAL; /* assume literal unless recognized */

            bool wrote_char = false;
            char outc = '\0';

            switch (nxt) {
                case '.':
                    /* \. => literal dot */
                    outc = '.';
                    i++;
                    cat = CAT_LITERAL;
                    break;
                case 'd':
                    /* \d => random digit */
                    outc = pick_random_digit();
                    i++;
                    cat = CAT_DIGIT;
                    break;
                case 'w':
                    /* \w => random wchar [A-Za-z0-9_] */
                    outc = pick_random_wchar();
                    i++;
                    cat = CAT_WCHAR;
                    break;
                case 'r':
                    /* \r => 0x0D */
                    outc = '\r';
                    i++;
                    cat = CAT_LITERAL;
                    break;
                case 'n':
                    /* \n => 0x0A */
                    outc = '\n';
                    i++;
                    cat = CAT_LITERAL;
                    break;
                case 't':
                    /* \t => 0x09 */
                    outc = '\t';
                    i++;
                    cat = CAT_LITERAL;
                    break;
                case '0':
                    /* \0 => 0x00 */
                    outc = '\0';
                    i++;
                    cat = CAT_LITERAL;
                    break;
                case 'x':
                    /* \xNN => parse two hex digits */
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
                    if (!wrote_char) {
                        /* if invalid or incomplete, output literal 'x' */
                        outc = 'x';
                        i++;
                        cat = CAT_LITERAL;
                    }
                    break;
                default:
                    /* \something => literal next char */
                    outc = nxt;
                    i++;
                    cat = CAT_LITERAL;
                    break;
            }

            if (!wrote_char) {
                /* possibly we haven't assigned outc yet */
                if (outc == '\0' && cat == CAT_LITERAL) {
                    /* means we wrote a real 0x00, keep going */
                }
                if (outc != '\0' || cat != CAT_LITERAL) {
                    /* we have a normal ASCII outc or 0x00 from above */
                }
            }

            /* Avoid consecutive identical chars: re-pick if needed and possible */
            if (outc && outc == last_char && cat != CAT_LITERAL && outc != '\0') {
                /* If it's a random category, try to re-pick once or twice */
                if (cat == CAT_DIGIT || cat == CAT_WCHAR || cat == CAT_PRINTABLE) {
                    char newc = pick_from_category(cat, NULL, 0, last_char);
                    outc = newc;
                }
            }

            result[ri++] = outc;
            last_char = outc;
            last_cat = cat;
            if (cat == CAT_BRACKET) {
                /* just in case, but we don't do bracket in backslash forms. */
                last_bracket_len = 0;
            } else {
                last_bracket_len = 0;
            }
            continue;
        }
        else if (c == '[') {
            // Collect everything until the next ']'
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

            // Now we expand special sequences in raw_buf => expanded_buf
            char expanded_buf[1024];
            memset(expanded_buf, 0, sizeof(expanded_buf));
            int expanded_len = expand_bracket_expression(raw_buf, raw_len,
                                                        expanded_buf, sizeof(expanded_buf));
            if (expanded_len < 1) {
                // fallback if no valid expansions
                expanded_buf[0] = '?';
                expanded_buf[1] = '\0';
                expanded_len = 1;
            }

            // Now pick one random character from expanded_buf
            Category cat = CAT_BRACKET;
            char outc = pick_random_bracket(expanded_buf, expanded_len, last_char);

            // Write outc to the result
            result[ri++] = outc;
            last_char = outc;
            last_cat = cat;

            // Store bracket info for potential + or * expansions
            memset(last_bracket_buf, 0, sizeof(last_bracket_buf));
            memcpy(last_bracket_buf, expanded_buf, expanded_len);
            last_bracket_buf[expanded_len] = '\0';
            last_bracket_len = expanded_len;

            // skip past the closing ']' if we found it
            if (j < len) {
                i = j;
            }
            continue;
        }
        else if (c == '+') {
            /* produce 1..6 new chars from last_cat, each different from last_char */
            int repeat_count = 1 + (rand() % 6);
            for (int rc = 0; rc < repeat_count; rc++) {
                char outc = pick_from_category(last_cat,
                                               last_bracket_buf,
                                               last_bracket_len,
                                               last_char);
                result[ri++] = outc;
                last_char = outc;
            }
        }
        else if (c == '*') {
            /* produce 0..5 new chars from last_cat, each different from last_char */
            int repeat_count = rand() % 6;
            for (int rc = 0; rc < repeat_count; rc++) {
                char outc = pick_from_category(last_cat,
                                               last_bracket_buf,
                                               last_bracket_len,
                                               last_char);
                result[ri++] = outc;
                last_char = outc;
            }
        }
        else if (c == '.') {
            /* random printable => CAT_PRINTABLE */
            Category cat = CAT_PRINTABLE;
            char outc = pick_random_printable();
            /* avoid consecutive duplicates if possible */
            if (outc == last_char) {
                char newc = pick_from_category(cat, NULL, 0, last_char);
                outc = newc;
            }
            result[ri++] = outc;
            last_char = outc;
            last_cat = cat;
            last_bracket_len = 0;
        }
        else {
            /* normal literal char => CAT_LITERAL */
            result[ri++] = c;
            last_char = c;
            last_cat = CAT_LITERAL;
            last_bracket_len = 0;
        }
    }

    /* finalize string */
    result[ri] = '\0';
    return result;
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

    // We might try a few times in case of repeated invalid signatures
    // (max 5 attempts).
    int attempts = 5;
    char *payload = NULL;
    int idx = -1;

    while (attempts--) {
        idx = rand() % targs->signatures_count;
        Signature *chosen = &targs->signatures[idx];

        payload = generate_payload(chosen);
        if (!payload || payload[0] == '\0') {
            // log warning, pick another
            phantom_log(LOG_LEVEL_WARNING, 
                        "Invalid or empty payload for signature %d. Trying another one.", idx);
            if (payload) free(payload);
            payload = NULL;
            continue;
        }
        // We got a non-empty payload
        break;
    }

    if (!payload) {
        // If we still have nothing after attempts, just close the client without sending
        phantom_log(LOG_LEVEL_ERROR, 
                    "Could not generate valid payload after multiple attempts. Closing connection.");
        close(fd);
        free(targs);
        return NULL;
    }

    // Now attempt to send. If the client closed connection, we skip.
    size_t payload_len = strlen(payload);
    // If you want to send raw bytes including \0 in the middle,
    // you'd need a different length approach. For now, we rely on strlen.
    ssize_t sent = send(fd, payload, payload_len, MSG_NOSIGNAL);
    if (sent >= 0) {
        if (debug) {
            phantom_log(LOG_LEVEL_DEBUG,
                        "Sent payload (%zd bytes) to %s:%d [sig:%d]",
                        sent, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), idx);
        } else if (verbose) {
            phantom_log(LOG_LEVEL_INFO,
                        "Sent payload to %s:%d",
                        inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
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
                         bool debug, bool verbose, bool quiet)
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
