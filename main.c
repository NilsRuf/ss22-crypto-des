#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "des.h"

#define SETTINGS_OK 0
#define SETTINGS_INVALID 1
#define SETTINGS_HELP 2
#define SETTINGS_CONSUMED 3
#define BUF_SIZE (1 << 16)

#define KEY_STR_DES_LEN 14
#define KEY_STR_TDES_LEN 28

#define ICASE(c) ((c) & ~0x20)
#define TO_HEX(c)                                                                                  \
    ((c) >= '0' && c <= '9'               ? (c) - '0'                                              \
     : ICASE(c) >= 'A' && ICASE(c) <= 'F' ? (ICASE(c) - 'A' + 10)                                  \
                                          : 0xff)

#define OPTION(opt, explanation) "\r\t" opt "\r\n\t\t" explanation "\r\n"
#define DEFAULT_SETTINGS()                                                                         \
    {                                                                                              \
        .des_mode = DES_MODE_DES, .crypt_mode = CRYPT_MODE_ENCRYPT, .in_mode = IN_MODE_STDIO,      \
        .out_mode = OUT_MODE_STDOUT, .key_type = DES_MODE_UNKNOWN, .in = stdin, .out = stdout,     \
    }

typedef int (*des_func_t)(const plain_des_key_t key, const uint8_t *stream, const uint32_t length,
                          uint8_t *cipherstream, const uint32_t ciphercap);
typedef int (*tdes_func_t)(const plain_tdes_key_t key, const uint8_t *stream, const uint32_t length,
                           uint8_t *cipherstream, const uint32_t ciphercap);

static uint8_t in_buf[BUF_SIZE];
static uint8_t out_buf[BUF_SIZE];

typedef enum {
    DES_MODE_UNKNOWN,
    DES_MODE_DES,
    DES_MODE_TDES,
} des_mode_t;

typedef enum {
    CRYPT_MODE_ENCRYPT,
    CRYPT_MODE_DECRYPT,
} crypt_mode_t;

typedef enum {
    IN_MODE_STDIO,
    IN_MODE_FILE,
} in_mode_t;

typedef enum {
    OUT_MODE_STDOUT,
    OUT_MODE_FILE,
} out_mode_t;

typedef struct {
    des_mode_t des_mode;
    crypt_mode_t crypt_mode;
    in_mode_t in_mode;
    out_mode_t out_mode;
    des_mode_t key_type;
    union {
        plain_des_key_t des_key;
        plain_tdes_key_t tdes_key;
    } key;

    FILE *in;
    FILE *out;
} settings_t;

void close_fds(settings_t *settings) {
    if (settings->in != stdin && settings->in != NULL) {
        fclose(settings->in);
    }
    if (settings->out != stdout && settings->out != NULL) {
        fclose(settings->out);
    }
}

int parse_key(char *key, settings_t *settings) {
    int len = strlen(key);
    if (len != KEY_STR_DES_LEN && len != KEY_STR_TDES_LEN) {
        printf("Invalid key length (must be %d or %d not %d).\n", KEY_STR_DES_LEN, KEY_STR_TDES_LEN,
               len);
        return SETTINGS_INVALID;
    }

    settings->key_type = len == KEY_STR_DES_LEN ? DES_MODE_DES : DES_MODE_TDES;

    int key_idx = 0;
    plain_des_key_t current_key = 0;
    for (int i = 0; i < len; i++) {
        uint8_t byte = TO_HEX(key[i]);
        if (byte == 0xff) {
            printf("Invalid hexadecimal key byte: %c.\n", key[i]);
            return SETTINGS_INVALID;
        }
        current_key = (current_key << 4) | (byte & 0xf);
        if (i == KEY_STR_DES_LEN - 1 || i == KEY_STR_TDES_LEN - 1) {
            settings->key.tdes_key[key_idx++] = current_key;
        }
    }

    return SETTINGS_CONSUMED;
}

int parse_option(char *opt, settings_t *settings, int args_left, char **argv_rest) {
    char *opt_part = args_left > 1 ? argv_rest[1] : "\0";

    if (*opt != '-') {
        printf("Expected an option - got %s.\n", opt);
        return SETTINGS_INVALID;
    }

    switch (opt[1]) {
    case 'h':
        return SETTINGS_HELP;
    case 't':
        settings->des_mode = DES_MODE_TDES;
        break;
    case 'k':
        return parse_key(opt_part, settings);
    case 'd':
        settings->crypt_mode = CRYPT_MODE_DECRYPT;
        break;
    case 'f':
        settings->in_mode = IN_MODE_FILE;
        settings->in = fopen(opt_part, "r");
        if (settings->in == NULL) {
            printf("Could not open file %s for reading.\n", opt_part);
            return SETTINGS_INVALID;
        }
        return SETTINGS_CONSUMED;
    case 'o':
        settings->out_mode = OUT_MODE_FILE;
        settings->out = fopen(opt_part, "w");
        if (settings->out == NULL) {
            printf("Could not open file %s for writing.\n", opt_part);
            return SETTINGS_INVALID;
        }
        return SETTINGS_CONSUMED;
    default:
        printf("Unknown setting!\n");
        return SETTINGS_INVALID;
    }

    return SETTINGS_OK;
}

int parse_args(int argc, char **argv, settings_t *settings) {
    int ret = SETTINGS_OK;
    for (int i = 1; i < argc; i++) {
        if (ret == SETTINGS_CONSUMED) {
            ret = SETTINGS_OK;
            continue;
        }

        ret = parse_option(argv[i], settings, argc - i, &argv[i]);
        if (ret != SETTINGS_OK && ret != SETTINGS_CONSUMED) {
            return ret;
        }
    }

    if (settings->key_type == DES_MODE_UNKNOWN) {
        printf("You must specify a key in hexadecimal form using the -k option.\n");
        return SETTINGS_INVALID;
    }

    if (settings->key_type != settings->des_mode) {
        printf("DES mode and key type must match!\n");
        return SETTINGS_INVALID;
    }
    return SETTINGS_OK;
}

void print_help(void) {
    printf("des-example: Options\n" OPTION("-h", "Show this help.") OPTION("-t", "Use triple DES")
               OPTION("-k <key>", "Encryption key in hexadecimal form (e.g. af102210befafd)")
                   OPTION("-d", "Decrypt instead of encrypt")
                       OPTION("-f <file>", "Read input from file")
                           OPTION("-o <file>", "Write output to file"));
}

int main(int argc, char **argv) {
    settings_t settings = DEFAULT_SETTINGS();
    int ret = parse_args(argc, argv, &settings);

    if (ret == SETTINGS_INVALID) {
        printf("Usage: ./des-example -k abcdef01020304 -f message.txt -o message.crypt\n");
        close_fds(&settings);
        return 1;
    }

    if (ret == SETTINGS_HELP) {
        print_help();
        close_fds(&settings);
        return 0;
    }

    des_func_t des_func = settings.des_mode != DES_MODE_DES           ? NULL
                          : settings.crypt_mode == CRYPT_MODE_ENCRYPT ? des_stream_encrypt
                                                                      : des_stream_decrypt;
    tdes_func_t tdes_func = settings.des_mode != DES_MODE_TDES          ? NULL
                            : settings.crypt_mode == CRYPT_MODE_ENCRYPT ? tdes_stream_encrypt
                                                                        : tdes_stream_decrypt;

    size_t count_in;
    while ((count_in = fread(in_buf, 1, BUF_SIZE, settings.in)) > 0) {
        int bytes_written = 0;
        if (des_func != NULL) {
            bytes_written = des_func(settings.key.des_key, in_buf, count_in, out_buf, BUF_SIZE);
        } else {
            bytes_written = tdes_func(settings.key.tdes_key, in_buf, count_in, out_buf, BUF_SIZE);
        }

        if (bytes_written < 0) {
            printf("DES routine failed: %d\n", bytes_written);
        }

        bytes_written = fwrite(out_buf, 1, bytes_written, settings.out);
        if (bytes_written < 0) {
            printf("Failed to write output bytes: %d", bytes_written);
            ret = 1;
            break;
        }
    }

    close_fds(&settings);
    return ret;
}
