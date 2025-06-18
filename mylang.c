// TODO:
// - data structures for lexing (lexer)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <assert.h>
#include <ctype.h>
#include "../strings/strings.c"

const char *print_definition = ""            \
    "print:\n"                               \
    "    mov     r9, -3689348814741910323\n" \
    "    sub     rsp, 40\n"                  \
    "    mov     BYTE [rsp+31], 10\n"        \
    "    lea     rcx, [rsp+30]\n"            \
    ".L2:\n"                                 \
    "    mov     rax, rdi\n"                 \
    "    lea     r8, [rsp+32]\n"             \
    "    mul     r9\n"                       \
    "    mov     rax, rdi\n"                 \
    "    sub     r8, rcx\n"                  \
    "    shr     rdx, 3\n"                   \
    "    lea     rsi, [rdx+rdx*4]\n"         \
    "    add     rsi, rsi\n"                 \
    "    sub     rax, rsi\n"                 \
    "    add     eax, 48\n"                  \
    "    mov     BYTE [rcx], al\n"           \
    "    mov     rax, rdi\n"                 \
    "    mov     rdi, rdx\n"                 \
    "    mov     rdx, rcx\n"                 \
    "    sub     rcx, 1\n"                   \
    "    cmp     rax, 9\n"                   \
    "    ja      .L2\n"                      \
    "    lea     rax, [rsp+32]\n"            \
    "    mov     edi, 1\n"                   \
    "    sub     rdx, rax\n"                 \
    "    xor     eax, eax\n"                 \
    "    lea     rsi, [rsp+32+rdx]\n"        \
    "    mov     rdx, r8\n"                  \
    "    mov     rax, 1\n"                   \
    "    syscall\n"                          \
    "    add     rsp, 40\n"                  \
    "    ret\n";

void todo(char *format, ...)
{
    char todo_buf[1024];
    va_list msg_fmt; 
    va_start(msg_fmt, format);
    vsprintf(todo_buf, format, msg_fmt);
    va_end(msg_fmt);
    printf("TODO: %s\n", todo_buf);
    exit(1);
}

typedef enum
{
    NONE,
    WORD,
    INTEGER,
    L_PAREN,
    R_PAREN,
    SEMICOLON,
    BUILTIN,
    TOKEN_TYPE_COUNT
} TokenType;

#define streq(s1, s2) (strcmp((s1), (s2)) == 0)

char *toktype_to_str(TokenType t)
{
    static_assert(TOKEN_TYPE_COUNT == 7 && "Cover all token types in toktype_to_str");
    switch (t)
    {
        case WORD:      return "Word";
        case INTEGER:   return "Integer";
        case L_PAREN:   return "Lparen";
        case R_PAREN:   return "Rparen";
        case SEMICOLON: return "Semicolon";
        case BUILTIN:   return "Builtin";
        case NONE:
        default:
            fprintf(stderr, "ERROR: None or unknown token type (%d)\n", t);
            exit(1);
    }
}

typedef struct
{
    size_t row;
    size_t col;
    char *file_path;
} Location;

Location loc_new(char *file_path)
{
    return (Location){
        .row = 0,
        .col = 0,
        .file_path = strdup(file_path)
    };
}

Location loc_clone(Location loc)
{
    return (Location){
        .row = loc.row,
        .col = loc.col,
        .file_path = strdup(loc.file_path)
    };
}

typedef struct
{
    TokenType type;
    char *text;
    Location loc;
    union { // Token value
        unsigned int val_uint; // TODO: assign it in lexing
    };
} Token;

typedef struct
{
    Token *items;
    size_t count;
    size_t capacity;
} Tokens;

char *shift_arg(int *argc, char ***argv)
{
    if (*argc) {
        char *arg = *argv[0];
        (*argc)--;
        (*argv)++;
        return arg;
    } else {
        return NULL;
    }
}

void usage(FILE *stream, char *program_name)
{
    (void) program_name;
    fprintf(stream, "TODO: usage\n");
}

int main(int argc, char **argv)
{
    char *program_name = shift_arg(&argc, &argv);
    assert((program_name != NULL) && "Program should be provided");

    if (argc < 1) {
        fprintf(stderr, "ERROR: file was not provided\n");
        usage(stderr, program_name);
        exit(1);
    }

    /// Begin Lexing
    char *file_path = shift_arg(&argc, &argv);
    // TODO: check for file extension
    FILE *source_file = fopen(file_path, "r");
    if (source_file == NULL) {
        fprintf(stderr, "ERROR: could not open file `%s`\n", file_path);
        exit(1);
    }
    
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    Location curr_loc = loc_new(file_path);
    String sb = s_new_empty();
    Tokens tokens = {0};
    while ((nread = getline(&line, &len, source_file)) != -1) {
        while (*line != '\n') {
            if (isblank(*line)) {
                line++;
                curr_loc.col++;
                continue;
            }
            Token token = (Token){
                .type = NONE,
                .loc  = loc_clone(curr_loc)
            };
            if (*line == '(') {
                token.text = "(";
                token.type = L_PAREN;
                line++; // TODO: lexer_advance
                curr_loc.col++;
            } else if (*line == ')') {
                token.text = ")";
                token.type = R_PAREN;
                line++;
                curr_loc.col++;
            } else if (*line == ';') {
                token.text = ";";
                token.type = SEMICOLON;
                line++;
                curr_loc.col++;
            } else if (strncmp("print(", line, strlen("print(")) == 0) {
                token.text = "print";
                token.type = BUILTIN;
                line += strlen("print");
                curr_loc.col += strlen("print");
            } else if (isdigit(*line)) {
                do {
                    s_push(&sb, *line);
                    line++;
                    curr_loc.col++;
                } while (isdigit(*line));

                s_push_null(&sb);
                token.text = strdup(sb.items);
                s_clear(&sb);

                token.type = INTEGER;
            } else if (isalpha(*line)) {
                do {
                    s_push(&sb, *line);
                    line++;
                    curr_loc.col++;
                } while (isalpha(*line) || isdigit(*line) || '_' == *line );
                s_push_null(&sb);
                token.text = strdup(sb.items);
                s_clear(&sb);

                token.type = WORD;
            } else {
                todo("lexing %c", *line);
            }
            da_push(&tokens, token);
        }
        curr_loc.row++;
        curr_loc.col = 0;
    }
    fclose(source_file);

    printf("Tokens (%zu):\n", tokens.count);
    Token *t;
    da_foreach(tokens, t) {
        printf("%s:%zu:%zu: <%s, `%s`>\n", t->loc.file_path, t->loc.row+1, t->loc.col+1, toktype_to_str(t->type), t->text);
    }
    /// End Lexing

    /// Begin Parsing
    // TODO: like tokens, make the data structures for Op and Ops (the operations of the intermediate representation)
    int i;
    da_for(tokens, i) {
        Token tok = tokens.items[i];
        switch (tok.type)
        {
            case WORD:
            {
                todo("parse WORD");
                break;
            }     
            case BUILTIN:
            {
                if (streq(tok.text, "print")) {
                    i++;
                    if (tokens.items[i].type != L_PAREN) {
                        todo("report error");
                    }
                    i++;
                    if (tokens.items[i].type != INTEGER) {
                        todo("report error");
                    }
                    int n = atoi(tokens.items[i].text);
                    i++;
                    if (tokens.items[i].type != R_PAREN) {
                        todo("report error");
                    }
                    printf("Op: print(%d)\n", n);
                    i++;
                    if (tokens.items[i].type != SEMICOLON) {
                        todo("report error");
                    }
                } else {
                    todo("parse builtin %s", tok.text);
                }
                break;
            }     
            case NONE:
            {
                fprintf(stderr, "Unreachable\n");
                exit(1);
            }
            default: todo("parse token type %s.", toktype_to_str(tok.type));
        }
        printf("INFO: Parsing done\n");
    }
    /// End Parsing

    /// Begin Generating
    char *output_file = "output.asm"; // TODO: make it have the same name of the file_path and ending with .asm
    FILE *output = fopen(output_file, "w");
    if (output == NULL) {
        fprintf(stderr, "Could not open file `%s`\n", output_file);
        exit(1);
    }
    todo("generate code");
    fclose(output);
    /// End Generating

    return 0;
}
