// TODO:
// - free dynamic arrays
// - comments

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/wait.h>
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

#define streq(s1, s2) (strcmp((s1), (s2)) == 0)

void todo(char *format, ...)
{
    char todo_buf[1024];
    va_list msg_fmt; 
    va_start(msg_fmt, format);
    vsprintf(todo_buf, format, msg_fmt);
    va_end(msg_fmt);
    printf("TODO: %s\n", todo_buf);
}

void error(char *format, ...)
{
    char err_buf[1024];
    va_list msg_fmt; 
    va_start(msg_fmt, format);
    vsprintf(err_buf, format, msg_fmt);
    va_end(msg_fmt);
    printf("ERROR: %s\n", err_buf);
}

void note(char *format, ...)
{
    char note_buf[1024];
    va_list msg_fmt; 
    va_start(msg_fmt, format);
    vsprintf(note_buf, format, msg_fmt);
    va_end(msg_fmt);
    printf("NOTE: %s\n", note_buf);
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
        .col = -1,
        .file_path = strdup(file_path)
    };
}

void loc_print(Location loc) {
    printf("%s:%zu:%zu: ", loc.file_path, loc.row+1, loc.col+1);
}

Location loc_clone(Location loc)
{
    return (Location){
        .row = loc.row,
        .col = loc.col,
        .file_path = strdup(loc.file_path)
    };
}

// NOTE: copied from nob.h @ Tsoding
bool read_entire_file(const char *path, String *source)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)                 return false;
    if (fseek(f, 0, SEEK_END) < 0) { fclose(f); return false; }
    long m = ftell(f);
    if (m < 0)                     { fclose(f); return false; }
    if (fseek(f, 0, SEEK_SET) < 0) { fclose(f); return false; }

    size_t new_count = source->count + m;
    if (new_count > source->capacity) {
        source->items = realloc(source->items, new_count);
        assert(source->items != NULL && "Buy more RAM lool!!");
        source->capacity = new_count;
    }

    fread(source->items + source->count, m, 1, f);
    if (ferror(f)) {
        fclose(f);
        return false;
    }
    source->count = new_count;

    fclose(f);
    return true;
}

typedef enum
{
    TOK_NONE,
    TOK_WORD,
    TOK_INTEGER,
    TOK_L_PAREN,
    TOK_R_PAREN,
    TOK_SEMICOLON,
    TOK_OPERATOR,
    TOK_TYPES_COUNT
} TokenType;

char *toktype_to_str(TokenType t)
{
    static_assert(TOK_TYPES_COUNT == 7 && "Cover all token types in toktype_to_str");
    switch (t)
    {
        case TOK_WORD:      return "Word";
        case TOK_INTEGER:   return "Integer";
        case TOK_L_PAREN:   return "Lparen";
        case TOK_R_PAREN:   return "Rparen";
        case TOK_SEMICOLON: return "Semicolon";
        case TOK_OPERATOR:  return "Operator";
        case TOK_NONE:      return "None";
        default:
            fprintf(stderr, "ERROR: Unknown token type (%d)\n", t);
            exit(1);
    }
}

typedef struct
{
    TokenType type;
    char *text;
    Location loc;
    union { // Token value
        unsigned int val_uint; // TODO: assign it in lexing, non so bene se farlo in lexing o in parsing
    };
} Token;

Token tok_none() { return (Token){ .type = TOK_NONE }; }
void tok_print(Token tok) { printf("<%s, `%s`>", toktype_to_str(tok.type), tok.text); }

typedef struct
{
    Token *items;
    size_t count;
    size_t capacity;
} Tokens;

typedef struct
{
    String *items;
    size_t count;
    size_t capacity;
} ArrayOfStrings;

typedef struct
{
    ArrayOfStrings source;
    Location loc;
} Lexer;

Lexer lex_new(char *file_path)
{
    Lexer lexer = {0};
    String full_source = {0};
    if (!read_entire_file(file_path, &full_source)) {
        fprintf(stderr, "Could not open file `%s`.\n", file_path);
        exit(1);
    }
    int i;
    String line = {0};
    da_for(full_source, i) {
        if (full_source.items[i] == '\n') {
            da_push(&lexer.source, s_from_s(line));
            s_clear(&line);
        } else {
            s_push(&line, full_source.items[i]);
        }
    }
    for (size_t i = 0; i < lexer.source.count; i++) {
        printf("%zu: ", i);
        s_print(lexer.source.items[i]);
        printf("\n");
    }
    lexer.loc = loc_new(file_path);
    da_free(&full_source);
    return lexer;
}

bool lex_can_advance(Lexer *lex)
{
    return (lex->loc.row < lex->source.count &&
            lex->loc.col+1 < lex->source.items[lex->loc.row].count);
}

char lex_get(Lexer *lex)
{
    if (lex->loc.row < lex->source.count && lex->loc.col < lex->source.items[lex->loc.row].count)
        return lex->source.items[lex->loc.row].items[lex->loc.col];
    else return EOF;
}

char lex_peek(Lexer *lex)
{
    if (lex_can_advance(lex)) return lex->source.items[lex->loc.row].items[lex->loc.col+1];
    else return EOF;
}

bool lex_expect(Lexer *lex, char c) { return lex_peek(lex) == c; }

char lex_advance(Lexer *lex)
{
    char c = lex_peek(lex);
    printf("peek = '%c' (%d)\n", c, c);
    if (c == '\n') { // TODO: non ci sono piu' newline
        lex->loc.col = -1;
        lex->loc.row++;
        return lex_advance(lex);
    } else if (isblank(c)) {
        do {
            lex->loc.row++;
        } while (isblank(lex_peek(lex)));
        if (lex_get(lex) == EOF) return EOF;
        else return lex_advance(lex);
    } else if (c == '/') {
        if (lex_expect(lex, '/')) {
            lex->loc.col = -1;
            lex->loc.row++;
            return lex_advance(lex);
        } else {
            loc_print(lex->loc);
            error("Unexpected character '%c'", c);
            note("To comment put two of them: \"//\".");
            exit(1);
        }
    } else {
        lex->loc.col++;
    }
    return c;
}

Tokens lex_lex(Lexer *lex)
{
    static_assert(TOK_TYPES_COUNT == 7, "Cover all token types in lex_lex");
    Tokens tokens = {0};
    String word = s_new_empty();
    char c = lex_advance(lex);
    if (c == EOF) return tokens;
    do {
        Token token = (Token){
            .type = TOK_NONE,
            .loc  = loc_clone(lex->loc)
        };
        if (c == '=') {
            token.text = "=";
            token.type = TOK_OPERATOR;
        } else if (c == '+') {
            token.text = "+";
            token.type = TOK_OPERATOR;
        } else if (c == '(') {
            token.text = "(";
            token.type = TOK_L_PAREN;
        } else if (c == ')') {
            token.text = ")";
            token.type = TOK_R_PAREN;
        } else if (c == ';') {
            token.text = ";";
            token.type = TOK_SEMICOLON;
        } else if (isdigit(c)) {
            s_push(&word, c);
            while (lex_can_advance(lex) && isdigit(c = lex_peek(lex))) {
                s_push(&word, c);
                lex_advance(lex);
            }

            s_push_null(&word);
            token.text = strdup(word.items);
            s_clear(&word);

            token.type = TOK_INTEGER;
        } else if (isalpha(c) || c == '_') {
            s_push(&word, c);
            while (lex_can_advance(lex) && (isdigit(c = lex_peek(lex)) || isalpha(c) || c == '_')) {
                s_push(&word, c);
                lex_advance(lex);
            }

            s_push_null(&word);
            token.text = strdup(word.items);
            s_clear(&word);

            token.type = TOK_WORD;
        } else if (c == 0 || c == EOF) {
            break;
        } else {
            todo("lex '%c'", c);
            exit(1);
        }
        da_push(&tokens, token);
    } while ((c = lex_advance(lex)) != EOF);
    printf("INFO: Lexing took %lf seconds\n", 666.); // TODO
    return tokens;
}

typedef enum
{
    OP_NONE,
    OP_PRINT,
    OP_VAR_DEC,
    OP_VAR_ASSIGN,
    OP_TYPES_COUNT
} OpType;

typedef struct
{
    OpType type;
    union {
        unsigned int val_uint;
        char *val_str;
    };
} Op;

typedef struct
{
    Op *items;
    size_t count;
    size_t capacity;
} Ops;

typedef struct
{
    Tokens tokens;
    size_t i;
} Parser;

Parser parser_new(Tokens tokens)
{
    return (Parser){
        .tokens = tokens,
        .i = 0
    };
}

bool parser_can_advance(Parser *p) { return p->i < p->tokens.count; }

Token parser_get(Parser *p)
{
    if (parser_can_advance(p)) return p->tokens.items[p->i];
    else return tok_none();
}

Token parser_next(Parser *p)
{
    Token t = parser_get(p);
    p->i++;
    return t;
}

bool parser_expect(Parser *p, TokenType type) { return parser_get(p).type == type; }

bool parser_expect_and_match(Parser *p, TokenType type)
{
    if (parser_expect(p, type)) {
        p->i++;
        return true;
    } else return false;
}

void error_expected_token_type(TokenType expected, Token victim, Token from)
{
    if (victim.type == TOK_NONE) {
        loc_print(from.loc);
        error("Expecting `%s`, but got nothing instead.", toktype_to_str(expected));
    } else {
        loc_print(victim.loc);
        error("Expecting `%s`, but got `%s` instead.", toktype_to_str(expected), toktype_to_str(victim.type));
    }
    exit(1);
}

Ops parser_parse(Parser *parser)
{
    Ops ops = {0};
    Op op;
    Token tok;
    static_assert(OP_TYPES_COUNT == 4, "Cover all op types in parser_parse");
    while (parser_can_advance(parser)) {
        tok = parser_next(parser);
        switch (tok.type)
        {
            case TOK_WORD:
            {
                if (streq(tok.text, "print")) {
                    if (!parser_expect_and_match(parser, TOK_L_PAREN)) {
                        error_expected_token_type(TOK_L_PAREN, parser_get(parser), tok);
                    }
                    if (!parser_expect(parser, TOK_INTEGER)) {
                        error_expected_token_type(TOK_INTEGER, parser_get(parser), tok);
                    }
                    Token t_int = parser_next(parser);
                    int n = atoi(t_int.text);
                    if (!parser_expect_and_match(parser, TOK_R_PAREN)) {
                        error_expected_token_type(TOK_R_PAREN, parser_get(parser), tok);
                    }
                    if (!parser_expect_and_match(parser, TOK_SEMICOLON)) {
                        error_expected_token_type(TOK_SEMICOLON, parser_get(parser), tok);
                    }
                    op = (Op){
                        .type = OP_PRINT,
                        .val_uint = n
                    };
                    da_push(&ops, op);
                } else if (streq(tok.text, "var")) {
                    Token t_var_name = parser_get(parser);
                    if (!parser_expect_and_match(parser, TOK_WORD)) {
                        error_expected_token_type(TOK_WORD, parser_get(parser), tok);
                    }
                    if (!parser_expect_and_match(parser, TOK_SEMICOLON)) {
                        error_expected_token_type(TOK_SEMICOLON, parser_get(parser), tok);
                    }
                    op = (Op){
                        .type = OP_VAR_DEC,
                        .val_str = strdup(t_var_name.text)
                    };
                    da_push(&ops, op);
                } else if (parser_expect(parser, TOK_OPERATOR)) {
                    if (!streq(parser_get(parser).text, "=")) { 
                        loc_print(parser_get(parser).loc);
                        error("Expecting operator `=`, but got `%s`.", parser_get(parser).text);
                        exit(1);
                    }
                    parser_expect_and_match(parser, TOK_OPERATOR);
                    //da_push_many(parser_parse_expr(parser)); // TODO
                    Token t_val = parser_get(parser);
                    if (!parser_expect_and_match(parser, TOK_INTEGER)) {
                        error_expected_token_type(TOK_INTEGER, parser_get(parser), tok);
                    }
                    if (!parser_expect_and_match(parser, TOK_SEMICOLON)) {
                        error_expected_token_type(TOK_SEMICOLON, parser_get(parser), tok);
                    }
                    op = (Op){
                        .type = OP_VAR_ASSIGN,
                        .val_uint = atoi(t_val.text)
                    };
                    da_push(&ops, op);
                } else {
                    error("unknown WORD `%s`", tok.text);
                    exit(1);
                }
                break;
            }     
            case TOK_NONE:
            {
                fprintf(stderr, "Unreachable\n");
                exit(1);
            }
            default: 
                todo("parse token type %s.", toktype_to_str(tok.type));
                exit(1);
        }
        printf("INFO: Parsing took %lf seconds\n", 666.); // TODO
    }
    return ops;
}

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
    (void) stream;
    todo("usage");
}

bool run_cmd(char **cmd, int len)
{
    if (cmd == NULL) return false;
    printf("CMD: ");
    for (int i = 0; i < len; i++) {
        printf("%s ", cmd[i]);
    }
    printf("\n");
    switch (fork()) {
        case -1:
            perror("fork");
            exit(EXIT_FAILURE);
        case 0:
            execvp(*cmd, cmd);
            fprintf(stderr, "ERROR: Could not run cmd\n");
            exit(1);
        default:
            int status;
            wait(&status);
            return WEXITSTATUS(status) == 0;
    }
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
    Lexer lexer = lex_new(file_path);
    Tokens tokens = lex_lex(&lexer);

    printf("\nTokens (%zu):\n", tokens.count);
    Token *t;
    da_foreach(tokens, t) {
        loc_print(t->loc);
        tok_print(*t);
        printf("\n");
    }
    printf("\n");
    /// End Lexing

    /// Begin Parsing
    Parser parser = parser_new(tokens);
    Ops ops = parser_parse(&parser);
    /// End Parsing

    /// Begin Generating
    char *output_file = "output.asm"; // TODO: make it have the same name of the file_path and ending with .asm
    FILE *output = fopen(output_file, "w");
    if (output == NULL) {
        fprintf(stderr, "Could not open file `%s`\n", output_file);
        exit(1);
    }

    // TODO: begin file
    fprintf(output, "format ELF64 executable 3\n");
    fprintf(output, "segment readable executable\n");
    fprintf(output, "%s\n", print_definition);
    fprintf(output, "entry start\n");
    fprintf(output, "start:\n");

    int i;
    da_for(ops, i) {
        Op op = ops.items[i];
        static_assert(OP_TYPES_COUNT == 4, "Cover all op types in code generation");
        switch (op.type)
        {
            case OP_PRINT:
            {
                fprintf(output, "    mov rdi, %d\n", op.val_uint);
                fprintf(output, "    call print\n");
                break;
            }
            case OP_VAR_DEC:
            {
                todo("generate OP_VAR_DEC");
                exit(1);
            }
            case OP_VAR_ASSIGN:
            {
                todo("generate OP_VAR_DEC");
                exit(1);
            }
            case OP_NONE:
            default:
                fclose(output);
                fprintf(stderr, "Unreachable\n");
                exit(1);
        }
    }

    // TODO: end file
    fprintf(output, "    mov rax, 60\n");
    fprintf(output, "    mov rdi, 0\n");
    fprintf(output, "    syscall\n");

    fclose(output);
    printf("INFO: Generation took %lf seconds\n", 666.); // TODO
    /// End Generating

    /// Begin Finalizing
    char *fasm_cmd[] = {"fasm", "-m", "524288", "output.asm", NULL}; // TODO: hardcoded
    run_cmd(fasm_cmd, 4);

    char *chmod_cmd[] = {"chmod", "+x", "output", NULL}; // TODO: hardcoded
    run_cmd(chmod_cmd, 3);
    /// End Finalizing

    return 0;
}
