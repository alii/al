// External scanner for the one newline-sensitive token the LR grammar cannot
// express: a `-` at the start of a line. The reference parser's "P4" rule
// says a `-` whose leading trivia contains a newline never continues an
// additive chain; it starts a new statement or match arm instead. Only
// negative-literal and unary rules accept this token, so `x - 1` stays a
// subtraction while a fresh-line `-5` arm or statement breaks the chain.

#include "tree_sitter/parser.h"

enum TokenType {
    MINUS_LINE_START,
};

void *tree_sitter_scarlet_external_scanner_create(void) { return NULL; }

void tree_sitter_scarlet_external_scanner_destroy(void *payload) {}

unsigned tree_sitter_scarlet_external_scanner_serialize(void *payload, char *buffer) {
    return 0;
}

void tree_sitter_scarlet_external_scanner_deserialize(void *payload, const char *buffer,
                                                      unsigned length) {}

bool tree_sitter_scarlet_external_scanner_scan(void *payload, TSLexer *lexer,
                                               const bool *valid_symbols) {
    if (!valid_symbols[MINUS_LINE_START]) {
        return false;
    }

    // Runs before whitespace extras are consumed, so the newline (if any)
    // between the previous token and the `-` is still visible here.
    bool saw_newline = false;
    for (;;) {
        int32_t c = lexer->lookahead;
        if (c == '\n') {
            saw_newline = true;
        } else if (c != ' ' && c != '\t' && c != '\r') {
            break;
        }
        lexer->advance(lexer, true);
    }

    if (!saw_newline || lexer->lookahead != '-') {
        return false;
    }

    lexer->advance(lexer, false);
    // `--` is its own (never-parsed) token and `->` is an arrow; neither is a
    // line-start minus.
    if (lexer->lookahead == '-' || lexer->lookahead == '>') {
        return false;
    }

    lexer->mark_end(lexer);
    lexer->result_symbol = MINUS_LINE_START;
    return true;
}
