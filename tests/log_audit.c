/*
 * log_audit.c: Fail-closed audit of production logging call sites
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* section: defines */
#define ARRAY_SIZE(array)	(sizeof(array) / sizeof((array)[0]))
#define AUDIT_ARGUMENT_LIMIT	64
#define AUDIT_MACRO_LIMIT	16
#define AUDIT_TEXT_LIMIT	8192

/* section: types */
typedef struct {
	size_t begin;
	size_t end;
} audit_span;

typedef struct {
	size_t begin;
	size_t end;
} call_argument;

typedef struct {
	const char *definition;
	const char *definition_path;
	size_t format_index;
	const char *name;
} log_symbol;

typedef struct {
	const char *first_expression;
	const char *format;
	const char *path;
} log_exception;

typedef struct {
	size_t call_count;
	size_t config_binding_count;
	size_t config_definition_count;
	size_t config_message_count;
	size_t declaration_count;
	size_t definition_count;
	size_t direct_root_call_count;
	size_t exception_count[7];
	size_t macro_definition_count[6];
	bool quiet;
} audit_state;

/* section: global variables */
static const log_exception log_exceptions[] = {
	{ "base", "%s. Affected: \"%s\"%s", "src/config.c" },
	{ "base", "%s%s", "src/config.c" },
	{ "config_errmsg((conf_error)errno)", "%s%s%s", "src/listener.c" },
	{ "config_errmsg(config_error)", "%s%s", "src/main.c" },
	{ "config_errmsg(config_error)", "%s", "src/main.c" },
	{ "helper_line", "%s", "src/listener_metrics.c" },
	{ "metrics_line", "%s", "src/listener_metrics.c" }
};

static const log_symbol log_symbols[] = {
	{ NULL, NULL, 5, "mksysmsg" },
	{ "#defineMKSYS_LOG(logfile,maxlevel,lvl,...)mksysmsg(MKSYS_PREFIX_ON,logfile,maxlevel,lvl,MKSYS_LINE_END,__VA_ARGS__)", "src/log.h", 3, "MKSYS_LOG" },
	{ "#defineCONNECTION_SETUP_LOG(snapshot,lvl,...)MKSYS_LOG((snapshot)->log_filename,(snapshot)->log_level,lvl,__VA_ARGS__)", "src/connection/setup.h", 2, "CONNECTION_SETUP_LOG" },
	{ "#defineLOG(lvl,...)MKSYS_LOG(MKSYS_NOLOGFILE,MKSYS_LEVEL_ALL,lvl,__VA_ARGS__)", "src/main.c", 1, "LOG" },
	{ "#defineLISTENER_LOG(ctx,lvl,...)MKSYS_LOG((ctx)->log_filename,(ctx)->config->log.level,lvl,__VA_ARGS__)", "src/listener.c", 2, "LISTENER_LOG" },
	{ "#defineLISTENER_LOG_TERMINAL(ctx,lvl,...)MKSYS_LOG(MKSYS_NOLOGFILE,(ctx)->config->log.level,lvl,__VA_ARGS__)", "src/listener.c", 2, "LISTENER_LOG_TERMINAL" }
};

static const char *const reserved_starts[] = { "metrics schema=", "resolver_helper" };

/* section: functions (local) */
static bool audit_error(const audit_state *state, const char *path, size_t offset, const char *message) {
	if (!state->quiet) {
		fprintf(stderr, "%s:%zu: %s\n", path, offset, message);
	}
	return false;
}

static bool ascii_identifier_start(char character) {
	return (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || character == '_';
}

static bool ascii_identifier_continue(char character) {
	return ascii_identifier_start(character) || (character >= '0' && character <= '9');
}

static bool ascii_space(char character) {
	return character == ' ' || character == '\t' || character == '\v' || character == '\f' || character == '\n';
}

static bool path_has_suffix(const char *path, const char *suffix) {
	size_t path_length = strlen(path);
	size_t suffix_length = strlen(suffix);
	return path_length >= suffix_length && strcmp(path + path_length - suffix_length, suffix) == 0 && (path_length == suffix_length || path[path_length - suffix_length - 1U] == '/');
}

static bool prefix_matches(const char *text, size_t text_size, const char *prefix) {
	size_t prefix_size = strlen(prefix);
	return text_size >= prefix_size && memcmp(text, prefix, prefix_size) == 0;
}

static bool source_literal_skip(const char *text, size_t size, size_t *position, audit_state *state, const char *path) {
	char quote = text[*position];
	size_t cursor = *position + 1U;
	while (cursor < size) {
		if (text[cursor] == '\\') {
			if (cursor + 1U >= size) {
				return audit_error(state, path, cursor, "unterminated escape in literal");
			}
			cursor += 2U;
			continue;
		}
		if (text[cursor] == quote) {
			*position = cursor + 1U;
			return true;
		}
		if (text[cursor] == '\n') {
			return audit_error(state, path, cursor, "newline in literal");
		}
		cursor++;
	}
	return audit_error(state, path, *position, "unterminated literal");
}

static bool source_space_skip(const char *text, size_t size, size_t *position, audit_state *state, const char *path) {
	while (*position < size) {
		if (ascii_space(text[*position])) {
			(*position)++;
			continue;
		}
		if (*position + 1U < size && text[*position] == '/' && text[*position + 1U] == '/') {
			*position += 2U;
			while (*position < size && text[*position] != '\n') {
				(*position)++;
			}
			continue;
		}
		if (*position + 1U < size && text[*position] == '/' && text[*position + 1U] == '*') {
			*position += 2U;
			while (*position + 1U < size && !(text[*position] == '*' && text[*position + 1U] == '/')) {
				(*position)++;
			}
			if (*position + 1U >= size) {
				return audit_error(state, path, *position, "unterminated block comment");
			}
			*position += 2U;
			continue;
		}
		break;
	}
	return true;
}

static bool source_normalize(const unsigned char *input, size_t input_size, char **result, size_t *result_size, audit_state *state, const char *path) {
	static const char trigraph_third[] = { '=', '/', '\'', '(', ')', '!', '<', '>', '-' };
	for (size_t index = 0; index < input_size; index++) {
		if (input[index] == '\0') {
			return audit_error(state, path, index, "NUL byte in source input");
		}
		if (index + 2U < input_size && input[index] == '?' && input[index + 1U] == '?') {
			for (size_t third = 0; third < ARRAY_SIZE(trigraph_third); third++) {
				if (input[index + 2U] == (unsigned char)trigraph_third[third]) {
					return audit_error(state, path, index, "C99 trigraph spelling in source input");
				}
			}
		}
	}
	char *newlines = (char *)malloc(input_size + 1U);
	if (newlines == NULL) {
		return audit_error(state, path, 0, "cannot allocate newline-normalization buffer");
	}
	size_t newline_size = 0;
	for (size_t index = 0; index < input_size; index++) {
		if (input[index] == '\r') {
			if (index + 1U >= input_size || input[index + 1U] != '\n') {
				free(newlines);
				return audit_error(state, path, index, "bare CR in source input");
			}
			newlines[newline_size++] = '\n';
			index++;
		} else {
			newlines[newline_size++] = (char)input[index];
		}
	}
	char *normalized = (char *)malloc(newline_size + 1U);
	if (normalized == NULL) {
		free(newlines);
		return audit_error(state, path, 0, "cannot allocate continuation-normalization buffer");
	}
	size_t normalized_size = 0;
	for (size_t index = 0; index < newline_size;) {
		if (newlines[index] != '\\') {
			normalized[normalized_size++] = newlines[index++];
			continue;
		}
		size_t cursor = index + 1U;
		if (cursor < newline_size && newlines[cursor] == '\n') {
			index = cursor + 1U;
			continue;
		}
		while (cursor < newline_size && (newlines[cursor] == ' ' || newlines[cursor] == '\t' || newlines[cursor] == '\v' || newlines[cursor] == '\f')) {
			cursor++;
		}
		if (cursor > index + 1U && cursor < newline_size && newlines[cursor] == '\n') {
			free(newlines);
			free(normalized);
			return audit_error(state, path, index, "nonstandard backslash-whitespace-newline continuation");
		}
		normalized[normalized_size++] = newlines[index++];
	}
	free(newlines);
	normalized[normalized_size] = '\0';
	*result = normalized;
	*result_size = normalized_size;
	return true;
}

static bool source_read(const char *path, unsigned char **content, size_t *size, audit_state *state) {
	FILE *file = fopen(path, "rb");
	if (file == NULL) {
		return audit_error(state, path, 0, "cannot open source input");
	}
	if (fseek(file, 0, SEEK_END) != 0) {
		fclose(file);
		return audit_error(state, path, 0, "cannot seek source input");
	}
	long length = ftell(file);
	if (length < 0 || fseek(file, 0, SEEK_SET) != 0) {
		fclose(file);
		return audit_error(state, path, 0, "cannot size source input");
	}
	unsigned char *buffer = (unsigned char *)malloc((size_t)length + 1U);
	if (buffer == NULL) {
		fclose(file);
		return audit_error(state, path, 0, "cannot allocate source input buffer");
	}
	size_t received = fread(buffer, 1, (size_t)length, file);
	bool closed = fclose(file) == 0;
	if (received != (size_t)length || !closed) {
		free(buffer);
		return audit_error(state, path, received, "cannot read complete source input");
	}
	buffer[received] = '\0';
	*content = buffer;
	*size = received;
	return true;
}

static int symbol_index(const char *text, size_t size) {
	for (size_t index = 0; index < ARRAY_SIZE(log_symbols); index++) {
		if (strlen(log_symbols[index].name) == size && memcmp(text, log_symbols[index].name, size) == 0) {
			return (int)index;
		}
	}
	return -1;
}

static bool code_compact(const char *text, size_t begin, size_t end, char *result, size_t capacity, audit_state *state, const char *path) {
	size_t output = 0;
	for (size_t position = begin; position < end;) {
		if (ascii_space(text[position])) {
			position++;
			continue;
		}
		if (position + 1U < end && text[position] == '/' && text[position + 1U] == '/') {
			break;
		}
		if (position + 1U < end && text[position] == '/' && text[position + 1U] == '*') {
			position += 2U;
			while (position + 1U < end && !(text[position] == '*' && text[position + 1U] == '/')) {
				position++;
			}
			if (position + 1U >= end) {
				return audit_error(state, path, position, "unterminated block comment while compacting code");
			}
			position += 2U;
			continue;
		}
		if (output + 1U >= capacity) {
			return audit_error(state, path, position, "compacted code exceeds audit buffer");
		}
		result[output++] = text[position++];
	}
	result[output] = '\0';
	return true;
}

static bool macro_registered_parse(const char *text, size_t line_begin, size_t line_end, size_t name_begin, size_t name_end, const char *path, audit_span *spans, size_t *span_count, audit_state *state) {
	int index = symbol_index(text + name_begin, name_end - name_begin);
	char compact[AUDIT_TEXT_LIMIT];
	if (index == 0) {
		return audit_error(state, path, name_begin, "logging root cannot be defined as a macro");
	}
	if (index > 0) {
		if (!path_has_suffix(path, log_symbols[index].definition_path)
			|| !code_compact(text, line_begin, line_end, compact, sizeof(compact), state, path) || strcmp(compact, log_symbols[index].definition) != 0) {
			return audit_error(state, path, name_begin, "registered logging macro definition does not match its audited form");
		}
		if (*span_count >= AUDIT_MACRO_LIMIT) {
			return audit_error(state, path, line_begin, "too many registered logging macro definitions");
		}
		spans[*span_count].begin = line_begin;
		spans[*span_count].end = line_end;
		(*span_count)++;
		state->macro_definition_count[index]++;
		return true;
	}
	for (size_t position = name_end; position < line_end;) {
		if (text[position] == '"' || text[position] == '\'') {
			if (!source_literal_skip(text, line_end, &position, state, path)) {
				return false;
			}
			continue;
		}
		if (position + 1U < line_end && text[position] == '/' && (text[position + 1U] == '/' || text[position + 1U] == '*')) {
			size_t skipped = position;
			if (!source_space_skip(text, line_end, &skipped, state, path)) {
				return false;
			}
			position = skipped;
			continue;
		}
		if (ascii_identifier_start(text[position])) {
			size_t identifier_begin = position++;
			while (position < line_end && ascii_identifier_continue(text[position])) {
				position++;
			}
			if (symbol_index(text + identifier_begin, position - identifier_begin) >= 0) {
				return audit_error(state, path, identifier_begin, "unregistered macro references a logging root or wrapper");
			}
			continue;
		}
		position++;
	}
	return true;
}

static bool source_macros_parse(const char *text, size_t size, const char *path, audit_span *spans, size_t *span_count, audit_state *state) {
	for (size_t line_begin = 0; line_begin < size;) {
		size_t line_end = line_begin;
		while (line_end < size && text[line_end] != '\n') {
			line_end++;
		}
		size_t position = line_begin;
		while (position < line_end && (text[position] == ' ' || text[position] == '\t' || text[position] == '\v' || text[position] == '\f')) {
			position++;
		}
		if (position < line_end && text[position] == '#') {
			position++;
			while (position < line_end && ascii_space(text[position])) {
				position++;
			}
			static const char define_word[] = "define";
			if (position + sizeof(define_word) - 1U <= line_end && memcmp(text + position, define_word, sizeof(define_word) - 1U) == 0
				&& (position + sizeof(define_word) - 1U == line_end || !ascii_identifier_continue(text[position + sizeof(define_word) - 1U]))) {
				position += sizeof(define_word) - 1U;
				while (position < line_end && ascii_space(text[position])) {
					position++;
				}
				if (position >= line_end || !ascii_identifier_start(text[position])) {
					return audit_error(state, path, position, "cannot classify macro definition");
				}
				size_t name_begin = position++;
				while (position < line_end && ascii_identifier_continue(text[position])) {
					position++;
				}
				if (!macro_registered_parse(text, line_begin, line_end, name_begin, position, path, spans, span_count, state)) {
					return false;
				}
			}
		}
		line_begin = line_end < size ? line_end + 1U : size;
	}
	return true;
}

static bool position_in_spans(size_t position, const audit_span *spans, size_t span_count, size_t *span_end) {
	for (size_t index = 0; index < span_count; index++) {
		if (position >= spans[index].begin && position < spans[index].end) {
			*span_end = spans[index].end;
			return true;
		}
	}
	return false;
}

static bool call_arguments_parse(const char *text, size_t size, size_t open, call_argument *arguments, size_t *argument_count, size_t *close, audit_state *state, const char *path) {
	size_t begin = open + 1U;
	size_t brace_depth = 0;
	size_t bracket_depth = 0;
	size_t parenthesis_depth = 0;
	*argument_count = 0;
	for (size_t position = begin; position < size;) {
		if (text[position] == '"' || text[position] == '\'') {
			if (!source_literal_skip(text, size, &position, state, path)) {
				return false;
			}
			continue;
		}
		if (position + 1U < size && text[position] == '/' && (text[position + 1U] == '/' || text[position + 1U] == '*')) {
			if (!source_space_skip(text, size, &position, state, path)) {
				return false;
			}
			continue;
		}
		switch (text[position]) {
			case '(':
				parenthesis_depth++;
				break;
			case ')':
				if (parenthesis_depth == 0 && bracket_depth == 0 && brace_depth == 0) {
					if (*argument_count >= AUDIT_ARGUMENT_LIMIT) {
						return audit_error(state, path, position, "too many logging call arguments");
					}
					if (position > begin || *argument_count > 0) {
						arguments[*argument_count].begin = begin;
						arguments[*argument_count].end = position;
						(*argument_count)++;
					}
					*close = position;
					return true;
				}
				if (parenthesis_depth == 0) {
					return audit_error(state, path, position, "unbalanced logging call parenthesis");
				}
				parenthesis_depth--;
				break;
			case '[':
				bracket_depth++;
				break;
			case ']':
				if (bracket_depth == 0) {
					return audit_error(state, path, position, "unbalanced logging call bracket");
				}
				bracket_depth--;
				break;
			case '{':
				brace_depth++;
				break;
			case '}':
				if (brace_depth == 0) {
					return audit_error(state, path, position, "unbalanced logging call brace");
				}
				brace_depth--;
				break;
			case ',':
				if (parenthesis_depth == 0 && bracket_depth == 0 && brace_depth == 0) {
					if (*argument_count >= AUDIT_ARGUMENT_LIMIT) {
						return audit_error(state, path, position, "too many logging call arguments");
					}
					arguments[*argument_count].begin = begin;
					arguments[*argument_count].end = position;
					(*argument_count)++;
					begin = position + 1U;
				}
				break;
		}
		position++;
	}
	return audit_error(state, path, open, "unterminated logging call");
}

static bool decoded_append(char *result, size_t capacity, size_t *size, unsigned int value, audit_state *state, const char *path, size_t position) {
	if (*size + 1U >= capacity || value > UINT8_MAX) {
		return audit_error(state, path, position, "decoded string exceeds audit bounds");
	}
	result[(*size)++] = (char)value;
	return true;
}

static bool string_expression_decode(const char *text, size_t begin, size_t end, char *result, size_t capacity, size_t *result_size, audit_state *state, const char *path) {
	size_t output = 0;
	size_t position = begin;
	bool found = false;
	while (true) {
		if (!source_space_skip(text, end, &position, state, path)) {
			return false;
		}
		if (position >= end) {
			break;
		}
		if (text[position] != '"') {
			return false;
		}
		found = true;
		position++;
		while (position < end && text[position] != '"') {
			unsigned int value = (unsigned char)text[position++];
			if (value == '\n') {
				return audit_error(state, path, position - 1U, "newline in format string literal");
			}
			if (value != '\\') {
				if (!decoded_append(result, capacity, &output, value, state, path, position - 1U)) {
					return false;
				}
				continue;
			}
			if (position >= end) {
				return audit_error(state, path, position, "unterminated format escape");
			}
			char escaped = text[position++];
			switch (escaped) {
				case '\\': value = '\\'; break;
				case '\'': value = '\''; break;
				case '"': value = '"'; break;
				case '?': value = '?'; break;
				case 'a': value = '\a'; break;
				case 'b': value = '\b'; break;
				case 'f': value = '\f'; break;
				case 'n': value = '\n'; break;
				case 'r': value = '\r'; break;
				case 't': value = '\t'; break;
				case 'v': value = '\v'; break;
				case 'x': {
					value = 0;
					size_t digits = 0;
					while (position < end) {
						unsigned int digit;
						if (text[position] >= '0' && text[position] <= '9') {
							digit = (unsigned int)(text[position] - '0');
						} else if (text[position] >= 'a' && text[position] <= 'f') {
							digit = (unsigned int)(text[position] - 'a' + 10);
						} else if (text[position] >= 'A' && text[position] <= 'F') {
							digit = (unsigned int)(text[position] - 'A' + 10);
						} else {
							break;
						}
						if (value > UINT8_MAX / 16U) {
							return audit_error(state, path, position, "hex escape exceeds one byte");
						}
						value = value * 16U + digit;
						position++;
						digits++;
					}
					if (digits == 0) {
						return audit_error(state, path, position, "hex escape has no digits");
					}
					break;
				}
				default:
					if (escaped < '0' || escaped > '7') {
						return audit_error(state, path, position - 1U, "unsupported format escape");
					}
					value = (unsigned int)(escaped - '0');
					for (size_t digit = 1; digit < 3 && position < end && text[position] >= '0' && text[position] <= '7'; digit++) {
						value = value * 8U + (unsigned int)(text[position++] - '0');
					}
					break;
			}
			if (!decoded_append(result, capacity, &output, value, state, path, position - 1U)) {
				return false;
			}
		}
		if (position >= end || text[position] != '"') {
			return audit_error(state, path, position, "unterminated format string literal");
		}
		position++;
	}
	if (!found) {
		return false;
	}
	result[output] = '\0';
	*result_size = output;
	return true;
}

static bool format_message_safe(const char *format, size_t format_size) {
	char literal[AUDIT_TEXT_LIMIT];
	size_t literal_size = 0;
	bool conversion = false;
	for (size_t position = 0; position < format_size && format[position] != '\0' && format[position] != '\n'; position++) {
		if (format[position] == '%' && position + 1U < format_size && format[position + 1U] == '%') {
			literal[literal_size++] = '%';
			position++;
			continue;
		}
		if (format[position] == '%') {
			conversion = true;
			break;
		}
		literal[literal_size++] = format[position];
	}
	for (size_t index = 0; index < ARRAY_SIZE(reserved_starts); index++) {
		if (prefix_matches(literal, literal_size, reserved_starts[index])) {
			return false;
		}
		size_t reserved_size = strlen(reserved_starts[index]);
		if (conversion && literal_size <= reserved_size && memcmp(reserved_starts[index], literal, literal_size) == 0) {
			return false;
		}
	}
	return true;
}

static bool exception_match(const char *path, const char *format, const char *expression, audit_state *state) {
	for (size_t index = 0; index < ARRAY_SIZE(log_exceptions); index++) {
		if (path_has_suffix(path, log_exceptions[index].path) && strcmp(format, log_exceptions[index].format) == 0 && strcmp(expression, log_exceptions[index].first_expression) == 0) {
			state->exception_count[index]++;
			return true;
		}
	}
	return false;
}

static bool logging_call_audit(const char *text, size_t size, size_t open, int symbol, const char *path, audit_state *state) {
	call_argument arguments[AUDIT_ARGUMENT_LIMIT];
	size_t argument_count;
	size_t close;
	if (!call_arguments_parse(text, size, open, arguments, &argument_count, &close, state, path)) {
		return false;
	}
	(void)close;
	if (log_symbols[symbol].format_index >= argument_count) {
		return audit_error(state, path, open, "logging call has no auditable format argument");
	}
	char format[AUDIT_TEXT_LIMIT];
	size_t format_size;
	call_argument format_argument = arguments[log_symbols[symbol].format_index];
	if (!string_expression_decode(text, format_argument.begin, format_argument.end, format, sizeof(format), &format_size, state, path)) {
		return audit_error(state, path, format_argument.begin, "logging format is not a complete string-literal chain");
	}
	if (!format_message_safe(format, format_size)) {
		if (log_symbols[symbol].format_index + 1U >= argument_count) {
			return audit_error(state, path, format_argument.begin, "reserved-prefix logging call has no first format argument");
		}
		char expression[AUDIT_TEXT_LIMIT];
		call_argument first = arguments[log_symbols[symbol].format_index + 1U];
		if (!code_compact(text, first.begin, first.end, expression, sizeof(expression), state, path) || !exception_match(path, format, expression, state)) {
			return audit_error(state, path, format_argument.begin, "logging message can produce a reserved record prefix");
		}
	}
	state->call_count++;
	if (symbol == 0) {
		state->direct_root_call_count++;
	}
	return true;
}

static bool mksysmsg_declaration_audit(const char *text, size_t size, size_t identifier_begin, size_t open, const char *path, bool *classified, audit_state *state) {
	size_t line_begin = identifier_begin;
	while (line_begin > 0 && text[line_begin - 1U] != '\n') {
		line_begin--;
	}
	char prefix[64];
	if (!code_compact(text, line_begin, identifier_begin, prefix, sizeof(prefix), state, path)) {
		return false;
	}
	if (strcmp(prefix, "int") != 0) {
		*classified = false;
		return true;
	}
	call_argument arguments[AUDIT_ARGUMENT_LIMIT];
	size_t argument_count;
	size_t close;
	if (!call_arguments_parse(text, size, open, arguments, &argument_count, &close, state, path)) {
		return false;
	}
	(void)arguments;
	(void)argument_count;
	size_t following = close + 1U;
	if (!source_space_skip(text, size, &following, state, path)) {
		return false;
	}
	if (path_has_suffix(path, "src/log.c") && following < size && text[following] == '{') {
		state->definition_count++;
		*classified = true;
		return true;
	}
	if (path_has_suffix(path, "src/log.h") && following < size && text[following] == ';') {
		state->declaration_count++;
		*classified = true;
		return true;
	}
	return audit_error(state, path, identifier_begin, "mksysmsg declaration or definition appears outside its fixed location");
}

static bool config_message_safe(const char *message, size_t size) {
	for (size_t index = 0; index < ARRAY_SIZE(reserved_starts); index++) {
		size_t reserved_size = strlen(reserved_starts[index]);
		if (prefix_matches(message, size, reserved_starts[index]) || (size < reserved_size && memcmp(reserved_starts[index], message, size) == 0)) {
			return false;
		}
	}
	return true;
}

static bool config_errmsg_body_audit(const char *text, size_t body_begin, size_t body_end, const char *path, audit_state *state) {
	for (size_t position = body_begin; position < body_end;) {
		if (text[position] == '"' || text[position] == '\'') {
			if (!source_literal_skip(text, body_end, &position, state, path)) {
				return false;
			}
			continue;
		}
		if (position + 1U < body_end && text[position] == '/' && (text[position + 1U] == '/' || text[position + 1U] == '*')) {
			if (!source_space_skip(text, body_end, &position, state, path)) {
				return false;
			}
			continue;
		}
		if (!ascii_identifier_start(text[position])) {
			position++;
			continue;
		}
		size_t identifier_begin = position++;
		while (position < body_end && ascii_identifier_continue(text[position])) {
			position++;
		}
		if (position - identifier_begin != 6U || memcmp(text + identifier_begin, "return", 6U) != 0) {
			continue;
		}
		size_t expression_begin = position;
		while (position < body_end && text[position] != ';') {
			if (text[position] == '"' || text[position] == '\'') {
				if (!source_literal_skip(text, body_end, &position, state, path)) {
					return false;
				}
				continue;
			}
			position++;
		}
		if (position >= body_end) {
			return audit_error(state, path, identifier_begin, "unterminated config_errmsg return");
		}
		char compact[AUDIT_TEXT_LIMIT];
		if (!code_compact(text, expression_begin, position, compact, sizeof(compact), state, path)) {
			return false;
		}
		if (strcmp(compact, "NULL") != 0) {
			char message[AUDIT_TEXT_LIMIT];
			size_t message_size;
			if (!string_expression_decode(text, expression_begin, position, message, sizeof(message), &message_size, state, path) || !config_message_safe(message, message_size)) {
				return audit_error(state, path, expression_begin, "config_errmsg return can produce a reserved prefix");
			}
			state->config_message_count++;
		}
		position++;
	}
	return true;
}

static bool config_source_audit(const char *text, size_t size, const char *path, audit_state *state) {
	char *compact = (char *)malloc(size + 1U);
	if (compact == NULL) {
		return audit_error(state, path, 0, "cannot allocate config audit buffer");
	}
	if (!code_compact(text, 0, size, compact, size + 1U, state, path)) {
		free(compact);
		return false;
	}
	const char binding[] = "constchar*constbase=config_errmsg(CONF_ECPROXYDUP);";
	for (char *match = strstr(compact, binding); match != NULL; match = strstr(match + 1, binding)) {
		state->config_binding_count++;
	}
	free(compact);
	for (size_t position = 0; position < size;) {
		if (text[position] == '"' || text[position] == '\'') {
			if (!source_literal_skip(text, size, &position, state, path)) {
				return false;
			}
			continue;
		}
		if (position + 1U < size && text[position] == '/' && (text[position + 1U] == '/' || text[position + 1U] == '*')) {
			if (!source_space_skip(text, size, &position, state, path)) {
				return false;
			}
			continue;
		}
		if (!ascii_identifier_start(text[position])) {
			position++;
			continue;
		}
		size_t identifier_begin = position++;
		while (position < size && ascii_identifier_continue(text[position])) {
			position++;
		}
		if (position - identifier_begin != 13U || memcmp(text + identifier_begin, "config_errmsg", 13U) != 0) {
			continue;
		}
		size_t line_begin = identifier_begin;
		while (line_begin > 0 && text[line_begin - 1U] != '\n') {
			line_begin--;
		}
		char prefix[64];
		if (!code_compact(text, line_begin, identifier_begin, prefix, sizeof(prefix), state, path)) {
			return false;
		}
		if (strcmp(prefix, "constchar*") != 0) {
			continue;
		}
		size_t open = position;
		if (!source_space_skip(text, size, &open, state, path) || open >= size || text[open] != '(') {
			return audit_error(state, path, identifier_begin, "cannot parse config_errmsg definition");
		}
		call_argument arguments[AUDIT_ARGUMENT_LIMIT];
		size_t argument_count;
		size_t close;
		if (!call_arguments_parse(text, size, open, arguments, &argument_count, &close, state, path)) {
			return false;
		}
		(void)arguments;
		(void)argument_count;
		size_t body_begin = close + 1U;
		if (!source_space_skip(text, size, &body_begin, state, path) || body_begin >= size || text[body_begin] != '{') {
			return audit_error(state, path, identifier_begin, "config_errmsg definition has no body");
		}
		size_t depth = 1;
		size_t body_end = body_begin + 1U;
		while (body_end < size && depth > 0) {
			if (text[body_end] == '"' || text[body_end] == '\'') {
				if (!source_literal_skip(text, size, &body_end, state, path)) {
					return false;
				}
				continue;
			}
			if (text[body_end] == '{') {
				depth++;
			} else if (text[body_end] == '}') {
				depth--;
			}
			body_end++;
		}
		if (depth != 0) {
			return audit_error(state, path, body_begin, "unterminated config_errmsg body");
		}
		state->config_definition_count++;
		if (!config_errmsg_body_audit(text, body_begin + 1U, body_end - 1U, path, state)) {
			return false;
		}
		position = body_end;
	}
	return true;
}

static bool source_scan(const char *text, size_t size, const char *path, audit_state *state) {
	audit_span macro_spans[AUDIT_MACRO_LIMIT];
	size_t macro_count = 0;
	if (!source_macros_parse(text, size, path, macro_spans, &macro_count, state)) {
		return false;
	}
	if (path_has_suffix(path, "src/config.c") && !config_source_audit(text, size, path, state)) {
		return false;
	}
	for (size_t position = 0; position < size;) {
		size_t span_end;
		if (position_in_spans(position, macro_spans, macro_count, &span_end)) {
			position = span_end;
			continue;
		}
		if (text[position] == '"' || text[position] == '\'') {
			if (!source_literal_skip(text, size, &position, state, path)) {
				return false;
			}
			continue;
		}
		if (position + 1U < size && text[position] == '/' && (text[position + 1U] == '/' || text[position + 1U] == '*')) {
			if (!source_space_skip(text, size, &position, state, path)) {
				return false;
			}
			continue;
		}
		if ((position + 1U < size && text[position] == '#' && text[position + 1U] == '#') || (position + 3U < size && memcmp(text + position, "%:%:", 4U) == 0)) {
			return audit_error(state, path, position, "token-pasting operator in production source");
		}
		if (!ascii_identifier_start(text[position])) {
			position++;
			continue;
		}
		size_t identifier_begin = position++;
		while (position < size && ascii_identifier_continue(text[position])) {
			position++;
		}
		int symbol = symbol_index(text + identifier_begin, position - identifier_begin);
		if (symbol < 0) {
			continue;
		}
		size_t following = position;
		if (!source_space_skip(text, size, &following, state, path)) {
			return false;
		}
		if (following >= size || text[following] != '(') {
			return audit_error(state, path, identifier_begin, "unclassified logging identifier occurrence");
		}
		if (symbol == 0) {
			bool classified;
			if (!mksysmsg_declaration_audit(text, size, identifier_begin, following, path, &classified, state)) {
				return false;
			}
			if (classified) {
				continue;
			}
		}
		if (!logging_call_audit(text, size, following, symbol, path, state)) {
			return false;
		}
	}
	return true;
}

static bool source_bytes_audit(const unsigned char *input, size_t input_size, const char *path, audit_state *state) {
	char *normalized;
	size_t normalized_size;
	if (!source_normalize(input, input_size, &normalized, &normalized_size, state, path)) {
		return false;
	}
	bool result = source_scan(normalized, normalized_size, path, state);
	free(normalized);
	return result;
}

static bool expect_bytes_path(const unsigned char *input, size_t input_size, const char *path, bool expected) {
	audit_state state;
	memset(&state, 0, sizeof(state));
	state.quiet = true;
	return source_bytes_audit(input, input_size, path, &state) == expected;
}

static bool expect_bytes(const unsigned char *input, size_t input_size, bool expected) {
	return expect_bytes_path(input, input_size, "fixture.c", expected);
}

static bool self_tests(void) {
	static const unsigned char safe_call[] = "MKSYS_LOG(a, b, c, \"safe %s\", value);\n";
	static const unsigned char safe_zero_call_wrapper[] = "#define LISTENER_LOG_TERMINAL(ctx, lvl, ...) MKSYS_LOG(MKSYS_NOLOGFILE, (ctx)->config->log.level, lvl, __VA_ARGS__)\n";
	static const unsigned char unsafe_alias[] = "#define MYLOG MKSYS_LOG\n";
	static const unsigned char unsafe_digraph[] = "int value = a %:%: b;\n";
	static const unsigned char unsafe_nonliteral[] = "MKSYS_LOG(a, b, c, format);\n";
	static const unsigned char unsafe_pointer[] = "void *pointer = mksysmsg;\n";
	static const unsigned char unsafe_split_paste[] = "#\\\n#\n";
	static const unsigned char unsafe_token_paste[] = "#define CAT(a, b) a ## b\nCAT(MKSYS_L, OG)(a, b, c, \"safe\");\n";
	static const unsigned char unsafe_value[] = "consume(MKSYS_LOG);\n";
	static const unsigned char unsafe_wrapper[] = "#define MYLOG(...) MKSYS_LOG(__VA_ARGS__)\n";
	static const unsigned char strict_splice[] = "MKSYS_\\\nLOG(a, b, c, \"safe\");\n";
	static const unsigned char strict_splice_crlf[] = "MKSYS_\\\r\nLOG(a, b, c, \"safe\");\r\n";
	static const unsigned char crlf[] = "MKSYS_LOG(a, b, c, \"safe\");\r\n";
	static const unsigned char bare_cr[] = "MKSYS_LOG(a, b, c, \"safe\");\r";
	static const unsigned char extended_space[] = "MKSYS_\\ \nLOG(a, b, c, \"safe\");\n";
	static const unsigned char extended_tab[] = "MKSYS_\\\t\nLOG(a, b, c, \"safe\");\n";
	static const unsigned char extended_vertical_tab[] = "MKSYS_\\\v\nLOG(a, b, c, \"safe\");\n";
	static const unsigned char extended_form_feed[] = "MKSYS_\\\f\nLOG(a, b, c, \"safe\");\n";
	static const unsigned char nul_begin[] = { 0, 'x' };
	static const unsigned char nul_middle[] = { 'x', 0, '#', '#', '\n' };
	static const unsigned char nul_end[] = { 'x', 0 };
	if (!expect_bytes(safe_call, sizeof(safe_call) - 1U, true)
		|| !expect_bytes_path(safe_zero_call_wrapper, sizeof(safe_zero_call_wrapper) - 1U, "src/listener.c", true)
		|| !expect_bytes(strict_splice, sizeof(strict_splice) - 1U, true) || !expect_bytes(strict_splice_crlf, sizeof(strict_splice_crlf) - 1U, true)
		|| !expect_bytes(crlf, sizeof(crlf) - 1U, true) || !expect_bytes(unsafe_alias, sizeof(unsafe_alias) - 1U, false)
		|| !expect_bytes(unsafe_digraph, sizeof(unsafe_digraph) - 1U, false) || !expect_bytes(unsafe_pointer, sizeof(unsafe_pointer) - 1U, false)
		|| !expect_bytes(unsafe_nonliteral, sizeof(unsafe_nonliteral) - 1U, false) || !expect_bytes(unsafe_split_paste, sizeof(unsafe_split_paste) - 1U, false)
		|| !expect_bytes(unsafe_token_paste, sizeof(unsafe_token_paste) - 1U, false) || !expect_bytes(unsafe_value, sizeof(unsafe_value) - 1U, false)
		|| !expect_bytes(unsafe_wrapper, sizeof(unsafe_wrapper) - 1U, false)
		|| !expect_bytes(bare_cr, sizeof(bare_cr) - 1U, false) || !expect_bytes(extended_space, sizeof(extended_space) - 1U, false)
		|| !expect_bytes(extended_tab, sizeof(extended_tab) - 1U, false) || !expect_bytes(extended_vertical_tab, sizeof(extended_vertical_tab) - 1U, false)
		|| !expect_bytes(extended_form_feed, sizeof(extended_form_feed) - 1U, false) || !expect_bytes(nul_begin, sizeof(nul_begin), false)
		|| !expect_bytes(nul_middle, sizeof(nul_middle), false) || !expect_bytes(nul_end, sizeof(nul_end), false)) {
		fprintf(stderr, "log audit byte/source fixture failed\n");
		return false;
	}
	static const char trigraph_third[] = { '=', '/', '\'', '(', ')', '!', '<', '>', '-' };
	for (size_t index = 0; index < ARRAY_SIZE(trigraph_third); index++) {
		unsigned char trigraph[] = { '/', '*', '?', '?', (unsigned char)trigraph_third[index], '*', '/' };
		if (!expect_bytes(trigraph, sizeof(trigraph), false)) {
			fprintf(stderr, "log audit trigraph fixture failed at index %zu\n", index);
			return false;
		}
	}
	audit_state state;
	memset(&state, 0, sizeof(state));
	state.quiet = true;
	const char safe_formats[][64] = { "\"ordinary %s\"", "\"ordinary \" \"%s\"", "\"metrics \"", "\"progress %% %s\"", "\"safe\\nmetrics schema=1\"" };
	for (size_t index = 0; index < ARRAY_SIZE(safe_formats); index++) {
		char decoded[128];
		size_t decoded_size;
		if (!string_expression_decode(safe_formats[index], 0, strlen(safe_formats[index]), decoded, sizeof(decoded), &decoded_size, &state, "format-fixture")
			|| !format_message_safe(decoded, decoded_size)) {
			fprintf(stderr, "log audit safe format fixture failed at index %zu\n", index);
			return false;
		}
	}
	const char unsafe_formats[][64] = { "\"%s\"", "\"metrics schema=1\"", "\"metrics %s\"", "\"resolver_%s\"" };
	for (size_t index = 0; index < ARRAY_SIZE(unsafe_formats); index++) {
		char decoded[128];
		size_t decoded_size;
		if (!string_expression_decode(unsafe_formats[index], 0, strlen(unsafe_formats[index]), decoded, sizeof(decoded), &decoded_size, &state, "format-fixture")
			|| format_message_safe(decoded, decoded_size)) {
			fprintf(stderr, "log audit unsafe format fixture failed at index %zu\n", index);
			return false;
		}
	}
	if (!config_message_safe("ordinary", 8U) || config_message_safe("metrics schema=1", 16U) || config_message_safe("resolver_", 9U)) {
		fprintf(stderr, "log audit config_errmsg provenance fixture failed\n");
		return false;
	}
	return true;
}

static bool audit_finalize(const audit_state *state) {
	if (state->call_count == 0 || state->definition_count != 1 || state->declaration_count != 1 || state->direct_root_call_count != 6
		|| state->config_binding_count != 1 || state->config_definition_count != 1 || state->config_message_count == 0) {
		fprintf(stderr, "log audit inventory mismatch: calls=%zu root_calls=%zu definitions=%zu declarations=%zu binding=%zu config_definition=%zu config_messages=%zu\n",
			state->call_count, state->direct_root_call_count, state->definition_count, state->declaration_count, state->config_binding_count, state->config_definition_count,
			state->config_message_count);
		return false;
	}
	for (size_t index = 1; index < ARRAY_SIZE(log_symbols); index++) {
		if (state->macro_definition_count[index] != 1) {
			fprintf(stderr, "log audit macro definition mismatch for %s: %zu\n",
				log_symbols[index].name, state->macro_definition_count[index]);
			return false;
		}
	}
	for (size_t index = 0; index < ARRAY_SIZE(log_exceptions); index++) {
		if (state->exception_count[index] != 1) {
			fprintf(stderr, "log audit exception mismatch for %s/%s: %zu\n", log_exceptions[index].path,
				log_exceptions[index].format, state->exception_count[index]);
			return false;
		}
	}
	return true;
}

/* section: functions (entry point) */
int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "log audit received no production source paths\n");
		return EXIT_FAILURE;
	}
	if (!self_tests()) {
		return EXIT_FAILURE;
	}
	audit_state state;
	memset(&state, 0, sizeof(state));
	for (int index = 1; index < argc; index++) {
		unsigned char *input;
		size_t input_size;
		if (!source_read(argv[index], &input, &input_size, &state)) {
			return EXIT_FAILURE;
		}
		bool valid = source_bytes_audit(input, input_size, argv[index], &state);
		free(input);
		if (!valid) {
			return EXIT_FAILURE;
		}
	}
	return audit_finalize(&state) ? EXIT_SUCCESS : EXIT_FAILURE;
}
