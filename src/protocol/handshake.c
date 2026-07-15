/*
 * protocol/handshake.c: Functions for modern protocol handshake (13w41a and later)
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../basic.h"

#include "handshake.h"

size_t make_message(void *dst, const void *src) {
	void *tmp, *ptr_dst, *ptr_tmp;
	size_t dst_length, payload_length, src_length;
	tmp = calloc(1, BUFSIZ);
	ptr_tmp = int2varint(0, tmp);
	src_length = strlen(src);
	ptr_tmp = int2varint(src_length, ptr_tmp);
	memcpy(ptr_tmp, src, src_length);
	ptr_tmp += src_length;
	dst_length = ptr_tmp - tmp;
	ptr_dst = int2varint(dst_length, dst);
	memcpy(ptr_dst, tmp, dst_length);
	ptr_dst += dst_length;
	payload_length = ptr_dst - dst;
	free(tmp);
	return payload_length;
}

size_t make_kickreason(void *dst, const void *src) {
	void *input;
	size_t payload_length;
	input = calloc(1, BUFSIZ);
	sprintf(input, "{\"extra\":[{\"text\":\"%s\"}],\"text\":\"\"}", (char *)src);
	payload_length = make_message(dst, input);
	free(input);
	return payload_length;
}

size_t make_motd(void *dst, const void *src, varint_t ver) {
	void *input;
	size_t payload_length;
	input = calloc(1, BUFSIZ);
	sprintf(input, "{\"version\":{\"name\":\"\",\"protocol\":%u},\"players\":{\"max\":0,\"online\":0,\"sample\":[]},\"description\":{\"text\":\"%s\"}}", ver, (char *)src);
	payload_length = make_message(dst, input);
	free(input);
	return payload_length;
}

p_handshake packet_read(void *src, void *end) {
	p_handshake result;
	void *part2_start;
	varint_t address_length, size_part1, size_part2, username_length;
	memset(&result, 0, sizeof(result));
	src = varint2int(src, &size_part1);
	if (src == NULL) {
		goto cleanup;
	}
	src = varint2int(src, &result.id_part1);
	if (src == NULL) {
		goto cleanup;
	}
	src = varint2int(src, &result.version);
	if (src == NULL) {
		goto cleanup;
	}
	src = varint2int(src, &address_length);
	if (src == NULL) {
		goto cleanup;
	}
	if (address_length > PROTOHANDSHAKE_ADDRESSMAXLEN) {
		goto cleanup;
	}
	if (address_length == 0) {
		goto cleanup;
	}
	if ((char *)src + address_length > (char *)end) {
		goto cleanup;
	}
	if ((*((char *)(src + address_length - 1))) == '\0') {
		result.address = malloc(strlen(src) + 1);
		if (result.address == NULL) {
			goto cleanup;
		}
		strcpy(result.address, src);
		src += strlen(src);
		if (memcmp(src, "\0FML\0", 5) == 0) {
			result.version_fml = 1;
			src += 5;
		} else if (memcmp(src, "\0FML2\0", 6) == 0) {
			result.version_fml = 2;
			src += 6;
		}
	} else {
		result.version_fml = 0;
		result.address = calloc(1, address_length + 1);
		if (result.address == NULL) {
			goto cleanup;
		}
		memcpy(result.address, src, address_length);
		src += address_length;
	}
	if ((char *)src + sizeof(in_port_t) > (char *)end) {
		goto cleanup;
	}
	result.port = ntohs(*((in_port_t *)src));
	src = (void *)(((in_port_t *)src) + 1);
	src = varint2int(src, &result.nextstate);
	if (src == NULL) {
		goto cleanup;
	}
	if ((result.nextstate == CLIENT_INTENT_LOGIN) || (result.nextstate == CLIENT_INTENT_TRANSFER)) {
		part2_start = src = varint2int(src, &size_part2);
		if (src == NULL) {
			goto cleanup;
		}
		src = varint2int(src, &result.id_part2);
		if (src == NULL) {
			goto cleanup;
		}
		src = varint2int(src, &username_length);
		if (src == NULL) {
			goto cleanup;
		}
		if (username_length > PROTOHANDSHAKE_USERNAMEMAXLEN) {
			goto cleanup;
		}
		if ((char *)src + username_length > (char *)end) {
			goto cleanup;
		}
		result.username = calloc(1, username_length + 1);
		if (result.username == NULL) {
			goto cleanup;
		}
		memcpy(result.username, src, username_length);
		src += username_length;
		if ((size_t)(src - part2_start) > size_part2) {
			goto cleanup;
		}
		result.signature_data_length = size_part2 - (src - part2_start);
		if (result.signature_data_length) {
			if (((result.version <= PVERDB_R_1_20_1) || ((result.version & PVERDB_SNAPMASK) <= PVERDB_S_1_20_1_RC1)) && (*((char *)src) == 1)) {
				result.signature_data_length--;
				src++;
			}
			if ((char *)src + result.signature_data_length > (char *)end) {
				goto cleanup;
			}
			result.signature_data = malloc(result.signature_data_length);
			if (result.signature_data == NULL) {
				goto cleanup;
			}
			memcpy(result.signature_data, src, result.signature_data_length);
			src += result.signature_data_length;
		} else {
			result.signature_data_length = 0;
		}
	}
	return result;
cleanup:
	packet_destroy(result);
	memset(&result, 0, sizeof(result));
	return result;
}

size_t packet_write(void *dst, const p_handshake src) {
	void *part1, *part2, *ptr_dst, *ptr_part1, *ptr_part2;
	size_t address_length, address_length_pure, size, size_part1, size_part2, username_length;
	ptr_part1 = part1 = calloc(1, BUFSIZ);
	ptr_part2 = part2 = calloc(1, BUFSIZ);
	ptr_dst = dst;
	ptr_part1 = int2varint(src.id_part1, ptr_part1);
	ptr_part1 = int2varint(src.version, ptr_part1);
	address_length = address_length_pure = strlen(src.address);
	if (src.version_fml == 1) {
		address_length += 5;
	} else if (src.version_fml == 2) {
		address_length += 6;
	}
	ptr_part1 = int2varint(address_length, ptr_part1);
	memcpy(ptr_part1, src.address, address_length_pure);
	if (src.version_fml == 1) {
		memcpy(ptr_part1 + address_length_pure, "\0FML\0", 5);
	} else if (src.version_fml == 2) {
		memcpy(ptr_part1 + address_length_pure, "\0FML2\0", 6);
	}
	ptr_part1 += address_length;
	*((in_port_t *)ptr_part1) = htons(src.port);
	ptr_part1 = (void *)(((in_port_t *)ptr_part1) + 1);
	ptr_part1 = int2varint(src.nextstate, ptr_part1);
	size_part1 = ptr_part1 - part1;
	ptr_part2 = int2varint(src.id_part2, ptr_part2);
	if ((src.nextstate == CLIENT_INTENT_LOGIN) || (src.nextstate == CLIENT_INTENT_TRANSFER)) {
		username_length = strlen(src.username);
		ptr_part2 = int2varint(username_length, ptr_part2);
		memcpy(ptr_part2, src.username, username_length);
		ptr_part2 += username_length;
		if (src.signature_data_length) {
			if ((src.version <= PVERDB_R_1_20_1) || ((src.version & PVERDB_SNAPMASK) <= PVERDB_S_1_20_1_RC1)) {
				ptr_part2 = int2varint(1, ptr_part2);
			}
			memcpy(ptr_part2, src.signature_data, src.signature_data_length);
			ptr_part2 += src.signature_data_length;
		}
	}
	size_part2 = ptr_part2 - part2;
	ptr_dst = int2varint(size_part1, ptr_dst);
	memcpy(ptr_dst, part1, size_part1);
	ptr_dst += size_part1;
	ptr_dst = int2varint(size_part2, ptr_dst);
	memcpy(ptr_dst, part2, size_part2);
	ptr_dst += size_part2;
	size = ptr_dst - dst;
	free(part1);
	free(part2);
	return size;
}

void packet_destroy(p_handshake object) {
	if (object.address != NULL) {
		free(object.address);
		object.address = NULL;
	}
	if (object.signature_data != NULL) {
		free(object.signature_data);
		object.signature_data = NULL;
	}
	if (object.username != NULL) {
		free(object.username);
		object.username = NULL;
	}
}
