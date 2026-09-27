/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HD_EXTERNAL_PROTOCOL_VERSION 1U
#define HD_EXTERNAL_LINE_MAX 256U

typedef enum { HdExternalNone, HdExternalInfo, HdExternalStatus, HdExternalError } HdExternalType;
typedef struct {
    HdExternalType type;
    uint32_t protocol;
    uint64_t bytes;
    uint32_t files;
    uint32_t matched;
    uint32_t changed;
    uint32_t missing;
    uint32_t new_files;
    int32_t exit_code;
    char state[16];
    char version[32];
    char target[64];
    char error[64];
} HdExternalMessage;
typedef struct { char line[HD_EXTERNAL_LINE_MAX]; size_t length; bool overflow; } HdExternalDecoder;
typedef void (*HdExternalCallback)(const HdExternalMessage*, void*);

void hd_external_decoder_reset(HdExternalDecoder* decoder);
void hd_external_decoder_feed(HdExternalDecoder* decoder, const uint8_t* data, size_t length, HdExternalCallback callback, void* context);
bool hd_external_parse_line(const char* line, HdExternalMessage* message);
