/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef struct HashdeepExternal HashdeepExternal;
typedef struct {
    bool active, connected, running;
    uint32_t protocol, serial_errors, files, matched, changed, missing, new_files;
    uint64_t bytes;
    int32_t exit_code;
    char state[16], version[32], target[64], error[64];
} HdExternalSnapshot;

HashdeepExternal* hd_external_alloc(void);
void hd_external_free(HashdeepExternal* external);
bool hd_external_start(HashdeepExternal* external, uint32_t baudrate);
void hd_external_stop(HashdeepExternal* external);
bool hd_external_run(HashdeepExternal* external, const char* operation);
bool hd_external_cancel(HashdeepExternal* external);
void hd_external_snapshot(HashdeepExternal* external, HdExternalSnapshot* snapshot);
