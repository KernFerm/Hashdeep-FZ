/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <furi.h>
#include <storage/storage.h>

#define HD_PATH_MAX 255U
#define HD_DIGEST_HEX_MAX 64U
#define HD_IO_CHUNK 1024U

typedef enum {
    HdAlgorithmMd5,
    HdAlgorithmSha1,
    HdAlgorithmSha256,
} HdAlgorithm;

typedef enum {
    HdStatusOk,
    HdStatusCancelled,
    HdStatusInvalid,
    HdStatusOpenError,
    HdStatusReadError,
    HdStatusWriteError,
    HdStatusMalformed,
    HdStatusUnsupported,
    HdStatusMissing,
    HdStatusTooLarge,
} HdStatus;

typedef struct {
    volatile bool* cancel;
    FuriMutex* mutex;
    volatile uint64_t bytes;
    volatile uint32_t files;
    volatile uint32_t errors;
    volatile uint32_t matched;
    volatile uint32_t changed;
    volatile uint32_t missing;
    volatile uint32_t new_files;
    volatile uint32_t malformed;
    char error_path[HD_PATH_MAX + 1U];
} HdProgress;

typedef struct {
    uint64_t size;
    bool has_md5;
    bool has_sha1;
    bool has_sha256;
    char md5[33];
    char sha1[41];
    char sha256[65];
    char path[HD_PATH_MAX + 1U];
} HdManifestEntry;

const char* hd_algorithm_name(HdAlgorithm algorithm);
size_t hd_algorithm_hex_length(HdAlgorithm algorithm);
bool hd_digest_valid(HdAlgorithm algorithm, const char* digest);
HdStatus hd_hash_file(Storage* storage, const char* path, HdAlgorithm algorithm, char* hex, HdProgress* progress);
HdStatus hd_hash_file_all(Storage* storage, const char* path, HdManifestEntry* result, HdProgress* progress);
HdStatus hd_create_manifest(Storage* storage, const char* root, const char* output, HdProgress* progress);
HdStatus hd_audit_manifest(Storage* storage, const char* manifest, HdProgress* progress);
HdStatus hd_verify_file(Storage* storage, const char* path, HdAlgorithm algorithm, const char* expected, char* actual, bool* match, HdProgress* progress);
bool hd_self_test(void);
