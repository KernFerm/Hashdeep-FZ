/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Hashdeep-compatible streaming and HASHDEEP-1.0 manifest handling. */
#include "hashdeep_engine.h"

#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    mbedtls_md5_context md5;
    mbedtls_sha1_context sha1;
    mbedtls_sha256_context sha256;
} HdAllContexts;

#define HD_NATIVE_REPORT_PATH "/ext/hashdeep_fz/report.txt"
#define HD_NATIVE_REPORT_PARTIAL "/ext/hashdeep_fz/report.txt.partial"
#define HD_NATIVE_REPORT_BACKUP  "/ext/hashdeep_fz/report.txt.backup"
#define HD_AUDIT_MAX_ENTRIES 1024U
#define HD_AUDIT_PATH_BYTES  32768U

typedef struct {
    uint32_t hash;
    uint16_t offset;
} HdPathIndexItem;

typedef struct {
    HdPathIndexItem* items;
    char* paths;
    uint16_t count;
    uint16_t used;
    bool sorted;
} HdPathIndex;

static uint32_t hd_path_hash(const char* path) {
    uint32_t hash = 2166136261U;
    while(*path) {
        hash ^= (uint8_t)*path++;
        hash *= 16777619U;
    }
    return hash;
}

static bool hd_path_index_init(HdPathIndex* index) {
    memset(index, 0, sizeof(*index));
    index->items = malloc(sizeof(HdPathIndexItem) * HD_AUDIT_MAX_ENTRIES);
    index->paths = malloc(HD_AUDIT_PATH_BYTES);
    if(!index->items || !index->paths) {
        free(index->items);
        free(index->paths);
        memset(index, 0, sizeof(*index));
        return false;
    }
    return true;
}

static void hd_path_index_free(HdPathIndex* index) {
    free(index->items);
    free(index->paths);
    memset(index, 0, sizeof(*index));
}

static HdStatus hd_path_index_add(HdPathIndex* index, const char* path, bool* duplicate) {
    *duplicate = false;
    for(uint16_t i = 0U; i < index->count; i++) {
        if(!strcmp(index->paths + index->items[i].offset, path)) {
            *duplicate = true;
            return HdStatusOk;
        }
    }
    size_t length = strlen(path) + 1U;
    if(index->count >= HD_AUDIT_MAX_ENTRIES ||
       (size_t)index->used + length > HD_AUDIT_PATH_BYTES) return HdStatusTooLarge;
    uint16_t offset = index->used;
    memcpy(index->paths + offset, path, length);
    index->items[index->count].hash = hd_path_hash(path);
    index->items[index->count].offset = offset;
    index->count++;
    index->used = (uint16_t)(index->used + length);
    return HdStatusOk;
}

static void hd_path_index_sort(HdPathIndex* index) {
    for(uint16_t i = 1U; i < index->count; i++) {
        HdPathIndexItem value = index->items[i];
        uint16_t position = i;
        while(position > 0U) {
            HdPathIndexItem previous = index->items[position - 1U];
            if(previous.hash < value.hash ||
               (previous.hash == value.hash && previous.offset <= value.offset)) break;
            index->items[position] = previous;
            position--;
        }
        index->items[position] = value;
    }
    index->sorted = true;
}

static bool hd_path_index_contains(const HdPathIndex* index, const char* path) {
    if(!index->sorted) return false;
    uint32_t hash = hd_path_hash(path);
    size_t low = 0U, high = index->count;
    while(low < high) {
        size_t middle = low + (high - low) / 2U;
        if(index->items[middle].hash < hash) low = middle + 1U;
        else high = middle;
    }
    while(low < index->count && index->items[low].hash == hash) {
        if(!strcmp(index->paths + index->items[low].offset, path)) return true;
        low++;
    }
    return false;
}

static void hd_progress_add_u32(HdProgress* progress, volatile uint32_t* field, uint32_t value) {
    if(!progress) return;
    if(progress->mutex) furi_mutex_acquire(progress->mutex, FuriWaitForever);
    *field += value;
    if(progress->mutex) furi_mutex_release(progress->mutex);
}

static void hd_progress_add_bytes(HdProgress* progress, uint64_t value) {
    if(!progress) return;
    if(progress->mutex) furi_mutex_acquire(progress->mutex, FuriWaitForever);
    progress->bytes += value;
    if(progress->mutex) furi_mutex_release(progress->mutex);
}

static void hd_progress_error_path(HdProgress* progress, const char* path) {
    if(!progress || !path) return;
    if(progress->mutex) furi_mutex_acquire(progress->mutex, FuriWaitForever);
    snprintf(progress->error_path, sizeof(progress->error_path), "%s", path);
    if(progress->mutex) furi_mutex_release(progress->mutex);
}

static bool hd_is_app_report_path(const char* path) {
    return !strcmp(path, HD_NATIVE_REPORT_PATH) ||
           !strcmp(path, HD_NATIVE_REPORT_PARTIAL) ||
           !strcmp(path, HD_NATIVE_REPORT_BACKUP);
}

static void hd_hex(const uint8_t* bytes, size_t length, char* output) {
    static const char digits[] = "0123456789abcdef";
    for(size_t i = 0; i < length; i++) {
        output[i * 2U] = digits[bytes[i] >> 4U];
        output[i * 2U + 1U] = digits[bytes[i] & 15U];
    }
    output[length * 2U] = '\0';
}

static bool hd_cancelled(const HdProgress* progress) {
    return progress && progress->cancel && *progress->cancel;
}

static bool hd_path_is_safe_ext(const char* path) {
    if(!path || strncmp(path, "/ext", 4U) || (path[4] && path[4] != '/') ||
       strlen(path) > HD_PATH_MAX || strstr(path, "..") || strstr(path, "//")) return false;
    for(const char* cursor = path; *cursor; cursor++) {
        unsigned char c = (unsigned char)*cursor;
        if(c < 0x20U || c > 0x7EU || c == '\\' || strchr(":*?\"<>|", c)) return false;
    }
    return true;
}

static bool hd_path_kind(Storage* storage, const char* path, bool* is_directory) {
    FileInfo info;
    if(storage_common_stat(storage, path, &info) == FSE_OK) {
        *is_directory = (info.flags & FSF_DIRECTORY) != 0U;
        return true;
    }
    File* probe = storage_file_alloc(storage);
    bool opened = storage_dir_open(probe, path);
    if(opened) storage_dir_close(probe);
    storage_file_free(probe);
    if(opened) {
        *is_directory = true;
        return true;
    }
    return false;
}

const char* hd_algorithm_name(HdAlgorithm algorithm) {
    if(algorithm == HdAlgorithmMd5) return "md5";
    if(algorithm == HdAlgorithmSha1) return "sha1";
    return "sha256";
}

size_t hd_algorithm_hex_length(HdAlgorithm algorithm) {
    if(algorithm == HdAlgorithmMd5) return 32U;
    if(algorithm == HdAlgorithmSha1) return 40U;
    return 64U;
}

bool hd_digest_valid(HdAlgorithm algorithm, const char* digest) {
    if(!digest) return false;
    size_t expected = hd_algorithm_hex_length(algorithm);
    for(size_t i = 0; i < expected; i++) {
        char c = digest[i];
        if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return digest[expected] == '\0';
}

static bool hd_hex_equal(const char* left, const char* right, size_t length) {
    for(size_t i = 0U; i < length; i++) {
        char a = left[i], b = right[i];
        if(a >= 'A' && a <= 'F') a = (char)(a + ('a' - 'A'));
        if(b >= 'A' && b <= 'F') b = (char)(b + ('a' - 'A'));
        if(a != b) return false;
    }
    return true;
}

static bool hd_all_start(HdAllContexts* contexts) {
    mbedtls_md5_init(&contexts->md5);
    mbedtls_sha1_init(&contexts->sha1);
    mbedtls_sha256_init(&contexts->sha256);
    return mbedtls_md5_starts(&contexts->md5) == 0 &&
           mbedtls_sha1_starts(&contexts->sha1) == 0 &&
           mbedtls_sha256_starts(&contexts->sha256, 0) == 0;
}

static void hd_all_free(HdAllContexts* contexts) {
    mbedtls_md5_free(&contexts->md5);
    mbedtls_sha1_free(&contexts->sha1);
    mbedtls_sha256_free(&contexts->sha256);
}

HdStatus hd_hash_file_all(Storage* storage, const char* path, HdManifestEntry* result, HdProgress* progress) {
    if(!storage || !path || !result || strlen(path) > HD_PATH_MAX) return HdStatusInvalid;
    File* file = storage_file_alloc(storage);
    if(!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        hd_progress_error_path(progress, path);
        storage_file_free(file);
        return HdStatusOpenError;
    }
    uint8_t* buffer = malloc(HD_IO_CHUNK);
    HdAllContexts contexts;
    bool contexts_started = buffer && hd_all_start(&contexts);
    if(!buffer || !contexts_started) {
        if(buffer) hd_all_free(&contexts);
        free(buffer);
        storage_file_close(file);
        storage_file_free(file);
        return HdStatusInvalid;
    }
    memset(result, 0, sizeof(*result));
    snprintf(result->path, sizeof(result->path), "%s", path);
    HdStatus status = HdStatusOk;
    while(true) {
        if(hd_cancelled(progress)) {
            status = HdStatusCancelled;
            break;
        }
        size_t read = storage_file_read(file, buffer, HD_IO_CHUNK);
        if(read) {
            if(mbedtls_md5_update(&contexts.md5, buffer, read) ||
               mbedtls_sha1_update(&contexts.sha1, buffer, read) ||
               mbedtls_sha256_update(&contexts.sha256, buffer, read)) {
                status = HdStatusReadError;
                break;
            }
            result->size += read;
            hd_progress_add_bytes(progress, read);
        }
        if(read < HD_IO_CHUNK) {
            if(storage_file_get_error(file) != FSE_OK) status = HdStatusReadError;
            break;
        }
    }
    if(status == HdStatusOk) {
        uint8_t md5[16], sha1[20], sha256[32];
        if(mbedtls_md5_finish(&contexts.md5, md5) ||
           mbedtls_sha1_finish(&contexts.sha1, sha1) ||
           mbedtls_sha256_finish(&contexts.sha256, sha256)) {
            status = HdStatusReadError;
        } else {
            hd_hex(md5, sizeof(md5), result->md5);
            hd_hex(sha1, sizeof(sha1), result->sha1);
            hd_hex(sha256, sizeof(sha256), result->sha256);
            result->has_md5 = result->has_sha1 = result->has_sha256 = true;
            if(progress) hd_progress_add_u32(progress, &progress->files, 1U);
        }
    }
    hd_all_free(&contexts);
    free(buffer);
    storage_file_close(file);
    storage_file_free(file);
    if(status != HdStatusOk && status != HdStatusCancelled)
        hd_progress_error_path(progress, path);
    return status;
}

HdStatus hd_hash_file(Storage* storage, const char* path, HdAlgorithm algorithm, char* hex, HdProgress* progress) {
    HdManifestEntry result;
    HdStatus status = hd_hash_file_all(storage, path, &result, progress);
    if(status != HdStatusOk) return status;
    const char* source = algorithm == HdAlgorithmMd5 ? result.md5 :
                         algorithm == HdAlgorithmSha1 ? result.sha1 : result.sha256;
    memcpy(hex, source, hd_algorithm_hex_length(algorithm) + 1U);
    return HdStatusOk;
}

HdStatus hd_verify_file(Storage* storage, const char* path, HdAlgorithm algorithm, const char* expected, char* actual, bool* match, HdProgress* progress) {
    if(!match || !actual || !hd_digest_valid(algorithm, expected)) return HdStatusInvalid;
    HdStatus status = hd_hash_file(storage, path, algorithm, actual, progress);
    if(status != HdStatusOk) return status;
    size_t length = hd_algorithm_hex_length(algorithm);
    *match = hd_hex_equal(actual, expected, length);
    return HdStatusOk;
}

static bool hd_write(File* file, const char* text) {
    size_t length = strlen(text);
    return storage_file_write(file, text, length) == length;
}

static HdStatus hd_manifest_walk(
    Storage* storage,
    File* output,
    const char* path,
    const char* temporary_path,
    const char* final_path,
    uint8_t depth,
    HdProgress* progress) {
    if(depth > 24U || strlen(path) > HD_PATH_MAX) return HdStatusInvalid;
    if(!strcmp(path, temporary_path) || !strcmp(path, final_path) ||
       hd_is_app_report_path(path)) return HdStatusOk;
    bool is_directory = false;
    if(!hd_path_kind(storage, path, &is_directory)) return HdStatusMissing;
    if(!is_directory) {
        HdManifestEntry entry;
        HdStatus status = hd_hash_file_all(storage, path, &entry, progress);
        if(status != HdStatusOk) return status;
        char line[HD_PATH_MAX + 180U];
        int length = snprintf(line, sizeof(line), "%llu,%s,%s,%s,%s\n",
            (unsigned long long)entry.size, entry.md5, entry.sha1, entry.sha256, entry.path);
        if(length < 0 || (size_t)length >= sizeof(line) || !hd_write(output, line)) return HdStatusWriteError;
        return HdStatusOk;
    }
    File* directory = storage_file_alloc(storage);
    if(!storage_dir_open(directory, path)) {
        hd_progress_error_path(progress, path);
        storage_file_free(directory);
        return HdStatusOpenError;
    }
    HdStatus final_status = HdStatusOk;
    FileInfo info;
    char name[HD_PATH_MAX + 1U];
    while(!hd_cancelled(progress) && storage_dir_read(directory, &info, name, sizeof(name))) {
        if(!strcmp(name, ".") || !strcmp(name, "..")) continue;
        char child[HD_PATH_MAX + 1U];
        int length = snprintf(child, sizeof(child), "%s/%s", path, name);
        if(length < 0 || (size_t)length >= sizeof(child)) {
            if(progress) hd_progress_add_u32(progress, &progress->errors, 1U);
            hd_progress_error_path(progress, path);
            final_status = HdStatusInvalid;
            continue;
        }
        HdStatus status = hd_manifest_walk(
            storage,
            output,
            child,
            temporary_path,
            final_path,
            (uint8_t)(depth + 1U),
            progress);
        if(status == HdStatusCancelled) { final_status = status; break; }
        if(status != HdStatusOk) {
            if(progress) hd_progress_add_u32(progress, &progress->errors, 1U);
            final_status = status;
        }
    }
    if(hd_cancelled(progress)) final_status = HdStatusCancelled;
    else {
        FS_Error error = storage_file_get_error(directory);
        if(error != FSE_OK && error != FSE_NOT_EXIST) {
            hd_progress_error_path(progress, path);
            final_status = HdStatusReadError;
        }
    }
    storage_dir_close(directory);
    storage_file_free(directory);
    return final_status;
}

HdStatus hd_create_manifest(Storage* storage, const char* root, const char* output, HdProgress* progress) {
    if(!storage || !hd_path_is_safe_ext(root) || !hd_path_is_safe_ext(output) ||
       !strcmp(root, output) || strlen(output) > HD_PATH_MAX - 8U) return HdStatusInvalid;
    char parent[HD_PATH_MAX + 1U];
    snprintf(parent, sizeof(parent), "%s", output);
    char* slash = strrchr(parent, '/');
    if(!slash || slash == parent) return HdStatusInvalid;
    *slash = '\0';
    if(!storage_simply_mkdir(storage, parent)) return HdStatusOpenError;
    char temporary[HD_PATH_MAX + 1U];
    char backup[HD_PATH_MAX + 1U];
    snprintf(temporary, sizeof(temporary), "%s.partial", output);
    snprintf(backup, sizeof(backup), "%s.backup", output);
    if(storage_file_exists(storage, backup)) {
        if(!storage_file_exists(storage, output)) {
            if(storage_common_rename(storage, backup, output) != FSE_OK)
                return HdStatusWriteError;
        } else if(storage_common_remove(storage, backup) != FSE_OK) {
            return HdStatusWriteError;
        }
    }
    if(storage_file_exists(storage, temporary) &&
       storage_common_remove(storage, temporary) != FSE_OK) return HdStatusWriteError;
    File* file = storage_file_alloc(storage);
    if(!storage_file_open(file, temporary, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        storage_file_free(file);
        return HdStatusOpenError;
    }
    HdStatus status = HdStatusOk;
    if(!hd_write(file, "%%%% HASHDEEP-1.0\n%%%% size,md5,sha1,sha256,filename\n# Generated by Hashdeep FZ native mode\n"))
        status = HdStatusWriteError;
    char root_line[HD_PATH_MAX + 16U];
    int root_length = snprintf(root_line, sizeof(root_line), "# root=%s\n", root);
    if(status == HdStatusOk && (root_length < 0 || (size_t)root_length >= sizeof(root_line) ||
       !hd_write(file, root_line))) status = HdStatusWriteError;
    if(status == HdStatusOk)
        status = hd_manifest_walk(storage, file, root, temporary, output, 0U, progress);
    if(!storage_file_sync(file) && status == HdStatusOk) status = HdStatusWriteError;
    storage_file_close(file);
    storage_file_free(file);
    if(status != HdStatusOk) {
        storage_common_remove(storage, temporary);
        return status;
    }

    bool had_output = storage_file_exists(storage, output);
    if(had_output && storage_common_rename(storage, output, backup) != FSE_OK) {
        storage_common_remove(storage, temporary);
        return HdStatusWriteError;
    }
    if(storage_common_rename(storage, temporary, output) != FSE_OK) {
        if(had_output) storage_common_rename(storage, backup, output);
        storage_common_remove(storage, temporary);
        return HdStatusWriteError;
    }
    if(had_output) storage_common_remove(storage, backup);
    return HdStatusOk;
}

static bool hd_parse_u64(const char* text, uint64_t* value) {
    if(!text || !*text) return false;
    uint64_t result = 0U;
    while(*text) {
        if(*text < '0' || *text > '9') return false;
        uint8_t digit = (uint8_t)(*text - '0');
        if(result > (UINT64_MAX - digit) / 10U) return false;
        result = result * 10U + digit;
        text++;
    }
    *value = result;
    return true;
}

static bool hd_parse_entry(char* line, HdManifestEntry* entry) {
    memset(entry, 0, sizeof(*entry));
    char* fields[5];
    char* cursor = line;
    for(size_t i = 0; i < 4U; i++) {
        fields[i] = cursor;
        char* comma = strchr(cursor, ',');
        if(!comma) return false;
        *comma = '\0';
        cursor = comma + 1U;
    }
    fields[4] = cursor;
    size_t path_length = strlen(fields[4]);
    while(path_length && (fields[4][path_length - 1U] == '\n' || fields[4][path_length - 1U] == '\r'))
        fields[4][--path_length] = '\0';
    if(!hd_parse_u64(fields[0], &entry->size) || !hd_digest_valid(HdAlgorithmMd5, fields[1]) ||
       !hd_digest_valid(HdAlgorithmSha1, fields[2]) || !hd_digest_valid(HdAlgorithmSha256, fields[3]) ||
       !path_length || path_length > HD_PATH_MAX || !hd_path_is_safe_ext(fields[4])) return false;
    snprintf(entry->md5, sizeof(entry->md5), "%s", fields[1]);
    snprintf(entry->sha1, sizeof(entry->sha1), "%s", fields[2]);
    snprintf(entry->sha256, sizeof(entry->sha256), "%s", fields[3]);
    snprintf(entry->path, sizeof(entry->path), "%s", fields[4]);
    entry->has_md5 = entry->has_sha1 = entry->has_sha256 = true;
    return true;
}

static HdStatus hd_find_new_files(
    Storage* storage,
    const char* manifest,
    const HdPathIndex* index,
    const char* path,
    uint8_t depth,
    HdProgress* progress) {
    if(depth > 24U || strlen(path) > HD_PATH_MAX) return HdStatusInvalid;
    if(hd_cancelled(progress)) return HdStatusCancelled;
    if(!strcmp(path, manifest) || hd_is_app_report_path(path)) return HdStatusOk;
    bool is_directory = false;
    if(!hd_path_kind(storage, path, &is_directory)) return HdStatusMissing;
    if(!is_directory) {
        if(!hd_path_index_contains(index, path)) {
            HdManifestEntry measured;
            HdStatus status = hd_hash_file_all(storage, path, &measured, progress);
            if(status != HdStatusOk) return status;
            hd_progress_add_u32(progress, &progress->new_files, 1U);
        }
        return HdStatusOk;
    }
    File* directory = storage_file_alloc(storage);
    if(!storage_dir_open(directory, path)) {
        hd_progress_error_path(progress, path);
        storage_file_free(directory);
        return HdStatusOpenError;
    }
    HdStatus final_status = HdStatusOk;
    FileInfo info;
    char name[HD_PATH_MAX + 1U];
    while(!hd_cancelled(progress) && storage_dir_read(directory, &info, name, sizeof(name))) {
        if(!strcmp(name, ".") || !strcmp(name, "..")) continue;
        char child[HD_PATH_MAX + 1U];
        int length = snprintf(child, sizeof(child), "%s/%s", path, name);
        if(length < 0 || (size_t)length >= sizeof(child)) {
            hd_progress_add_u32(progress, &progress->errors, 1U);
            hd_progress_error_path(progress, path);
            final_status = HdStatusInvalid;
            continue;
        }
        HdStatus status = hd_find_new_files(
            storage, manifest, index, child, (uint8_t)(depth + 1U), progress);
        if(status == HdStatusCancelled) {
            final_status = status;
            break;
        }
        if(status != HdStatusOk && status != HdStatusMissing) {
            hd_progress_add_u32(progress, &progress->errors, 1U);
            final_status = status;
        }
    }
    if(hd_cancelled(progress)) final_status = HdStatusCancelled;
    else {
        FS_Error error = storage_file_get_error(directory);
        if(error != FSE_OK && error != FSE_NOT_EXIST) {
            hd_progress_error_path(progress, path);
            final_status = HdStatusReadError;
        }
    }
    storage_dir_close(directory);
    storage_file_free(directory);
    return final_status;
}

HdStatus hd_audit_manifest(Storage* storage, const char* manifest, HdProgress* progress) {
    if(!storage || !manifest || !progress) return HdStatusInvalid;
    File* file = storage_file_alloc(storage);
    if(!storage_file_open(file, manifest, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_free(file);
        return HdStatusOpenError;
    }
    HdPathIndex index;
    if(!hd_path_index_init(&index)) {
        storage_file_close(file);
        storage_file_free(file);
        return HdStatusInvalid;
    }
    char line[HD_PATH_MAX + 180U];
    size_t used = 0U;
    bool first = true, columns = false;
    char audit_root[HD_PATH_MAX + 1U] = "";
    HdStatus final_status = HdStatusOk;
    while(!hd_cancelled(progress)) {
        uint8_t byte;
        size_t got = storage_file_read(file, &byte, 1U);
        if(!got && !used) {
            if(storage_file_get_error(file) != FSE_OK) {
                hd_progress_error_path(progress, manifest);
                final_status = HdStatusReadError;
            }
            break;
        }
        if(got && byte != '\n' && used + 1U < sizeof(line)) {
            line[used++] = (char)byte;
            continue;
        }
        if(got && byte != '\n') {
            hd_progress_add_u32(progress, &progress->malformed, 1U);
            while(storage_file_read(file, &byte, 1U) == 1U && byte != '\n') {}
            if(storage_file_get_error(file) != FSE_OK) {
                hd_progress_error_path(progress, manifest);
                final_status = HdStatusReadError;
                break;
            }
            used = 0U;
            final_status = HdStatusMalformed;
            continue;
        }
        line[used] = '\0';
        used = 0U;
        if(first) {
            first = false;
            if(strcmp(line, "%%%% HASHDEEP-1.0")) { final_status = HdStatusMalformed; break; }
            continue;
        }
        if(!columns) {
            if(!strcmp(line, "%%%% size,md5,sha1,sha256,filename")) { columns = true; continue; }
            final_status = HdStatusUnsupported;
            break;
        }
        if(!strncmp(line, "# root=", 7U)) {
            char* root = line + 7U;
            size_t root_length = strlen(root);
            if(root_length && root[root_length - 1U] == '\r') root[--root_length] = '\0';
            if(!hd_path_is_safe_ext(root) || audit_root[0]) {
                hd_progress_add_u32(progress, &progress->malformed, 1U);
                final_status = HdStatusMalformed;
            } else {
                memcpy(audit_root, root, root_length + 1U);
            }
            continue;
        }
        if(!line[0] || line[0] == '#') continue;
        HdManifestEntry expected, actual;
        if(!hd_parse_entry(line, &expected)) {
            hd_progress_add_u32(progress, &progress->malformed, 1U);
            final_status = HdStatusMalformed;
            continue;
        }
        bool duplicate = false;
        HdStatus index_status = hd_path_index_add(&index, expected.path, &duplicate);
        if(index_status != HdStatusOk) {
            final_status = index_status;
            break;
        }
        if(duplicate) {
            hd_progress_add_u32(progress, &progress->malformed, 1U);
            final_status = HdStatusMalformed;
            continue;
        }
        HdStatus status = hd_hash_file_all(storage, expected.path, &actual, progress);
        if(status == HdStatusOpenError) {
            hd_progress_add_u32(progress, &progress->missing, 1U);
            continue;
        }
        if(status != HdStatusOk) {
            hd_progress_add_u32(progress, &progress->errors, 1U);
            final_status = status;
            continue;
        }
        if(actual.size == expected.size && hd_hex_equal(actual.md5, expected.md5, 32U) &&
           hd_hex_equal(actual.sha1, expected.sha1, 40U) &&
           hd_hex_equal(actual.sha256, expected.sha256, 64U))
            hd_progress_add_u32(progress, &progress->matched, 1U);
        else
            hd_progress_add_u32(progress, &progress->changed, 1U);
    }
    if(hd_cancelled(progress)) final_status = HdStatusCancelled;
    else if(final_status == HdStatusOk && (first || !columns)) final_status = HdStatusMalformed;
    storage_file_close(file);
    storage_file_free(file);
    if(final_status == HdStatusOk && audit_root[0]) {
        hd_path_index_sort(&index);
        HdStatus new_status = hd_find_new_files(
            storage, manifest, &index, audit_root, 0U, progress);
        if(new_status != HdStatusOk) final_status = new_status;
    }
    hd_path_index_free(&index);
    return final_status;
}

bool hd_self_test(void) {
    static const uint8_t abc[] = {'a','b','c'};
    uint8_t output[32];
    char hex[65];
    if(mbedtls_md5(abc, sizeof(abc), output) != 0) return false;
    hd_hex(output, 16U, hex);
    if(strcmp(hex, "900150983cd24fb0d6963f7d28e17f72")) return false;
    if(mbedtls_sha1(abc, sizeof(abc), output) != 0) return false;
    hd_hex(output, 20U, hex);
    if(strcmp(hex, "a9993e364706816aba3e25717850c26c9cd0d89d")) return false;
    if(mbedtls_sha256(abc, sizeof(abc), output, 0) != 0) return false;
    hd_hex(output, 32U, hex);
    return !strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}
