/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "hashdeep_engine.h"
#include "hashdeep_external.h"

#include <dialogs/dialogs.h>
#include <furi.h>
#include <furi/core/memmgr.h>
#include <gui/gui.h>
#include <gui/view.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_input.h>
#include <gui/modules/variable_item_list.h>
#include <gui/modules/widget.h>
#include <storage/storage.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HD_VERSION "1.0.1"

typedef enum { HdViewMain, HdViewSettings, HdViewInput, HdViewText, HdViewExternal } HdViewId;
typedef enum {
    HdMenuHashFile, HdMenuHashDirectory, HdMenuVerify, HdMenuAudit, HdMenuCreate,
    HdMenuExternal, HdMenuDirectory, HdMenuManifestOutput, HdMenuExpected, HdMenuReports,
    HdMenuSettings, HdMenuAbout
} HdMenu;
typedef enum { HdInputManifestFilename, HdInputExpected } HdInputPurpose;
typedef enum { HdOpNone, HdOpHash, HdOpVerify, HdOpAudit, HdOpManifest } HdOperation;

typedef struct {
    Gui* gui; Storage* storage; DialogsApp* dialogs; ViewDispatcher* dispatcher;
    Submenu* menu; VariableItemList* settings; TextInput* input; Widget* widget;
    View* external_view; FuriString* text; FuriString* selected_path;
    FuriThread* worker; FuriMutex* mutex; HashdeepExternal* external;
    HdProgress progress; HdStatus status; HdOperation operation; HdAlgorithm algorithm;
    HdViewId current_view, return_view; HdInputPurpose input_purpose;
    char directory[HD_PATH_MAX + 1U]; char manifest_output[HD_PATH_MAX + 1U];
    char output_directory[HD_PATH_MAX + 1U]; char manifest_filename[64];
    char expected[HD_DIGEST_HEX_MAX + 1U]; char digest[HD_DIGEST_HEX_MAX + 1U];
    char last_report[1024]; bool verify_match; volatile bool cancel;
    uint32_t start_tick, end_tick, baud;
    uint8_t baud_index, external_operation, directory_preset, output_preset;
    bool views_added;
    size_t heap_before, heap_after, heap_min; uint32_t stack_free;
} HdApp;

typedef struct { HdApp* app; uint32_t revision; } HdExternalModel;
static const uint32_t hd_bauds[] = {115200U, 230400U, 460800U};
static const char* const hd_baud_names[] = {"115200", "230400", "460800"};
static const char* const hd_external_operation_names[] = {"Hash", "Manifest", "Audit"};
static const char* const hd_external_operation_commands[] = {"HASH", "MANIFEST", "AUDIT"};
static const char* const hd_directory_preset_names[] = {
    "SD root", "Apps/Tools", "NFC", "Sub-GHz", "LF RFID", "Infrared", "Hashdeep input"};
static const char* const hd_directory_presets[] = {
    "/ext", "/ext/apps/Tools", "/ext/nfc", "/ext/subghz", "/ext/lfrfid",
    "/ext/infrared", "/ext/hashdeep_input"};
static const char* const hd_output_preset_names[] = {
    "Hashdeep output", "SD root", "Apps/Tools", "NFC", "Sub-GHz", "LF RFID", "Infrared"};
static const char* const hd_output_presets[] = {
    "/ext/hashdeep_fz", "/ext", "/ext/apps/Tools", "/ext/nfc", "/ext/subghz",
    "/ext/lfrfid", "/ext/infrared"};

static bool hd_safe_ext_path(const char* path) {
    if(!path || strncmp(path, "/ext", 4U) || (path[4] && path[4] != '/') ||
       strlen(path) > HD_PATH_MAX || strstr(path, "..") || strstr(path, "//")) return false;
    for(const char* cursor = path; *cursor; cursor++) {
        unsigned char c = (unsigned char)*cursor;
        if(c < 0x20U || c > 0x7EU || c == '\\' || strchr(":*?\"<>|", c)) return false;
    }
    return true;
}

static bool hd_filename_valid(const char* filename) {
    size_t length = filename ? strlen(filename) : 0U;
    if(!length || length >= 64U || !strcmp(filename, ".") || !strcmp(filename, ".."))
        return false;
    for(size_t i = 0U; i < length; i++) {
        unsigned char c = (unsigned char)filename[i];
        if(c < 0x20U || c > 0x7EU || strchr("/\\:*?\"<>|", c)) return false;
    }
    return true;
}

static bool hd_build_manifest_output(HdApp* app) {
    if(!hd_safe_ext_path(app->output_directory) || !hd_filename_valid(app->manifest_filename))
        return false;
    int length = snprintf(
        app->manifest_output,
        sizeof(app->manifest_output),
        "%s/%s",
        app->output_directory,
        app->manifest_filename);
    return length > 0 && (size_t)length < sizeof(app->manifest_output) - 8U;
}

static void hd_switch(HdApp* app, HdViewId view) { app->current_view = view; view_dispatcher_switch_to_view(app->dispatcher, view); }
static void hd_show(HdApp* app, const char* title, const char* body, HdViewId back) {
    widget_reset(app->widget); furi_string_printf(app->text, "\e#%s\n%s", title, body);
    widget_add_text_scroll_element(app->widget, 0, 0, 128, 64, furi_string_get_cstr(app->text));
    app->return_view = back; hd_switch(app, HdViewText);
}

static const char* hd_status_text(HdStatus status) {
    switch(status) {
    case HdStatusOk: return "Completed"; case HdStatusCancelled: return "Cancelled";
    case HdStatusInvalid: return "Invalid input or allocation failure";
    case HdStatusOpenError: return "Could not open file or directory";
    case HdStatusReadError: return "Read failed or SD card disappeared";
    case HdStatusWriteError: return "Write failed or storage is full";
    case HdStatusMalformed: return "Malformed manifest entries found";
    case HdStatusUnsupported: return "Unsupported manifest columns";
    case HdStatusMissing: return "File or directory missing";
    case HdStatusTooLarge: return "Manifest exceeds native audit limit";
    }
    return "Unknown error";
}

static uint64_t hd_elapsed(uint32_t start, uint32_t end) {
    uint32_t frequency = furi_kernel_get_tick_frequency();
    return frequency ? ((uint64_t)(end - start) * 1000U) / frequency : 0U;
}

static bool hd_save_report(HdApp* app) {
    const char* final_path = "/ext/hashdeep_fz/report.txt";
    const char* temporary_path = "/ext/hashdeep_fz/report.txt.partial";
    const char* backup_path = "/ext/hashdeep_fz/report.txt.backup";
    if(!storage_simply_mkdir(app->storage, "/ext/hashdeep_fz")) return false;
    if(storage_file_exists(app->storage, backup_path)) {
        if(!storage_file_exists(app->storage, final_path)) {
            if(storage_common_rename(app->storage, backup_path, final_path) != FSE_OK)
                return false;
        } else if(storage_common_remove(app->storage, backup_path) != FSE_OK) {
            return false;
        }
    }
    if(storage_file_exists(app->storage, temporary_path) &&
       storage_common_remove(app->storage, temporary_path) != FSE_OK) return false;
    File* file = storage_file_alloc(app->storage);
    bool written = false;
    if(storage_file_open(file, temporary_path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        size_t length = strlen(app->last_report);
        written = storage_file_write(file, app->last_report, length) == length &&
                  storage_file_sync(file);
        storage_file_close(file);
    }
    storage_file_free(file);
    if(!written) {
        storage_common_remove(app->storage, temporary_path);
        return false;
    }
    bool had_report = storage_file_exists(app->storage, final_path);
    if(had_report && storage_common_rename(app->storage, final_path, backup_path) != FSE_OK) {
        storage_common_remove(app->storage, temporary_path);
        return false;
    }
    if(storage_common_rename(app->storage, temporary_path, final_path) != FSE_OK) {
        if(had_report) storage_common_rename(app->storage, backup_path, final_path);
        storage_common_remove(app->storage, temporary_path);
        return false;
    }
    if(had_report) storage_common_remove(app->storage, backup_path);
    return true;
}

static int32_t hd_worker(void* context) {
    HdApp* app = context;
    app->heap_before = memmgr_get_free_heap(); app->start_tick = furi_get_tick();
    memset(&app->progress, 0, sizeof(app->progress));
    app->progress.cancel = &app->cancel;
    app->progress.mutex = app->mutex;
    const char* path = furi_string_get_cstr(app->selected_path);
    if(app->operation == HdOpHash)
        app->status = hd_hash_file(app->storage, path, app->algorithm, app->digest, &app->progress);
    else if(app->operation == HdOpVerify)
        app->status = hd_verify_file(app->storage, path, app->algorithm, app->expected, app->digest, &app->verify_match, &app->progress);
    else if(app->operation == HdOpAudit)
        app->status = hd_audit_manifest(app->storage, path, &app->progress);
    else if(app->operation == HdOpManifest)
        app->status = hd_create_manifest(app->storage, app->directory, app->manifest_output, &app->progress);
    else app->status = HdStatusInvalid;
    app->end_tick = furi_get_tick(); app->heap_after = memmgr_get_free_heap();
    app->heap_min = memmgr_get_minimum_free_heap();
    app->stack_free = furi_thread_get_stack_space(furi_thread_get_current_id());
    view_dispatcher_send_custom_event(app->dispatcher, 1U); return 0;
}

static void hd_join(HdApp* app) { if(app->worker) { furi_thread_join(app->worker); furi_thread_free(app->worker); app->worker = NULL; } }

static void hd_show_result(HdApp* app) {
    uint64_t ms = hd_elapsed(app->start_tick, app->end_tick);
    const char* op = app->operation == HdOpHash ? "Hash" : app->operation == HdOpVerify ? "Verify" : app->operation == HdOpAudit ? "Audit" : "Manifest";
    char detail[560] = "";
    if(app->operation == HdOpHash && app->status == HdStatusOk)
        snprintf(detail, sizeof(detail), "%s\n%s: %s\n", furi_string_get_cstr(app->selected_path), hd_algorithm_name(app->algorithm), app->digest);
    else if(app->operation == HdOpVerify && app->status == HdStatusOk)
        snprintf(detail, sizeof(detail), "%s\nResult: %s\nActual: %s\n", furi_string_get_cstr(app->selected_path), app->verify_match ? "MATCH" : "MISMATCH", app->digest);
    else if(app->operation == HdOpManifest)
        snprintf(detail, sizeof(detail), "Input: %s\nOutput: %s\n", app->directory, app->manifest_output);
    else snprintf(detail, sizeof(detail), "%s\n", furi_string_get_cstr(app->selected_path));
    if(app->status != HdStatusOk && app->progress.error_path[0]) {
        size_t used = strlen(detail);
        snprintf(
            detail + used,
            sizeof(detail) - used,
            "Failure path: %s\n",
            app->progress.error_path);
    }
    snprintf(app->last_report, sizeof(app->last_report),
        "Hashdeep FZ v%s\nOperation: %s\nStatus: %s\n%sFiles: %lu\nBytes: %llu\nMatched: %lu\nChanged: %lu\nMissing: %lu\nNew: %lu\nMalformed: %lu\nErrors: %lu\nElapsed: %llu.%03llu s\nHeap: %lu -> %lu (min %lu)\nWorker stack free: %lu\n",
        HD_VERSION, op, hd_status_text(app->status), detail,
        (unsigned long)app->progress.files, (unsigned long long)app->progress.bytes,
        (unsigned long)app->progress.matched, (unsigned long)app->progress.changed,
        (unsigned long)app->progress.missing, (unsigned long)app->progress.new_files,
        (unsigned long)app->progress.malformed,
        (unsigned long)app->progress.errors, (unsigned long long)(ms / 1000U),
        (unsigned long long)(ms % 1000U), (unsigned long)app->heap_before,
        (unsigned long)app->heap_after, (unsigned long)app->heap_min, (unsigned long)app->stack_free);
    bool report_saved = hd_save_report(app);
    char display[1152];
    snprintf(
        display,
        sizeof(display),
        "%s%s",
        app->last_report,
        report_saved ? "\nReport saved: /ext/hashdeep_fz/report.txt" :
                       "\nREPORT NOT SAVED: check SD card and free space.");
    hd_show(
        app,
        report_saved ? (app->status == HdStatusOk ? "Measured result" : "Operation stopped") :
                       "Report save failed",
        display,
        HdViewMain);
}

static void hd_start_worker(HdApp* app, HdOperation operation) {
    hd_join(app); app->cancel = false; app->operation = operation; app->status = HdStatusInvalid;
    if(operation == HdOpManifest && !hd_build_manifest_output(app)) {
        hd_show(app, "Invalid output", "Choose an output-folder preset and a filename without / \\ : * ? \" < > |", HdViewMain);
        return;
    }
    if(operation == HdOpManifest && (!hd_safe_ext_path(app->directory) ||
       !hd_safe_ext_path(app->manifest_output) || !strcmp(app->directory, app->manifest_output))) {
        hd_show(app, "Invalid paths", "Input and output must be different absolute /ext paths without .. or reserved filename characters.", HdViewMain);
        return;
    }
    if(operation == HdOpManifest && !strcmp(app->directory, "/ext/hashdeep_input"))
        storage_simply_mkdir(app->storage, app->directory);
    memset(&app->progress, 0, sizeof(app->progress));
    hd_show(app, "Working", "Reading actual file bytes from microSD.\n\nBack requests cancellation. No result is inferred or simulated.", HdViewMain);
    app->worker = furi_thread_alloc_ex("HashdeepWorker", 6144U, hd_worker, app);
    if(app->worker) furi_thread_start(app->worker);
    else hd_show(app, "Failed", "Could not allocate worker. No result produced.", HdViewMain);
}

static void hd_confirm_manifest(GuiButtonType button, InputType type, void* context) {
    if(button == GuiButtonTypeCenter && type == InputTypeShort)
        hd_start_worker(context, HdOpManifest);
}

static void hd_request_manifest(HdApp* app) {
    if(!hd_build_manifest_output(app)) {
        hd_show(app, "Invalid output", "Choose an output-folder preset and a valid manifest filename.", HdViewMain);
        return;
    }
    if(!storage_file_exists(app->storage, app->manifest_output)) {
        hd_start_worker(app, HdOpManifest);
        return;
    }
    widget_reset(app->widget);
    furi_string_printf(
        app->text,
        "\e#Replace manifest?\n%s\n\nThe old manifest stays intact until the replacement is complete.",
        app->manifest_output);
    widget_add_text_scroll_element(
        app->widget, 0, 0, 128, 51, furi_string_get_cstr(app->text));
    widget_add_button_element(
        app->widget, GuiButtonTypeCenter, "Replace", hd_confirm_manifest, app);
    app->return_view = HdViewMain;
    hd_switch(app, HdViewText);
}

static bool hd_pick(HdApp* app, const char* extension) {
    DialogsFileBrowserOptions options; dialog_file_browser_set_basic_options(&options, extension, NULL);
    options.hide_ext = false; options.skip_assets = false;
    return dialog_file_browser_show(app->dialogs, app->selected_path, app->selected_path, &options);
}

static void hd_choose_directory(HdApp* app) {
    furi_string_set_str(app->selected_path, app->directory);
    if(!hd_pick(app, "*")) return;
    const char* selected = furi_string_get_cstr(app->selected_path);
    size_t length = strlen(selected);
    if(length > HD_PATH_MAX) {
        hd_show(app, "Path too long", "The selected parent directory exceeds 255 bytes.", HdViewMain);
        return;
    }
    memcpy(app->directory, selected, length + 1U);
    char* slash = strrchr(app->directory, '/');
    if(!slash || slash == app->directory) {
        snprintf(app->directory, sizeof(app->directory), "/ext");
    } else {
        *slash = '\0';
    }
    if(!hd_safe_ext_path(app->directory)) {
        hd_show(app, "Invalid directory", "The selected file is not inside a safe /ext directory.", HdViewMain);
        return;
    }
    char body[HD_PATH_MAX + 80U];
    snprintf(body, sizeof(body), "Selected file:\n%s\n\nInput directory is now:\n%s", selected, app->directory);
    hd_show(app, "Directory selected", body, HdViewMain);
}

static void hd_input_done(void* context) { HdApp* app = context; hd_switch(app, HdViewMain); }
static void hd_open_input(HdApp* app, HdInputPurpose purpose) {
    app->input_purpose = purpose; char* buffer; size_t size; const char* header;
    if(purpose == HdInputManifestFilename) { buffer = app->manifest_filename; size = sizeof(app->manifest_filename); header = "Manifest filename"; }
    else { buffer = app->expected; size = sizeof(app->expected); header = "Expected hex digest"; }
    text_input_reset(app->input); text_input_set_header_text(app->input, header); text_input_set_minimum_length(app->input, 1U);
    text_input_set_result_callback(app->input, hd_input_done, app, buffer, size, true); hd_switch(app, HdViewInput);
}

static void hd_external_draw(Canvas* canvas, void* model_context) {
    HdExternalModel* model = model_context; HdExternalSnapshot s; hd_external_snapshot(model->app->external, &s); char line[96];
    canvas_set_font(canvas, FontPrimary); canvas_draw_str(canvas, 1, 9, "External Hashdeep"); canvas_set_font(canvas, FontKeyboard);
    snprintf(line, sizeof(line), "%s %s", s.version[0] ? s.version : "waiting", s.state); canvas_draw_str(canvas, 1, 20, line);
    snprintf(line, sizeof(line), "Files %lu Bytes %llu", (unsigned long)s.files, (unsigned long long)s.bytes); canvas_draw_str(canvas, 1, 30, line);
    snprintf(line, sizeof(line), "Match %lu Change %lu", (unsigned long)s.matched, (unsigned long)s.changed); canvas_draw_str(canvas, 1, 40, line);
    snprintf(line, sizeof(line), "Missing %lu New %lu", (unsigned long)s.missing, (unsigned long)s.new_files); canvas_draw_str(canvas, 1, 50, line);
    canvas_draw_str(canvas, 1, 60, s.error[0] ? s.error : s.target);
    char action[20]; snprintf(action, sizeof(action), "OK %s", s.running ? "Stop" : hd_external_operation_names[model->app->external_operation]);
    canvas_draw_str(canvas, 78, 9, action);
}

static bool hd_external_input(InputEvent* event, void* context) {
    HdApp* app = context; if(event->key != InputKeyOk || event->type != InputTypeShort) return false;
    HdExternalSnapshot s; hd_external_snapshot(app->external, &s); if(!s.connected) return false;
    if(s.running) hd_external_cancel(app->external);
    else hd_external_run(app->external, hd_external_operation_commands[app->external_operation]);
    return true;
}

static void hd_selected(void* context, uint32_t index) {
    HdApp* app = context;
    if(index == HdMenuHashFile) { if(hd_pick(app, "*")) hd_start_worker(app, HdOpHash); }
    else if(index == HdMenuHashDirectory) hd_request_manifest(app);
    else if(index == HdMenuVerify) {
        if(!hd_digest_valid(app->algorithm, app->expected)) hd_show(app, "Invalid digest", "Set an expected digest matching the selected algorithm first.", HdViewMain);
        else if(hd_pick(app, "*")) hd_start_worker(app, HdOpVerify);
    } else if(index == HdMenuAudit) { if(hd_pick(app, ".hashdeep|.txt|*")) hd_start_worker(app, HdOpAudit); }
    else if(index == HdMenuCreate) hd_request_manifest(app);
    else if(index == HdMenuExternal) { hd_external_start(app->external, app->baud); hd_switch(app, HdViewExternal); }
    else if(index == HdMenuDirectory) hd_choose_directory(app);
    else if(index == HdMenuManifestOutput) hd_open_input(app, HdInputManifestFilename);
    else if(index == HdMenuExpected) hd_open_input(app, HdInputExpected);
    else if(index == HdMenuReports) hd_show(app, "Last report", app->last_report[0] ? app->last_report : "No measured operation has completed yet.", HdViewMain);
    else if(index == HdMenuSettings) hd_switch(app, HdViewSettings);
    else if(index == HdMenuAbout) hd_show(app, "About Hashdeep FZ",
        "Version " HD_VERSION "\n\nNative mode hashes actual readable microSD files using streaming MD5, SHA-1, and SHA-256; creates and audits HASHDEEP-1.0 manifests; and labels legacy algorithms.\n\nExternal mode runs the genuine upstream hashdeep executable on a Raspberry Pi, spare Linux laptop, desktop, or VM. The Flipper is the 3.3V UART controller and measured status display.\n\nNo NFC/RFID/Sub-GHz identifier is treated as a hash. Their saved files can be hashed as ordinary bytes.\n\nUpstream public-domain/GPL licensing preserved.", HdViewMain);
}

static void hd_algorithm_changed(VariableItem* item) {
    HdApp* app = variable_item_get_context(item); app->algorithm = (HdAlgorithm)variable_item_get_current_value_index(item);
    const char* names[] = {"MD5 legacy", "SHA-1 legacy", "SHA-256"}; variable_item_set_current_value_text(item, names[app->algorithm]);
}
static void hd_baud_changed(VariableItem* item) {
    HdApp* app = variable_item_get_context(item); app->baud_index = variable_item_get_current_value_index(item); app->baud = hd_bauds[app->baud_index];
    variable_item_set_current_value_text(item, hd_baud_names[app->baud_index]);
}
static void hd_external_operation_changed(VariableItem* item) {
    HdApp* app = variable_item_get_context(item);
    app->external_operation = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, hd_external_operation_names[app->external_operation]);
}
static void hd_directory_preset_changed(VariableItem* item) {
    HdApp* app = variable_item_get_context(item);
    app->directory_preset = variable_item_get_current_value_index(item);
    snprintf(app->directory, sizeof(app->directory), "%s", hd_directory_presets[app->directory_preset]);
    variable_item_set_current_value_text(item, hd_directory_preset_names[app->directory_preset]);
}
static void hd_output_preset_changed(VariableItem* item) {
    HdApp* app = variable_item_get_context(item);
    app->output_preset = variable_item_get_current_value_index(item);
    snprintf(
        app->output_directory,
        sizeof(app->output_directory),
        "%s",
        hd_output_presets[app->output_preset]);
    variable_item_set_current_value_text(item, hd_output_preset_names[app->output_preset]);
}

static bool hd_custom(void* context, uint32_t event) { HdApp* app = context; if(event != 1U) return false; hd_join(app); hd_show_result(app); return true; }
static bool hd_back(void* context) {
    HdApp* app = context;
    if(app->current_view == HdViewMain) view_dispatcher_stop(app->dispatcher);
    else if(app->worker) { app->cancel = true; hd_show(app, "Cancelling", "Waiting for the current chunk to finish and files to close safely.", HdViewMain); }
    else if(app->current_view == HdViewExternal) { hd_external_stop(app->external); hd_switch(app, HdViewMain); }
    else if(app->current_view == HdViewText) hd_switch(app, app->return_view);
    else hd_switch(app, HdViewMain);
    return true;
}
static void hd_tick(void* context) {
    HdApp* app = context;
    if(app->current_view == HdViewExternal) { HdExternalModel* model = view_get_model(app->external_view); model->revision++; view_commit_model(app->external_view, true); return; }
    if(!app->worker) return;
    uint64_t bytes;
    uint32_t files, matched, changed, missing, new_files, errors, malformed;
    if(furi_mutex_acquire(app->mutex, 0U) != FuriStatusOk) return;
    bytes = app->progress.bytes;
    files = app->progress.files;
    matched = app->progress.matched;
    changed = app->progress.changed;
    missing = app->progress.missing;
    new_files = app->progress.new_files;
    errors = app->progress.errors;
    malformed = app->progress.malformed;
    furi_mutex_release(app->mutex);
    furi_string_printf(app->text, "\e#Working\nFiles: %lu\nBytes read: %llu\nMatched: %lu Changed: %lu\nMissing: %lu New: %lu\nErrors: %lu\nBack requests cancellation.",
        (unsigned long)files, (unsigned long long)bytes,
        (unsigned long)matched, (unsigned long)changed,
        (unsigned long)missing, (unsigned long)new_files,
        (unsigned long)(errors + malformed));
    widget_reset(app->widget); widget_add_text_scroll_element(app->widget, 0, 0, 128, 64, furi_string_get_cstr(app->text));
}

static HdApp* hd_alloc(void) {
    HdApp* app = calloc(1U, sizeof(*app)); if(!app) return NULL;
    app->gui = furi_record_open(RECORD_GUI); app->storage = furi_record_open(RECORD_STORAGE); app->dialogs = furi_record_open(RECORD_DIALOGS);
    app->dispatcher = view_dispatcher_alloc(); app->menu = submenu_alloc(); app->settings = variable_item_list_alloc();
    app->input = text_input_alloc(); app->widget = widget_alloc(); app->external_view = view_alloc();
    app->text = furi_string_alloc(); app->selected_path = furi_string_alloc_set("/ext"); app->mutex = furi_mutex_alloc(FuriMutexTypeNormal); app->external = hd_external_alloc();
    if(!app->gui || !app->storage || !app->dialogs || !app->dispatcher || !app->menu || !app->settings || !app->input || !app->widget || !app->external_view || !app->text || !app->selected_path || !app->mutex || !app->external) return app;
    snprintf(app->directory, sizeof(app->directory), "/ext");
    snprintf(app->output_directory, sizeof(app->output_directory), "/ext/hashdeep_fz");
    snprintf(app->manifest_filename, sizeof(app->manifest_filename), "manifest.hashdeep");
    hd_build_manifest_output(app);
    snprintf(app->last_report, sizeof(app->last_report), "No measured operation has completed yet."); app->algorithm = HdAlgorithmSha256; app->baud = 115200U;
    submenu_set_header(app->menu, "Hashdeep FZ v" HD_VERSION);
    submenu_add_item(app->menu, "Hash File", HdMenuHashFile, hd_selected, app);
    submenu_add_item(app->menu, "Hash Directory", HdMenuHashDirectory, hd_selected, app);
    submenu_add_item(app->menu, "Verify Digest", HdMenuVerify, hd_selected, app);
    submenu_add_item(app->menu, "Audit Manifest", HdMenuAudit, hd_selected, app);
    submenu_add_item(app->menu, "Create Manifest", HdMenuCreate, hd_selected, app);
    submenu_add_item(app->menu, "External Hashdeep", HdMenuExternal, hd_selected, app);
    submenu_add_item(app->menu, "Choose folder via file", HdMenuDirectory, hd_selected, app);
    submenu_add_item(app->menu, "Manifest filename", HdMenuManifestOutput, hd_selected, app);
    submenu_add_item(app->menu, "Expected digest", HdMenuExpected, hd_selected, app);
    submenu_add_item(app->menu, "Reports", HdMenuReports, hd_selected, app);
    submenu_add_item(app->menu, "Settings", HdMenuSettings, hd_selected, app);
    submenu_add_item(app->menu, "About", HdMenuAbout, hd_selected, app);
    VariableItem* algorithm = variable_item_list_add(app->settings, "Algorithm", 3U, hd_algorithm_changed, app);
    variable_item_set_current_value_index(algorithm, 2U); variable_item_set_current_value_text(algorithm, "SHA-256");
    VariableItem* baud = variable_item_list_add(app->settings, "External baud", COUNT_OF(hd_bauds), hd_baud_changed, app);
    variable_item_set_current_value_index(baud, 0U); variable_item_set_current_value_text(baud, hd_baud_names[0]);
    VariableItem* operation = variable_item_list_add(app->settings, "External operation", COUNT_OF(hd_external_operation_names), hd_external_operation_changed, app);
    variable_item_set_current_value_index(operation, 0U); variable_item_set_current_value_text(operation, hd_external_operation_names[0]);
    VariableItem* directory = variable_item_list_add(app->settings, "Input folder", COUNT_OF(hd_directory_presets), hd_directory_preset_changed, app);
    variable_item_set_current_value_index(directory, 0U); variable_item_set_current_value_text(directory, hd_directory_preset_names[0]);
    VariableItem* output = variable_item_list_add(app->settings, "Output folder", COUNT_OF(hd_output_preset_names), hd_output_preset_changed, app);
    variable_item_set_current_value_index(output, 0U); variable_item_set_current_value_text(output, hd_output_preset_names[0]);
    VariableItem* version = variable_item_list_add(app->settings, "Version", 1U, NULL, app); variable_item_set_current_value_text(version, HD_VERSION);
    VariableItem* selftest = variable_item_list_add(app->settings, "Crypto self-test", 1U, NULL, app); variable_item_set_current_value_text(selftest, hd_self_test() ? "PASS" : "FAIL");
    view_dispatcher_set_event_callback_context(app->dispatcher, app); view_dispatcher_set_custom_event_callback(app->dispatcher, hd_custom);
    view_dispatcher_set_navigation_event_callback(app->dispatcher, hd_back); view_dispatcher_set_tick_event_callback(app->dispatcher, hd_tick, 250U);
    view_dispatcher_add_view(app->dispatcher, HdViewMain, submenu_get_view(app->menu)); view_dispatcher_add_view(app->dispatcher, HdViewSettings, variable_item_list_get_view(app->settings));
    view_dispatcher_add_view(app->dispatcher, HdViewInput, text_input_get_view(app->input)); view_dispatcher_add_view(app->dispatcher, HdViewText, widget_get_view(app->widget));
    view_set_context(app->external_view, app); view_set_draw_callback(app->external_view, hd_external_draw); view_set_input_callback(app->external_view, hd_external_input);
    view_allocate_model(app->external_view, ViewModelTypeLocking, sizeof(HdExternalModel)); HdExternalModel* model = view_get_model(app->external_view); model->app = app; view_commit_model(app->external_view, false);
    view_dispatcher_add_view(app->dispatcher, HdViewExternal, app->external_view); app->views_added = true;
    view_dispatcher_attach_to_gui(app->dispatcher, app->gui, ViewDispatcherTypeFullscreen); return app;
}

static bool hd_valid(HdApp* app) { return app && app->gui && app->storage && app->dialogs && app->dispatcher && app->menu && app->settings && app->input && app->widget && app->external_view && app->text && app->selected_path && app->mutex && app->external; }
static void hd_free(HdApp* app) {
    if(!app) return;
    app->cancel = true;
    hd_join(app);
    if(app->external) hd_external_free(app->external);
    if(app->dispatcher && app->views_added) { view_dispatcher_remove_view(app->dispatcher, HdViewExternal); view_dispatcher_remove_view(app->dispatcher, HdViewText); view_dispatcher_remove_view(app->dispatcher, HdViewInput); view_dispatcher_remove_view(app->dispatcher, HdViewSettings); view_dispatcher_remove_view(app->dispatcher, HdViewMain); }
    if(app->mutex) furi_mutex_free(app->mutex);
    if(app->selected_path) furi_string_free(app->selected_path);
    if(app->text) furi_string_free(app->text);
    if(app->external_view) view_free(app->external_view);
    if(app->widget) widget_free(app->widget);
    if(app->input) text_input_free(app->input);
    if(app->settings) variable_item_list_free(app->settings);
    if(app->menu) submenu_free(app->menu);
    if(app->dispatcher) view_dispatcher_free(app->dispatcher);
    if(app->dialogs) furi_record_close(RECORD_DIALOGS);
    if(app->storage) furi_record_close(RECORD_STORAGE);
    if(app->gui) furi_record_close(RECORD_GUI);
    free(app);
}

int32_t hashdeep_fz_app(void* context) {
    UNUSED(context); HdApp* app = hd_alloc(); if(!hd_valid(app)) { hd_free(app); return -1; }
    hd_switch(app, HdViewMain); view_dispatcher_run(app->dispatcher); hd_free(app); return 0;
}
