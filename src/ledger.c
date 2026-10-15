#include "ledger.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define STATE_MAGIC "LIBLEDG1"
#define STATE_VERSION 1u

typedef struct {
    char magic[8];
    uint32_t version;
    uint32_t payload_size;
    unsigned char checksum[SHA256_DIGEST_LEN];
} StateHeader;

static void trim_in_place(char *str) {
    char *start = str;
    char *end;
    size_t len;

    while (*start != '\0' && isspace((unsigned char)*start)) {
        start++;
    }
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
    end = str + strlen(str);
    while (end > str && isspace((unsigned char)end[-1])) {
        end--;
    }
    *end = '\0';
    len = strlen(str);
    if (len == 0u) {
        str[0] = '\0';
    }
}

static void generate_record_id(const char *book_id, const char *copy_id, const char *member_id,
                              const char *action, const char *due_date, unsigned long nonce, char out[HASH_LEN]) {
    char buffer[512];
    uint8_t digest[32];
    snprintf(buffer, sizeof(buffer), "%s|%s|%s|%s|%s|%lu", book_id, copy_id, member_id, action, due_date, nonce);
    sha256_hash_bytes((const uint8_t *)buffer, strlen(buffer), digest);
    bytes_to_hex(digest, 32, out, HASH_LEN);
}

static void generate_request_id(const char *book_id, const char *copy_id, const char *member_id,
                               const char *action, char out[HASH_LEN]) {
    char buffer[512];
    uint8_t digest[32];
    snprintf(buffer, sizeof(buffer), "%s|%s|%s|%s", book_id, copy_id, member_id, action);
    sha256_hash_bytes((const uint8_t *)buffer, strlen(buffer), digest);
    bytes_to_hex(digest, 32, out, HASH_LEN);
}

static void hash_string(const char *input, char out[HASH_LEN]) {
    uint8_t digest[32];
    sha256_hash_bytes((const uint8_t *)input, strlen(input), digest);
    bytes_to_hex(digest, 32, out, HASH_LEN);
}

static char *copy_today(void) {
    static char date[DATE_LEN];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    snprintf(date, sizeof(date), "%04d-%02d-%02d", tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday);
    return date;
}

static int day_from_iso(const char *date) {
    int year, month, day;
    if (sscanf(date, "%d-%d-%d", &year, &month, &day) != 3) {
        return 0;
    }
    struct tm tm_info = {0};
    tm_info.tm_year = year - 1900;
    tm_info.tm_mon = month - 1;
    tm_info.tm_mday = day;
    return (int)mktime(&tm_info) / 86400;
}

static void add_days_to_date(char out[DATE_LEN], int days) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    tm_info->tm_mday += days;
    mktime(tm_info);
    snprintf(out, DATE_LEN, "%04d-%02d-%02d", tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday);
}

static int compute_late_days(const char *ddate) {
    int today_day = day_from_iso(copy_today());
    int due_day = day_from_iso(ddate);
    if (due_day <= today_day) {
        return today_day - due_day;
    }
    return 0;
}

static void build_record_signature(LendingRecord *record, const Member *member) {
    char message[512];
    snprintf(message, sizeof(message), "%s|%s|%s|%s|%s|%lu", record->book_id, record->copy_id,
             record->member_id, record->action, record->due_date, record->nonce);
    ecdsa_sign_message(message, member->private_key, record->signature);
}

static void serialize_record_for_hash(const LendingRecord *record, char out[1024]) {
    snprintf(out, 1024,
             "%s|%s|%s|%s|%s|%s|%s|%s|%.2f|%lu",
             record->record_id,
             record->book_id,
             record->copy_id,
             record->book_title,
             record->member_id,
             record->member_name,
             record->action,
             record->due_date,
             record->fine_amount,
             record->nonce);
}

static int merkle_hash_pair(const char *left_hex, const char *right_hex, char out[HASH_LEN]) {
    char input[HASH_LEN * 2 + 1];
    uint8_t digest[32];
    size_t left_len = strlen(left_hex);
    size_t right_len = strlen(right_hex);
    if (left_len + right_len >= sizeof(input)) {
        return 0;
    }

    memcpy(input, left_hex, left_len);
    memcpy(input + left_len, right_hex, right_len);
    input[left_len + right_len] = '\0';
    sha256_hash_bytes((const uint8_t *)input, strlen(input), digest);
    bytes_to_hex(digest, 32, out, HASH_LEN);
    return 1;
}

static int has_proof_of_work(const char *hash, int difficulty) {
    int i;
    if (hash == NULL || difficulty < 0 || difficulty > HASH_LEN - 1) {
        return 0;
    }
    for (i = 0; i < difficulty; ++i) {
        if (hash[i] != '0') {
            return 0;
        }
    }
    return 1;
}

static void compute_merkle_root(const LendingRecord *records, int count, char out[HASH_LEN]) {
    char values[MAX_RECORDS][HASH_LEN];
    int i, j, level_count = count;

    if (count <= 0) {
        strcpy(out, "0000000000000000000000000000000000000000000000000000000000000000");
        return;
    }

    for (i = 0; i < count; ++i) {
        char serialized[1024];
        uint8_t digest[32];
        serialize_record_for_hash(&records[i], serialized);
        sha256_hash_bytes((const uint8_t *)serialized, strlen(serialized), digest);
        bytes_to_hex(digest, 32, values[i], HASH_LEN);
    }

    while (level_count > 1) {
        int next_level = 0;
        char next_values[MAX_RECORDS][HASH_LEN];
        for (i = 0; i < level_count; i += 2) {
            if (i + 1 < level_count) {
                merkle_hash_pair(values[i], values[i + 1], next_values[next_level]);
            } else {
                merkle_hash_pair(values[i], values[i], next_values[next_level]);
            }
            next_level++;
        }
        level_count = next_level;
        for (j = 0; j < level_count; ++j) {
            strcpy(values[j], next_values[j]);
        }
    }
    strcpy(out, values[0]);
}

static void init_member_keys(Member *member) {
    if (!ecdsa_generate_key(member->private_key, member->public_key)) {
        member->private_key[0] = '\0';
        member->public_key[0] = '\0';
    }
}

void library_init(Library *lib) {
    memset(lib, 0, sizeof(*lib));
    lib->chain.block_count = 0;
    lib->chain.next_index = 0;
}

Book *find_book(Library *lib, const char *book_id) {
    int i;
    if (lib == NULL || book_id == NULL) {
        return NULL;
    }
    for (i = 0; i < lib->book_count; ++i) {
        if (strcmp(lib->books[i].id, book_id) == 0) {
            return &lib->books[i];
        }
    }
    return NULL;
}

Member *find_member(Library *lib, const char *member_id) {
    int i;
    if (lib == NULL || member_id == NULL) {
        return NULL;
    }
    for (i = 0; i < lib->member_count; ++i) {
        if (strcmp(lib->members[i].id, member_id) == 0) {
            return &lib->members[i];
        }
    }
    return NULL;
}

Copy *find_copy(Library *lib, const char *copy_id) {
    int i;
    if (lib == NULL || copy_id == NULL) {
        return NULL;
    }
    for (i = 0; i < lib->copy_count; ++i) {
        if (strcmp(lib->copies[i].copy_id, copy_id) == 0) {
            return &lib->copies[i];
        }
    }
    return NULL;
}

Copy *find_available_copy(Library *lib, const char *book_id) {
    int i;
    if (lib == NULL || book_id == NULL) {
        return NULL;
    }
    for (i = 0; i < lib->copy_count; ++i) {
        if (strcmp(lib->copies[i].book_id, book_id) == 0 && lib->copies[i].status == COPY_AVAILABLE) {
            return &lib->copies[i];
        }
    }
    return NULL;
}

int add_book(Library *lib, const char *book_id, const char *title, const char *author) {
    Book *book;
    if (lib == NULL || book_id == NULL || title == NULL || author == NULL) {
        return 0;
    }
    if (find_book(lib, book_id) != NULL) {
        return 0;
    }
    if (lib->book_count >= MAX_BOOKS) {
        return 0;
    }
    book = &lib->books[lib->book_count++];
    snprintf(book->id, sizeof(book->id), "%s", book_id);
    snprintf(book->title, sizeof(book->title), "%s", title);
    snprintf(book->author, sizeof(book->author), "%s", author);
    return 1;
}

int add_member(Library *lib, const char *member_id, const char *name, const char *course) {
    Member *member;
    if (lib == NULL || member_id == NULL || name == NULL || course == NULL) {
        return 0;
    }
    if (find_member(lib, member_id) != NULL) {
        return 0;
    }
    if (lib->member_count >= MAX_MEMBERS) {
        return 0;
    }
    member = &lib->members[lib->member_count++];
    snprintf(member->id, sizeof(member->id), "%s", member_id);
    snprintf(member->name, sizeof(member->name), "%s", name);
    snprintf(member->course, sizeof(member->course), "%s", course);
    init_member_keys(member);
    member->nonce = 0;
    return 1;
}

int add_copy(Library *lib, const char *copy_id, const char *book_id) {
    Copy *copy;
    Book *book;
    if (lib == NULL || copy_id == NULL || book_id == NULL) {
        return 0;
    }
    book = find_book(lib, book_id);
    if (book == NULL) {
        return 0;
    }
    if (find_copy(lib, copy_id) != NULL) {
        return 0;
    }
    if (lib->copy_count >= MAX_COPIES) {
        return 0;
    }
    copy = &lib->copies[lib->copy_count++];
    snprintf(copy->copy_id, sizeof(copy->copy_id), "%s", copy_id);
    snprintf(copy->book_id, sizeof(copy->book_id), "%s", book_id);
    copy->status = COPY_AVAILABLE;
    copy->borrower_id[0] = '\0';
    copy->due_date[0] = '\0';
    copy->renewal_count = 0;
    copy->reserved_count = 0;
    return 1;
}

int load_registries(Library *lib, const char *books_path, const char *members_path, const char *copies_path) {
    FILE *book_file;
    FILE *member_file;
    FILE *copy_file;
    char line[512];

    if (lib == NULL) {
        return 0;
    }

    if ((book_file = fopen(books_path, "r")) == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), book_file) != NULL) {
        char *parts[3] = {0};
        char *token;
        char *saveptr = NULL;
        int idx = 0;
        trim_in_place(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        token = strtok_s(line, ",", &saveptr);
        while (token != NULL && idx < 3) {
            trim_in_place(token);
            parts[idx++] = token;
            token = strtok_s(NULL, ",", &saveptr);
        }
        if (idx >= 3) {
            add_book(lib, parts[0], parts[1], parts[2]);
        }
    }
    fclose(book_file);

    if ((member_file = fopen(members_path, "r")) == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), member_file) != NULL) {
        char *parts[3] = {0};
        char *token;
        char *saveptr = NULL;
        int idx = 0;
        trim_in_place(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        token = strtok_s(line, ",", &saveptr);
        while (token != NULL && idx < 3) {
            trim_in_place(token);
            parts[idx++] = token;
            token = strtok_s(NULL, ",", &saveptr);
        }
        if (idx >= 3) {
            add_member(lib, parts[0], parts[1], parts[2]);
        }
    }
    fclose(member_file);

    if ((copy_file = fopen(copies_path, "r")) == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), copy_file) != NULL) {
        char *parts[8] = {0};
        char *token;
        char *saveptr = NULL;
        int idx = 0;
        trim_in_place(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        token = strtok_s(line, ",", &saveptr);
        while (token != NULL && idx < 8) {
            trim_in_place(token);
            parts[idx++] = token;
            token = strtok_s(NULL, ",", &saveptr);
        }
        if (idx >= 2) {
            Copy *copy = NULL;
            add_copy(lib, parts[0], parts[1]);
            copy = find_copy(lib, parts[0]);
            if (copy != NULL) {
                if (idx >= 3) {
                    if (strcmp(parts[2], "BORROWED") == 0) {
                        copy->status = COPY_BORROWED;
                    } else if (strcmp(parts[2], "RESERVED") == 0) {
                        copy->status = COPY_RESERVED;
                    } else {
                        copy->status = COPY_AVAILABLE;
                    }
                }
                if (idx >= 4) {
                    snprintf(copy->borrower_id, sizeof(copy->borrower_id), "%s", parts[3]);
                }
                if (idx >= 5) {
                    snprintf(copy->due_date, sizeof(copy->due_date), "%s", parts[4]);
                }
                if (idx >= 6) {
                    copy->renewal_count = atoi(parts[5]);
                }
                if (idx >= 7) {
                    copy->reserved_count = atoi(parts[6]);
                }
            }
        }
    }
    fclose(copy_file);
    return 1;
}

int save_state(const Library *lib, const char *path) {
    FILE *fp;
    StateHeader header;
    unsigned char checksum[SHA256_DIGEST_LEN];

    if (lib == NULL || path == NULL) {
        return 0;
    }

    memset(&header, 0, sizeof(header));
    memcpy(header.magic, STATE_MAGIC, sizeof(header.magic));
    header.version = STATE_VERSION;
    header.payload_size = (uint32_t)sizeof(*lib);
    sha256_hash_bytes((const uint8_t *)lib, sizeof(*lib), checksum);
    memcpy(header.checksum, checksum, sizeof(header.checksum));

    fp = fopen(path, "wb");
    if (fp == NULL) {
        return 0;
    }
    if (fwrite(&header, sizeof(header), 1, fp) != 1 ||
        fwrite(lib, sizeof(*lib), 1, fp) != 1) {
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return 1;
}

int load_state(Library *lib, const char *path) {
    FILE *fp;
    StateHeader header;
    Library *candidate;
    unsigned char checksum[SHA256_DIGEST_LEN];

    if (lib == NULL || path == NULL) {
        return 0;
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return 0;
    }
    candidate = malloc(sizeof(*candidate));
    if (candidate == NULL) {
        fclose(fp);
        return 0;
    }
    if (fread(&header, sizeof(header), 1, fp) != 1 ||
        memcmp(header.magic, STATE_MAGIC, sizeof(header.magic)) != 0 ||
        header.version != STATE_VERSION ||
        header.payload_size != sizeof(*candidate) ||
        fread(candidate, sizeof(*candidate), 1, fp) != 1) {
        fclose(fp);
        free(candidate);
        return 0;
    }
    fclose(fp);

    if (candidate->book_count < 0 || candidate->book_count > MAX_BOOKS ||
        candidate->member_count < 0 || candidate->member_count > MAX_MEMBERS ||
        candidate->copy_count < 0 || candidate->copy_count > MAX_COPIES ||
        candidate->pending_count < 0 || candidate->pending_count > MAX_PENDING ||
        candidate->chain.block_count < 0 || candidate->chain.block_count > MAX_BLOCKS ||
        candidate->chain.next_index < 0) {
        free(candidate);
        return 0;
    }
    sha256_hash_bytes((const uint8_t *)candidate, sizeof(*candidate), checksum);
    if (memcmp(header.checksum, checksum, sizeof(checksum)) != 0) {
        free(candidate);
        return 0;
    }
    *lib = *candidate;
    free(candidate);
    return 1;
}

static void add_pending_request(Library *lib, const char *book_id, const char *copy_id, const char *member_id,
                                const char *action, int priority) {
    PendingRequest *request;
    char request_id[HASH_LEN];

    if (lib->pending_count >= MAX_PENDING) {
        return;
    }

    request = &lib->pending[lib->pending_count++];
    generate_request_id(book_id, copy_id, member_id, action, request_id);
    snprintf(request->request_id, sizeof(request->request_id), "%s", request_id);
    snprintf(request->book_id, sizeof(request->book_id), "%s", book_id);
    snprintf(request->copy_id, sizeof(request->copy_id), "%s", copy_id);
    snprintf(request->member_id, sizeof(request->member_id), "%s", member_id);
    snprintf(request->action_requested, sizeof(request->action_requested), "%s", action);
    request->priority = priority;
    snprintf(request->status, sizeof(request->status), "%s", "PENDING");
}

static PendingRequest *find_pending_request(Library *lib, const char *request_id) {
    int i;
    if (lib == NULL || request_id == NULL) {
        return NULL;
    }
    for (i = 0; i < lib->pending_count; ++i) {
        if (strcmp(lib->pending[i].request_id, request_id) == 0) {
            return &lib->pending[i];
        }
    }
    return NULL;
}

static void assign_next_reservation(Copy *copy) {
    int i;
    if (copy == NULL) {
        return;
    }
    if (copy->reserved_count > 0) {
        for (i = 0; i < copy->reserved_count; ++i) {
            if (copy->reservation_queue[i][0] != '\0') {
                snprintf(copy->borrower_id, sizeof(copy->borrower_id), "%s", copy->reservation_queue[i]);
                copy->status = COPY_BORROWED;
                copy->due_date[0] = '\0';
                add_days_to_date(copy->due_date, 14);
                copy->reservation_queue[i][0] = '\0';
                memmove(copy->reservation_queue, copy->reservation_queue + i + 1, (copy->reserved_count - i - 1) * ID_LEN);
                copy->reserved_count--;
                return;
            }
        }
    }
}

int borrow_book(Library *lib, const char *book_id, const char *member_id) {
    Book *book;
    Member *member;
    Copy *copy;
    LendingRecord record;
    char due_date[DATE_LEN];
    char message[512];

    if (lib == NULL || book_id == NULL || member_id == NULL) {
        return 0;
    }

    book = find_book(lib, book_id);
    member = find_member(lib, member_id);
    if (book == NULL || member == NULL) {
        fprintf(stderr, "Error: invalid book or member.\n");
        return 0;
    }

    copy = find_available_copy(lib, book_id);
    if (copy == NULL) {
        fprintf(stderr, "Error: no available copy for this book.\n");
        return 0;
    }

    add_days_to_date(due_date, 14);
    copy->status = COPY_BORROWED;
    snprintf(copy->borrower_id, sizeof(copy->borrower_id), "%s", member_id);
    snprintf(copy->due_date, sizeof(copy->due_date), "%s", due_date);
    snprintf(copy->due_date, sizeof(copy->due_date), "%s", due_date);

    memset(&record, 0, sizeof(record));
    snprintf(record.book_id, sizeof(record.book_id), "%s", book_id);
    snprintf(record.copy_id, sizeof(record.copy_id), "%s", copy->copy_id);
    snprintf(record.book_title, sizeof(record.book_title), "%s", book->title);
    snprintf(record.member_id, sizeof(record.member_id), "%s", member_id);
    snprintf(record.member_name, sizeof(record.member_name), "%s", member->name);
    snprintf(record.action, sizeof(record.action), "%s", "BORROWED");
    snprintf(record.due_date, sizeof(record.due_date), "%s", due_date);
    record.fine_amount = 0.0;
    record.nonce = member->nonce++;
    generate_record_id(book_id, copy->copy_id, member_id, "BORROWED", due_date, record.nonce, record.record_id);
    build_record_signature(&record, member);

    snprintf(message, sizeof(message), "%s|%s|%s|%s|%s|%lu", record.book_id, record.copy_id, record.member_id,
             record.action, record.due_date, record.nonce);
    if (!ecdsa_verify_message(message, member->public_key, record.signature)) {
        fprintf(stderr, "Error: signature validation failed for borrow record.\n");
        return 0;
    }

    add_pending_request(lib, book_id, copy->copy_id, member_id, "BORROWED", 0);
    printf("Borrow request queued: %s -> %s due %s\n", member_id, copy->copy_id, due_date);
    return 1;
}

int reserve_book(Library *lib, const char *book_id, const char *member_id) {
    Book *book;
    Member *member;
    Copy *copy = NULL;
    int i;

    if (lib == NULL || book_id == NULL || member_id == NULL) {
        return 0;
    }
    book = find_book(lib, book_id);
    member = find_member(lib, member_id);
    if (book == NULL || member == NULL) {
        fprintf(stderr, "Error: invalid book or member.\n");
        return 0;
    }

    if (find_available_copy(lib, book_id) != NULL) {
        printf("Book %s has an available copy; reservation is unnecessary.\n", book_id);
        return 1;
    }

    for (i = 0; i < lib->copy_count; ++i) {
        if (strcmp(lib->copies[i].book_id, book_id) == 0) {
            copy = &lib->copies[i];
            break;
        }
    }
    if (copy == NULL) {
        fprintf(stderr, "Error: no copies exist for this title.\n");
        return 0;
    }

    if (copy->reserved_count < MAX_QUEUE) {
        snprintf(copy->reservation_queue[copy->reserved_count++], ID_LEN, "%s", member_id);
        copy->status = COPY_RESERVED;
        add_pending_request(lib, book_id, copy->copy_id, member_id, "RESERVED", 1);
        printf("Reservation added for member %s on copy %s.\n", member_id, copy->copy_id);
        return 1;
    }

    fprintf(stderr, "Error: reservation queue is full.\n");
    return 0;
}

int return_book(Library *lib, const char *copy_id, const char *member_id) {
    Copy *copy;
    Book *book;
    Member *member;
    LendingRecord record;
    double fine_amount = 0.0;
    char due_date[DATE_LEN];
    char message[512];
    int overdue_days;

    if (lib == NULL || copy_id == NULL || member_id == NULL) {
        return 0;
    }

    copy = find_copy(lib, copy_id);
    member = find_member(lib, member_id);
    if (copy == NULL || member == NULL) {
        fprintf(stderr, "Error: invalid copy or member.\n");
        return 0;
    }

    if (strcmp(copy->borrower_id, member_id) != 0) {
        fprintf(stderr, "Error: member is not the current borrower for this copy.\n");
        return 0;
    }

    book = find_book(lib, copy->book_id);
    if (book == NULL) {
        fprintf(stderr, "Error: book record not found.\n");
        return 0;
    }

    overdue_days = compute_late_days(copy->due_date);
    fine_amount = overdue_days > 0 ? overdue_days * 2.5 : 0.0;
    member->outstanding_fine += fine_amount;
    snprintf(due_date, sizeof(due_date), "%s", copy->due_date);

    memset(&record, 0, sizeof(record));
    snprintf(record.book_id, sizeof(record.book_id), "%s", copy->book_id);
    snprintf(record.copy_id, sizeof(record.copy_id), "%s", copy->copy_id);
    snprintf(record.book_title, sizeof(record.book_title), "%s", book->title);
    snprintf(record.member_id, sizeof(record.member_id), "%s", member_id);
    snprintf(record.member_name, sizeof(record.member_name), "%s", member->name);
    snprintf(record.action, sizeof(record.action), "%s", "RETURNED");
    snprintf(record.due_date, sizeof(record.due_date), "%s", due_date);
    record.fine_amount = fine_amount;
    record.nonce = member->nonce++;
    generate_record_id(copy->book_id, copy->copy_id, member_id, "RETURNED", due_date, record.nonce, record.record_id);
    build_record_signature(&record, member);

    snprintf(message, sizeof(message), "%s|%s|%s|%s|%s|%lu", record.book_id, record.copy_id, record.member_id,
             record.action, record.due_date, record.nonce);
    if (!ecdsa_verify_message(message, member->public_key, record.signature)) {
        fprintf(stderr, "Error: signature validation failed for return record.\n");
        return 0;
    }

    copy->status = COPY_AVAILABLE;
    copy->borrower_id[0] = '\0';
    copy->due_date[0] = '\0';
    if (copy->reserved_count > 0) {
        assign_next_reservation(copy);
    }

    add_pending_request(lib, copy->book_id, copy->copy_id, member_id, "RETURNED", overdue_days > 0 ? 3 : 0);
    printf("Return recorded for copy %s. Fine: %.2f\n", copy->copy_id, fine_amount);
    return 1;
}

int renew_book(Library *lib, const char *copy_id, const char *member_id) {
    Copy *copy;
    Member *member;
    Book *book;
    LendingRecord record;
    char due_date[DATE_LEN];
    char message[512];

    if (lib == NULL || copy_id == NULL || member_id == NULL) {
        return 0;
    }

    copy = find_copy(lib, copy_id);
    member = find_member(lib, member_id);
    book = find_book(lib, copy->book_id);
    if (copy == NULL || member == NULL || book == NULL) {
        fprintf(stderr, "Error: invalid copy or member.\n");
        return 0;
    }

    if (strcmp(copy->borrower_id, member_id) != 0) {
        fprintf(stderr, "Error: member does not own the copy.\n");
        return 0;
    }
    if (copy->renewal_count >= 2) {
        fprintf(stderr, "Error: renewal limit reached.\n");
        return 0;
    }
    if (copy->reserved_count > 0) {
        fprintf(stderr, "Error: copy has pending reservations.\n");
        return 0;
    }

    add_days_to_date(due_date, 14);
    snprintf(copy->due_date, sizeof(copy->due_date), "%s", due_date);
    copy->renewal_count++;

    memset(&record, 0, sizeof(record));
    snprintf(record.book_id, sizeof(record.book_id), "%s", copy->book_id);
    snprintf(record.copy_id, sizeof(record.copy_id), "%s", copy->copy_id);
    snprintf(record.book_title, sizeof(record.book_title), "%s", book->title);
    snprintf(record.member_id, sizeof(record.member_id), "%s", member_id);
    snprintf(record.member_name, sizeof(record.member_name), "%s", member->name);
    snprintf(record.action, sizeof(record.action), "%s", "RENEWED");
    snprintf(record.due_date, sizeof(record.due_date), "%s", due_date);
    record.fine_amount = 0.0;
    record.nonce = member->nonce++;
    generate_record_id(copy->book_id, copy->copy_id, member_id, "RENEWED", due_date, record.nonce, record.record_id);
    build_record_signature(&record, member);

    snprintf(message, sizeof(message), "%s|%s|%s|%s|%s|%lu", record.book_id, record.copy_id, record.member_id,
             record.action, record.due_date, record.nonce);
    if (!ecdsa_verify_message(message, member->public_key, record.signature)) {
        fprintf(stderr, "Error: signature validation failed for renewal record.\n");
        return 0;
    }

    add_pending_request(lib, copy->book_id, copy->copy_id, member_id, "RENEWED", 2);
    printf("Renewal applied to copy %s. New due date: %s\n", copy->copy_id, due_date);
    return 1;
}

int scan_overdue(Library *lib) {
    int i;
    int flagged = 0;
    if (lib == NULL) {
        return 0;
    }
    for (i = 0; i < lib->copy_count; ++i) {
        Copy *copy = &lib->copies[i];
        if (copy->status == COPY_BORROWED && copy->due_date[0] != '\0') {
            int overdue_days = compute_late_days(copy->due_date);
            if (overdue_days > 0) {
                double fine = overdue_days * 2.5;
                Member *member = find_member(lib, copy->borrower_id);
                Book *book = find_book(lib, copy->book_id);
                if (member != NULL && book != NULL) {
                    LendingRecord record;
                    char message[512];
                    memset(&record, 0, sizeof(record));
                    snprintf(record.book_id, sizeof(record.book_id), "%s", copy->book_id);
                    snprintf(record.copy_id, sizeof(record.copy_id), "%s", copy->copy_id);
                    snprintf(record.book_title, sizeof(record.book_title), "%s", book->title);
                    snprintf(record.member_id, sizeof(record.member_id), "%s", copy->borrower_id);
                    snprintf(record.member_name, sizeof(record.member_name), "%s", member->name);
                    snprintf(record.action, sizeof(record.action), "%s", "OVERDUE");
                    snprintf(record.due_date, sizeof(record.due_date), "%s", copy->due_date);
                    record.fine_amount = fine;
                    member->outstanding_fine += fine;
                    record.nonce = member->nonce++;
                    generate_record_id(copy->book_id, copy->copy_id, copy->borrower_id, "OVERDUE", copy->due_date, record.nonce, record.record_id);
                    build_record_signature(&record, member);
                    snprintf(message, sizeof(message), "%s|%s|%s|%s|%s|%lu", record.book_id, record.copy_id, record.member_id,
                             record.action, record.due_date, record.nonce);
                    if (ecdsa_verify_message(message, member->public_key, record.signature)) {
                        add_pending_request(lib, copy->book_id, copy->copy_id, copy->borrower_id, "OVERDUE", 4);
                        printf("Overdue flag created for copy %s: %d day(s), fine %.2f\n", copy->copy_id, overdue_days, fine);
                        flagged++;
                    }
                }
            }
        }
    }
    return flagged;
}

int mine_pending(Library *lib, const char *miner_id) {
    Block block;
    int i;
    int count = 0;
    char previous_hash[HASH_LEN] = "GENESIS";
    char rewards[512] = {0};
    char block_header[2048];
    uint8_t digest[32];
    unsigned long attempts = 0;
    if (lib == NULL || miner_id == NULL) {
        return 0;
    }
    if (lib->pending_count == 0) {
        printf("No pending actions to mine.\n");
        return 0;
    }

    memset(&block, 0, sizeof(block));
    block.index = lib->chain.block_count;
    block.timestamp = time(NULL);
    if (lib->chain.block_count > 0) {
        snprintf(previous_hash, sizeof(previous_hash), "%s", lib->chain.blocks[lib->chain.block_count - 1].hash);
    }
    snprintf(block.previous_hash, sizeof(block.previous_hash), "%s", previous_hash);
    snprintf(block.sealed_by, sizeof(block.sealed_by), "%s", miner_id);

    for (i = 0; i < lib->pending_count && count < MAX_RECORDS; ++i) {
        PendingRequest *request = &lib->pending[i];
        Book *book;
        Member *member;
        Copy *copy;
        if (strcmp(request->status, "PENDING") != 0) {
            continue;
        }
        book = find_book(lib, request->book_id);
        member = find_member(lib, request->member_id);
        copy = find_copy(lib, request->copy_id);
        if (book == NULL || member == NULL || copy == NULL) {
            continue;
        }

        memset(&block.records[count], 0, sizeof(block.records[count]));
        snprintf(block.records[count].book_id, sizeof(block.records[count].book_id), "%s", request->book_id);
        snprintf(block.records[count].copy_id, sizeof(block.records[count].copy_id), "%s", request->copy_id);
        snprintf(block.records[count].book_title, sizeof(block.records[count].book_title), "%s", book->title);
        snprintf(block.records[count].member_id, sizeof(block.records[count].member_id), "%s", request->member_id);
        snprintf(block.records[count].member_name, sizeof(block.records[count].member_name), "%s", member->name);
        snprintf(block.records[count].action, sizeof(block.records[count].action), "%s", request->action_requested);
        snprintf(block.records[count].due_date, sizeof(block.records[count].due_date), "%s", copy->due_date[0] != '\0' ? copy->due_date : copy_today());
        block.records[count].fine_amount = 0.0;
        block.records[count].nonce = member->nonce++;
        generate_record_id(request->book_id, request->copy_id, request->member_id, request->action_requested,
                           block.records[count].due_date, block.records[count].nonce, block.records[count].record_id);
        build_record_signature(&block.records[count], member);

        if (strcmp(request->action_requested, "RETURNED") == 0 || strcmp(request->action_requested, "OVERDUE") == 0) {
            block.token_reward += 10;
            snprintf(rewards + strlen(rewards), sizeof(rewards) - strlen(rewards), "%s:%d;", request->copy_id, 10);
            block.records[count].fine_amount = strcmp(request->action_requested, "OVERDUE") == 0 ? 2.5 : 0.0;
        } else if (strcmp(request->action_requested, "BORROWED") == 0) {
            block.token_reward += 0;
        }
        count++;
        request->priority = 0;
        snprintf(request->status, sizeof(request->status), "%s", "CONFIRMED");
    }

    if (count == 0) {
        return 0;
    }

    block.record_count = count;
    block.difficulty = BLOCK_DIFFICULTY;
    compute_merkle_root(block.records, count, block.merkle_root);
    snprintf(block.transaction_id, sizeof(block.transaction_id), "%s", "reward");
    hash_string(rewards, block.transaction_id);
    for (block.proof_nonce = 0u;; ++block.proof_nonce) {
        attempts++;
        snprintf(block_header, sizeof(block_header), "%d|%lld|%d|%s|%s|%s|%d|%s|%lu|%d",
                 block.index,
                 (long long)block.timestamp,
                 block.record_count,
                 block.previous_hash,
                 block.merkle_root,
                 block.sealed_by,
                 block.token_reward,
                 block.transaction_id,
                 block.proof_nonce,
                 block.difficulty);
        sha256_hash_bytes((const uint8_t *)block_header, strlen(block_header), digest);
        bytes_to_hex(digest, 32, block.hash, HASH_LEN);
        if (has_proof_of_work(block.hash, block.difficulty)) {
            break;
        }
    }

    lib->chain.blocks[lib->chain.block_count++] = block;
    lib->pending_count = 0;
    printf("Block #%d mined by %s with %d record(s), reward=%d tokens, attempts=%lu.\n",
           block.index, miner_id, count, block.token_reward, attempts);
    return 1;
}

int mine_pending_solo(Library *lib, const char *miner_id) {
    printf("Solo mining started: difficulty=%d\n", BLOCK_DIFFICULTY);
    return mine_pending(lib, miner_id);
}

int mine_pending_pool(Library *lib, const char *miner_id, int workers) {
    int result;
    if (workers < 1) {
        fprintf(stderr, "Error: pool worker count must be positive.\n");
        return 0;
    }
    printf("Pool mining started: workers=%d, difficulty=%d\n", workers, BLOCK_DIFFICULTY);
    result = mine_pending(lib, miner_id);
    if (result && lib->chain.block_count > 0) {
        Block *block = &lib->chain.blocks[lib->chain.block_count - 1];
        printf("Reward-sharing table\n");
        printf("Worker\tShare\n%s\t%d\n", miner_id, block->token_reward);
        if (workers > 1) {
            printf("Each of %d registered workers receives an equal conceptual share of %.2f tokens.\n",
                   workers, (double)block->token_reward / workers);
        }
    }
    return result;
}

int mine_pending_cloud(Library *lib, const char *miner_id, int rounds) {
    int round;
    int completed = 0;
    int earnings = 0;
    if (rounds < 1) {
        fprintf(stderr, "Error: cloud mining rounds must be positive.\n");
        return 0;
    }
    printf("Cloud mining started: rounds=%d, difficulty=%d\n", rounds, BLOCK_DIFFICULTY);
    for (round = 1; round <= rounds; ++round) {
        int before = lib->chain.block_count;
        if (mine_pending(lib, miner_id)) {
            completed++;
            earnings += lib->chain.blocks[before].token_reward;
        } else {
            printf("Cloud round %d: no pending transactions.\n", round);
        }
    }
    printf("Cloud earnings summary: completed_rounds=%d total_tokens=%d\n", completed, earnings);
    return 1;
}

int settle_fine(Library *lib, const char *member_id, double amount) {
    Member *member;
    if (lib == NULL || member_id == NULL || amount <= 0.0) {
        return 0;
    }
    member = find_member(lib, member_id);
    if (member == NULL || member->outstanding_fine <= 0.0 || amount > member->outstanding_fine) {
        fprintf(stderr, "Error: invalid member or settlement amount.\n");
        return 0;
    }
    member->outstanding_fine -= amount;
    printf("Fine settled for %s: %.2f paid, %.2f remaining.\n",
           member_id, amount, member->outstanding_fine);
    return 1;
}

int flag_request_suspicious(Library *lib, const char *request_id) {
    PendingRequest *request = find_pending_request(lib, request_id);
    if (request == NULL || strcmp(request->status, "PENDING") != 0) {
        fprintf(stderr, "Error: pending request not found.\n");
        return 0;
    }
    snprintf(request->status, sizeof(request->status), "%s", "SUSPICIOUS");
    request->priority = 99;
    printf("Fraud flag raised for request %s; manual review required.\n", request_id);
    return 1;
}

int review_request(Library *lib, const char *request_id, const char *decision) {
    PendingRequest *request = find_pending_request(lib, request_id);
    if (request == NULL || strcmp(request->status, "SUSPICIOUS") != 0 ||
        (strcmp(decision, "approve") != 0 && strcmp(decision, "reject") != 0)) {
        fprintf(stderr, "Error: suspicious request or review decision is invalid.\n");
        return 0;
    }
    if (strcmp(decision, "approve") == 0) {
        snprintf(request->status, sizeof(request->status), "%s", "PENDING");
        request->priority = 0;
    } else {
        snprintf(request->status, sizeof(request->status), "%s", "REJECTED");
    }
    printf("Manual review: request %s -> %s.\n", request_id, decision);
    return 1;
}

int validate_chain(const Library *lib) {
    int i;
    if (lib == NULL) {
        return 0;
    }
    for (i = 0; i < lib->chain.block_count; ++i) {
        Block block = lib->chain.blocks[i];
        char recomputed[HASH_LEN];
        char merkle[HASH_LEN];
        char header[2048];
        uint8_t digest[32];
        if (block.index != i) {
            return 0;
        }
        if (i > 0 && strcmp(block.previous_hash, lib->chain.blocks[i - 1].hash) != 0) {
            return 0;
        }
        compute_merkle_root(block.records, block.record_count, merkle);
        if (strcmp(block.merkle_root, merkle) != 0) {
            return 0;
        }
        snprintf(header, sizeof(header), "%d|%lld|%d|%s|%s|%s|%d|%s|%lu|%d",
                 block.index,
                 (long long)block.timestamp,
                 block.record_count,
                 block.previous_hash,
                 block.merkle_root,
                 block.sealed_by,
                 block.token_reward,
                 block.transaction_id,
                 block.proof_nonce,
                 block.difficulty);
        sha256_hash_bytes((const uint8_t *)header, strlen(header), digest);
        bytes_to_hex(digest, 32, recomputed, HASH_LEN);
        if (strcmp(block.hash, recomputed) != 0) {
            return 0;
        }
        if (!has_proof_of_work(block.hash, block.difficulty)) {
            return 0;
        }
    }
    return 1;
}

void print_library_summary(const Library *lib) {
    int i;
    puts("Library status");
    printf("Books: %d\n", lib->book_count);
    printf("Members: %d\n", lib->member_count);
    printf("Copies: %d\n", lib->copy_count);
    printf("Pending requests: %d\n", lib->pending_count);
    printf("Blocks mined: %d\n", lib->chain.block_count);
    for (i = 0; i < lib->copy_count; ++i) {
        const Copy *copy = &lib->copies[i];
        printf("Copy %s | status=%d | borrower=%s | due=%s\n", copy->copy_id, copy->status, copy->borrower_id, copy->due_date);
    }
}

void print_pending_requests(const Library *lib) {
    int i;
    if (lib == NULL) {
        return;
    }
    for (i = 0; i < lib->pending_count; ++i) {
        const PendingRequest *request = &lib->pending[i];
        printf("%s | priority=%d | %s | %s | %s | %s\n", request->request_id, request->priority,
               request->book_id, request->copy_id, request->member_id, request->status);
    }
}
