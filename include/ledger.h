#ifndef LEDGER_H
#define LEDGER_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "ecdsa.h"
#include "sha256.h"

#define MAX_BOOKS 128
#define MAX_MEMBERS 128
#define MAX_COPIES 512
#define MAX_PENDING 256
#define MAX_BLOCKS 1024
#define MAX_RECORDS 32
#define MAX_QUEUE 64
#define BLOCK_DIFFICULTY 2

#define ACTION_NAME_LEN 16
#define ID_LEN 32
#define TITLE_LEN 128
#define NAME_LEN 128
#define COURSE_LEN 64
#define DATE_LEN 32
#define HASH_LEN 65
#define SIG_LEN ECDSA_SIG_HEX_LEN

typedef enum {
    COPY_AVAILABLE = 0,
    COPY_BORROWED = 1,
    COPY_RESERVED = 2
} CopyStatus;

typedef enum {
    ACTION_BORROWED = 0,
    ACTION_RETURNED = 1,
    ACTION_RESERVED = 2,
    ACTION_RENEWED = 3,
    ACTION_OVERDUE = 4
} ActionType;

typedef enum {
    REQUEST_PENDING = 0,
    REQUEST_CONFIRMED = 1,
    REQUEST_SUSPICIOUS = 2
} RequestStatus;

typedef struct {
    char id[ID_LEN];
    char title[TITLE_LEN];
    char author[NAME_LEN];
} Book;

typedef struct {
    char id[ID_LEN];
    char name[NAME_LEN];
    char course[COURSE_LEN];
    char private_key[ECDSA_PRIVATE_KEY_LEN];
    char public_key[ECDSA_PUBLIC_KEY_LEN];
    unsigned long nonce;
} Member;

typedef struct {
    char copy_id[ID_LEN];
    char book_id[ID_LEN];
    char borrower_id[ID_LEN];
    CopyStatus status;
    char due_date[DATE_LEN];
    int renewal_count;
    int reserved_count;
    char reservation_queue[MAX_QUEUE][ID_LEN];
} Copy;

typedef struct {
    char record_id[HASH_LEN];
    char book_id[ID_LEN];
    char copy_id[ID_LEN];
    char book_title[TITLE_LEN];
    char member_id[ID_LEN];
    char member_name[NAME_LEN];
    char action[ACTION_NAME_LEN];
    char due_date[DATE_LEN];
    double fine_amount;
    unsigned long nonce;
    char signature[SIG_LEN];
} LendingRecord;

typedef struct {
    char request_id[HASH_LEN];
    char book_id[ID_LEN];
    char copy_id[ID_LEN];
    char member_id[ID_LEN];
    char action_requested[ACTION_NAME_LEN];
    int priority;
    char status[ACTION_NAME_LEN];
} PendingRequest;

typedef struct {
    int index;
    time_t timestamp;
    int record_count;
    char previous_hash[HASH_LEN];
    char merkle_root[HASH_LEN];
    char hash[HASH_LEN];
    char sealed_by[ID_LEN];
    int token_reward;
    char transaction_id[HASH_LEN];
    unsigned long proof_nonce;
    int difficulty;
    LendingRecord records[MAX_RECORDS];
} Block;

typedef struct {
    Block blocks[MAX_BLOCKS];
    int block_count;
    int next_index;
} Blockchain;

typedef struct {
    Book books[MAX_BOOKS];
    int book_count;
    Member members[MAX_MEMBERS];
    int member_count;
    Copy copies[MAX_COPIES];
    int copy_count;
    PendingRequest pending[MAX_PENDING];
    int pending_count;
    Blockchain chain;
} Library;

void library_init(Library *lib);
int load_registries(Library *lib, const char *books_path, const char *members_path, const char *copies_path);
int save_state(const Library *lib, const char *path);
int load_state(Library *lib, const char *path);
int add_book(Library *lib, const char *book_id, const char *title, const char *author);
int add_member(Library *lib, const char *member_id, const char *name, const char *course);
int add_copy(Library *lib, const char *copy_id, const char *book_id);
Book *find_book(Library *lib, const char *book_id);
Member *find_member(Library *lib, const char *member_id);
Copy *find_copy(Library *lib, const char *copy_id);
Copy *find_available_copy(Library *lib, const char *book_id);
int borrow_book(Library *lib, const char *book_id, const char *member_id);
int reserve_book(Library *lib, const char *book_id, const char *member_id);
int return_book(Library *lib, const char *copy_id, const char *member_id);
int renew_book(Library *lib, const char *copy_id, const char *member_id);
int scan_overdue(Library *lib);
int mine_pending(Library *lib, const char *miner_id);
int validate_chain(const Library *lib);
void print_library_summary(const Library *lib);
void print_pending_requests(const Library *lib);

#endif
