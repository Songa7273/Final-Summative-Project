#include "ledger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEFAULT_STATE_PATH "state.txt"

static int load_default_state(Library *lib) {
    FILE *state = fopen(DEFAULT_STATE_PATH, "rb");
    int loaded;
    if (state != NULL) {
        fclose(state);
        loaded = load_state(lib, DEFAULT_STATE_PATH);
        if (!loaded) {
            fprintf(stderr, "Error: default state is corrupt or incompatible.\n");
        }
        return loaded;
    }
    return load_registries(lib, "books.txt", "members.txt", "copies.txt");
}

static int save_default_state(const Library *lib) {
    if (!save_state(lib, DEFAULT_STATE_PATH)) {
        fprintf(stderr, "Error: unable to persist default state.\n");
        return 0;
    }
    return 1;
}

static void print_usage(const char *program_name) {
    printf("Usage:\n");
    printf("  %s seed\n", program_name);
    printf("  %s demo\n", program_name);
    printf("  %s load\n", program_name);
    printf("  %s borrow <book_id> <member_id>\n", program_name);
    printf("  %s borrow_book <book_id> <member_id>\n", program_name);
    printf("  %s return <copy_id> <member_id>\n", program_name);
    printf("  %s return_book <copy_id> <member_id>\n", program_name);
    printf("  %s reserve <book_id> <member_id>\n", program_name);
    printf("  %s reserve_book <book_id> <member_id>\n", program_name);
    printf("  %s renew <copy_id> <member_id>\n", program_name);
    printf("  %s renew_book <copy_id> <member_id>\n", program_name);
    printf("  %s overdue\n", program_name);
    printf("  %s check_overdue\n", program_name);
    printf("  %s mine <miner_id>\n", program_name);
    printf("  %s mine_solo <miner_id>\n", program_name);
    printf("  %s mine_pool <miner_id>\n", program_name);
    printf("  %s mine_cloud <miner_id> <rounds>\n", program_name);
    printf("  %s settle-fine <member_id> <amount>\n", program_name);
    printf("  %s flag-fraud <request_id>\n", program_name);
    printf("  %s review-fraud <request_id> <approve|reject>\n", program_name);
    printf("  %s verify\n", program_name);
    printf("  %s validate_chain\n", program_name);
    printf("  %s list\n", program_name);
    printf("  %s chain_view\n", program_name);
    printf("  %s pool_view\n", program_name);
    printf("  %s add-book <book_id> <title> <author>\n", program_name);
    printf("  %s register_book <book_id> <title> <author>\n", program_name);
    printf("  %s add-member <member_id> <name> <course>\n", program_name);
    printf("  %s register_member <member_id> <name> <course>\n", program_name);
    printf("  %s add-copy <copy_id> <book_id>\n", program_name);
    printf("  %s save <path>\n", program_name);
    printf("  %s load_state <path>\n", program_name);
}

static int create_sample_files(void) {
    FILE *books = fopen("books.txt", "w");
    FILE *members = fopen("members.txt", "w");
    FILE *copies = fopen("copies.txt", "w");
    int ok = 1;

    if (books != NULL) {
        fprintf(books, "B001,The Hobbit,J.R.R. Tolkien\n");
        fprintf(books, "B002,Algorithms,Robert Sedgewick\n");
        fclose(books);
    } else {
        ok = 0;
    }

    if (members != NULL) {
        fprintf(members, "M001,Alice Njeri,CS\n");
        fprintf(members, "M002,Sam Osei,SE\n");
        fclose(members);
    } else {
        ok = 0;
    }

    if (copies != NULL) {
        fprintf(copies, "C001,B001,AVAILABLE,, ,0,0\n");
        fprintf(copies, "C002,B001,AVAILABLE,, ,0,0\n");
        fprintf(copies, "C003,B002,AVAILABLE,, ,0,0\n");
        fclose(copies);
    } else {
        ok = 0;
    }

    return ok;
}

int main(int argc, char **argv) {
    Library *lib;
    int status = 0;
    srand((unsigned int)time(NULL));
    lib = malloc(sizeof(*lib));
    if (lib == NULL) {
        fprintf(stderr, "Unable to allocate library memory.\n");
        return 1;
    }
    library_init(lib);

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "seed") == 0) {
        remove(DEFAULT_STATE_PATH);
        if (create_sample_files()) {
            printf("Sample registries created.\n");
        } else {
            printf("Registry files are present or were not writable; continuing with existing files.\n");
        }
        return 0;
    }

    if (strcmp(argv[1], "demo") == 0) {
        Library *demo_lib = malloc(sizeof(*demo_lib));
        printf("Running demo workflow...\n");
        if (demo_lib == NULL) {
            fprintf(stderr, "Unable to allocate demo library memory.\n");
            free(lib);
            return 1;
        }
        create_sample_files();
        library_init(demo_lib);
        load_registries(demo_lib, "books.txt", "members.txt", "copies.txt");
        printf("Initial state:\n");
        print_library_summary(demo_lib);
        borrow_book(demo_lib, "B001", "M001");
        mine_pending(demo_lib, "miner-demo");
        printf("Validation result: %s\n", validate_chain(demo_lib) ? "passed" : "failed");
        free(demo_lib);
        free(lib);
        return 0;
    }

    if (strcmp(argv[1], "load") == 0) {
        if (!load_default_state(lib)) {
            fprintf(stderr, "Error: required registry files are missing or invalid.\n");
            free(lib);
            return 1;
        }
        print_library_summary(lib);
        free(lib);
        return 0;
    }

    if (!load_default_state(lib)) {
        fprintf(stderr, "Error: registries not loaded. Run '%s seed' first.\n", argv[0]);
        free(lib);
        return 1;
    }

    if (strcmp(argv[1], "list") == 0 || strcmp(argv[1], "chain_view") == 0) {
        print_library_summary(lib);
        free(lib);
        return 0;
    }

    if (strcmp(argv[1], "verify") == 0 || strcmp(argv[1], "validate_chain") == 0) {
        if (validate_chain(lib)) {
            printf("Blockchain validation passed.\n");
        } else {
            printf("Blockchain validation failed.\n");
            free(lib);
            return 1;
        }
        free(lib);
        return 0;
    }

    if (strcmp(argv[1], "overdue") == 0 || strcmp(argv[1], "check_overdue") == 0) {
        status = scan_overdue(lib);
        printf("Overdue scan result: %d flagged.\n", status);
        if (!save_default_state(lib)) {
            free(lib);
            return 1;
        }
        free(lib);
        return 0;
    }

    if (strcmp(argv[1], "pool_view") == 0) {
        print_pending_requests(lib);
        free(lib);
        return 0;
    }

    if (strcmp(argv[1], "mine_solo") == 0 && argc >= 3) {
        status = mine_pending_solo(lib, argv[2]);
        if (status && !save_default_state(lib)) {
            status = 0;
        }
        free(lib);
        return status ? 0 : 1;
    }

    if (strcmp(argv[1], "mine_pool") == 0 && argc >= 3) {
        status = mine_pending_pool(lib, argv[2], argc >= 4 ? atoi(argv[3]) : 1);
        if (status && !save_default_state(lib)) {
            status = 0;
        }
        free(lib);
        return status ? 0 : 1;
    }

    if (strcmp(argv[1], "mine") == 0 && argc >= 3) {
        status = mine_pending(lib, argv[2]);
        if (status && !save_default_state(lib)) {
            free(lib);
            return 1;
        }
        free(lib);
        return status ? 0 : 1;
    }

    if (strcmp(argv[1], "mine_cloud") == 0 && argc >= 4) {
        int rounds = atoi(argv[3]);
        status = mine_pending_cloud(lib, argv[2], rounds);
        if (status && !save_default_state(lib)) {
            status = 0;
        }
        free(lib);
        return status ? 0 : 1;
    }

    if (strcmp(argv[1], "borrow") == 0 || strcmp(argv[1], "borrow_book") == 0) {
        if (argc < 4) {
            print_usage(argv[0]);
            free(lib);
            return 1;
        }
        status = borrow_book(lib, argv[2], argv[3]);
        if (status && !save_default_state(lib)) {
            status = 0;
        }
        free(lib);
        return status ? 0 : 1;
    }

    if (strcmp(argv[1], "return") == 0 || strcmp(argv[1], "return_book") == 0) {
        if (argc < 4) {
            print_usage(argv[0]);
            free(lib);
            return 1;
        }
        status = return_book(lib, argv[2], argv[3]);
        if (status && !save_default_state(lib)) {
            status = 0;
        }
        free(lib);
        return status ? 0 : 1;
    }

    if (strcmp(argv[1], "reserve") == 0 || strcmp(argv[1], "reserve_book") == 0) {
        if (argc < 4) {
            print_usage(argv[0]);
            free(lib);
            return 1;
        }
        status = reserve_book(lib, argv[2], argv[3]);
        if (status && !save_default_state(lib)) {
            status = 0;
        }
        free(lib);
        return status ? 0 : 1;
    }

    if (strcmp(argv[1], "renew") == 0 || strcmp(argv[1], "renew_book") == 0) {
        if (argc < 4) {
            print_usage(argv[0]);
            free(lib);
            return 1;
        }
        status = renew_book(lib, argv[2], argv[3]);
        if (status && !save_default_state(lib)) {
            status = 0;
        }
        free(lib);
        return status ? 0 : 1;
    }

    if (strcmp(argv[1], "add-book") == 0 || strcmp(argv[1], "register_book") == 0) {
        if (argc < 5) {
            print_usage(argv[0]);
            free(lib);
            return 1;
        }
        status = add_book(lib, argv[2], argv[3], argv[4]);
        if (status && !save_default_state(lib)) {
            status = 0;
        }
        free(lib);
        return status ? 0 : 1;
    }

    if (strcmp(argv[1], "add-member") == 0 || strcmp(argv[1], "register_member") == 0) {
        if (argc < 5) {
            print_usage(argv[0]);
            free(lib);
            return 1;
        }
        status = add_member(lib, argv[2], argv[3], argv[4]);
        if (status && !save_default_state(lib)) {
            status = 0;
        }
        free(lib);
        return status ? 0 : 1;
    }

    if (strcmp(argv[1], "add-copy") == 0) {
        if (argc < 4) {
            print_usage(argv[0]);
            free(lib);
            return 1;
        }
        status = add_copy(lib, argv[2], argv[3]);
        if (status && !save_default_state(lib)) {
            status = 0;
        }
        free(lib);
        return status ? 0 : 1;
    }

    if (strcmp(argv[1], "settle-fine") == 0 && argc >= 4) {
        status = settle_fine(lib, argv[2], atof(argv[3]));
        if (status && !save_default_state(lib)) {
            status = 0;
        }
        free(lib);
        return status ? 0 : 1;
    }

    if (strcmp(argv[1], "flag-fraud") == 0 && argc >= 3) {
        status = flag_request_suspicious(lib, argv[2]);
        if (status && !save_default_state(lib)) {
            status = 0;
        }
        free(lib);
        return status ? 0 : 1;
    }

    if (strcmp(argv[1], "review-fraud") == 0 && argc >= 4) {
        status = review_request(lib, argv[2], argv[3]);
        if (status && !save_default_state(lib)) {
            status = 0;
        }
        free(lib);
        return status ? 0 : 1;
    }

    if (strcmp(argv[1], "save") == 0 && argc >= 3) {
        if (save_state(lib, argv[2])) {
            printf("State saved to %s\n", argv[2]);
            free(lib);
            return 0;
        }
        fprintf(stderr, "Unable to save state.\n");
        free(lib);
        return 1;
    }

    if (strcmp(argv[1], "load_state") == 0 && argc >= 3) {
        if (load_state(lib, argv[2])) {
            printf("State loaded from %s\n", argv[2]);
            print_library_summary(lib);
            free(lib);
            return 0;
        }
        fprintf(stderr, "Unable to load state.\n");
        free(lib);
        return 1;
    }

    print_usage(argv[0]);
    return 1;
}
