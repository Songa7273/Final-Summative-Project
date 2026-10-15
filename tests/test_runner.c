#include "ecdsa.h"
#include "ledger.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_sha256(void) {
    char hash[SHA256_HEX_LEN];
    const char *message = "abc";
    sha256_hash_hex((const uint8_t *)message, strlen(message), hash);
    return strcmp(hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0;
}

static int test_signatures(void) {
    char private_key[ECDSA_PRIVATE_KEY_LEN];
    char public_key[ECDSA_PUBLIC_KEY_LEN];
    char signature[ECDSA_SIG_HEX_LEN];
    if (!ecdsa_generate_key(private_key, public_key) ||
        !ecdsa_sign_message("library transaction", private_key, signature) ||
        !ecdsa_verify_message("library transaction", public_key, signature)) {
        return 0;
    }
    return !ecdsa_verify_message("tampered transaction", public_key, signature);
}

static int test_ledger(void) {
    Library *library = malloc(sizeof(*library));
    int passed;
    if (library == NULL) {
        return 0;
    }
    library_init(library);
    passed = load_registries(library, "books.txt", "members.txt", "copies.txt") &&
        borrow_book(library, "B001", "M001") &&
        mine_pending(library, "test-miner") &&
        validate_chain(library);
    if (!passed) {
        free(library);
        return 0;
    }
    passed = library->chain.blocks[0].difficulty == BLOCK_DIFFICULTY &&
        library->chain.blocks[0].hash[0] == '0' &&
        library->chain.blocks[0].hash[1] == '0';
    free(library);
    return passed;
}

static int test_persistence(void) {
    Library *original = malloc(sizeof(*original));
    Library *restored = malloc(sizeof(*restored));
    int passed = 0;
    if (original == NULL || restored == NULL) {
        free(original);
        free(restored);
        return 0;
    }
    library_init(original);
    if (load_registries(original, "books.txt", "members.txt", "copies.txt") &&
        borrow_book(original, "B001", "M001") &&
        mine_pending(original, "persistence-miner") &&
        save_state(original, "test-state.bin") &&
        load_state(restored, "test-state.bin") &&
        restored->chain.block_count == 1 &&
        restored->chain.blocks[0].proof_nonce == original->chain.blocks[0].proof_nonce &&
        strcmp(restored->members[0].private_key, original->members[0].private_key) == 0 &&
        validate_chain(restored)) {
        passed = 1;
    }
    remove("test-state.bin");
    free(original);
    free(restored);
    return passed;
}

int main(void) {
    int sha_ok = test_sha256();
    int signature_ok = test_signatures();
    int ledger_ok = test_ledger();
    int persistence_ok = test_persistence();
    if (!sha_ok || !signature_ok || !ledger_ok || !persistence_ok) {
        fprintf(stderr, "Tests failed.\n");
        return 1;
    }
    puts("All tests passed.");
    return 0;
}
