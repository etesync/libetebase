// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

#include "test_common.h"

int test_simple_getters();
int test_base64();
int test_utils();
int test_simple();
int test_item_deps();
int test_collection_transactions();
int test_items_transactions();
int test_collection_as_item();
int test_item_revisions();
int test_basic_invitations();
int test_bad_auth();

int
main() {
    int ret = 0;

    RUN_TEST(test_simple_getters);
    RUN_TEST(test_base64);
    RUN_TEST(test_utils);
    RUN_TEST(test_simple);
    RUN_TEST(test_item_deps);
    RUN_TEST(test_collection_transactions);
    RUN_TEST(test_items_transactions);
    RUN_TEST(test_collection_as_item);
    RUN_TEST(test_item_revisions);
    RUN_TEST(test_basic_invitations);
    RUN_TEST(test_bad_auth);

    return ret;
}

