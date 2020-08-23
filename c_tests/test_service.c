// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

#include "etebase.h"
#include "test_common.h"
#include <stdint.h>
#include <stdlib.h>

const char TEST_USER_SESSION[] = "gqd2ZXJzaW9uAa1lbmNyeXB0ZWREYXRhxQGr_KWyDChQ6tXOJwJKf0Kw3QyR99itPIF3vZ5w6pVXSIq7AWul3fIXjIZOsBEwTVRumw7e9Af38D5oIL2VLNPLlmTOMjzIvuB00z3zDMFbH8pwrg2p_FvAhLHGjUGoXzU2XIxS4If7rQUfEz1zWkHPqWMrj4hACML5fks302dOUw7OsSMekcQaaVqMyj82MY3lG2qj8CL6ykSED7nW6OYWwMBJ1rSDGXhQRd5JuCGl6kgAHxKS6gkkIAWeUKjC6-Th2etk1XPKDiks0SZrQpmuXG8h_TBdd4igjRUqnIk09z5wvJFViXIU4M3pQomyFPk3Slh7KHvWhzxG0zbC2kUngQZ5h-LbVTLuT_TQWjYmHiOIihenrzl7z9MLebUq6vuwusZMRJ1Atau0Y2HcOzulYt4tLRP49d56qFEId3R4xomZ666hy-EFodsbzpxEKHeBUro3_gifOOKR8zkyLKTRz1UipZfKvnWk_RHFgZlSClRsXyaP34wstUavSiz-HNmTEmflNQKM7Awfel108FcSbW9NQAogW2Y2copP-P-R-DiHThrXmgDsWkTQFA";

const char *
get_test_url() {
    const char *env = getenv("ETEBASE_TEST_API_URL");
    return (env) ? env : "http://localhost:8033";
}

int
test_simple_getters() {
    EtebaseUser *user = etebase_user_new("username", "email@localhost");
    assert_str_eq(etebase_user_get_username(user), "username");
    assert_str_eq(etebase_user_get_email(user), "email@localhost");
    etebase_user_destroy(user);
    return 0;
}

int
test_base64() {
    const char *text = "Test";
    char encoded[ETEBASE_UTILS_TO_BASE64_MAX_LEN(strlen(text) + 1)];
    fail_if(etebase_utils_to_base64(text, strlen(text) + 1, encoded, sizeof(encoded)));
    char decoded[ETEBASE_UTILS_FROM_BASE64_MAX_LEN(strlen(encoded))];
    uintptr_t decoded_len = 0;
    fail_if(etebase_utils_from_base64(encoded, decoded, sizeof(decoded), &decoded_len));
    assert_int_eq(decoded_len, strlen(text) + 1);
    assert_str_eq(decoded, text);

    fail_if(etebase_utils_from_base64(encoded, decoded, sizeof(decoded), NULL));

    fail_if(!etebase_utils_from_base64("#@$@#$*@#$", decoded, sizeof(decoded), NULL));
    assert_int_eq(ETEBASE_ERROR_CODE_BASE64, etebase_error_get_code());
    return 0;
}

int
test_utils() {
    assert_str_eq(etebase_get_default_server_url(), "https://api.etebase.com");
    char buf[32];
    fail_if(etebase_utils_randombytes(buf, sizeof(buf)));
    char pretty[ETEBASE_UTILS_PRETTY_FINGERPRINT_SIZE];
    fail_if(etebase_utils_pretty_fingerprint(buf, sizeof(buf), pretty));
    return 0;
}

int
test_simple() {
    EtebaseClient *client = etebase_client_new("libetebase-test", get_test_url());
    EtebaseAccount *etebase = etebase_account_restore(client, TEST_USER_SESSION, NULL, 0);
    etebase_client_destroy(client);

    etebase_account_force_server_url(etebase, get_test_url());
    etebase_account_fetch_token(etebase);

    EtebaseCollectionManager *col_mgr = etebase_account_get_collection_manager(etebase);
    EtebaseCollectionMetadata *col_meta = etebase_collection_metadata_new("Type", "Name");
    const char content[] = "Something";
    EtebaseCollection *col = etebase_collection_manager_create(col_mgr, col_meta, content, strlen(content));
    etebase_collection_metadata_destroy(col_meta);

    {
        char tmp[1000];
        intptr_t tmp_size = etebase_collection_get_content(col, &tmp, sizeof(tmp));
        fail_if(tmp_size < 0);
        assert_int_eq(tmp_size, strlen(content));
        tmp[tmp_size] = 0;
        assert_str_eq(tmp, content);
    }

    {
        EtebaseFetchOptions *fetch_options = etebase_fetch_options_new();
        etebase_fetch_options_set_prefetch(fetch_options, ETEBASE_PREFETCH_OPTION_AUTO);
        fail_if(etebase_collection_manager_upload(col_mgr, col, fetch_options));
        etebase_fetch_options_destroy(fetch_options);
    }

    {
        EtebaseCollectionListResponse *col_list = etebase_collection_manager_list(col_mgr, NULL);
        fail_if(!col_list);
        assert_int_ne(0, etebase_collection_list_response_get_data_length(col_list));

        EtebaseFetchOptions *fetch_options = etebase_fetch_options_new();
        etebase_fetch_options_set_stoken(fetch_options, etebase_collection_list_response_get_stoken(col_list));

        etebase_collection_list_response_destroy(col_list);
        col_list = etebase_collection_manager_list(col_mgr, fetch_options);
        assert_int_eq(0, etebase_collection_list_response_get_data_length(col_list));

        etebase_fetch_options_destroy(fetch_options);
        etebase_collection_list_response_destroy(col_list);
    }

    {
        EtebaseCollection *col2 = etebase_collection_manager_fetch(col_mgr, etebase_collection_get_uid(col), NULL);
        char content2[1000];
        intptr_t content2_size = etebase_collection_get_content(col2, &content2, sizeof(content2));
        fail_if(content2_size < 0);
        assert_int_eq(content2_size, strlen(content));
        content2[content2_size] = 0;
        assert_str_eq(content2, content);

        const char tmp[] = "Something else";
        etebase_collection_set_content(col2, tmp, strlen(tmp));
        etebase_collection_manager_transaction(col_mgr, col2, NULL);

        etebase_collection_destroy(col2);
    }

    EtebaseItemManager *item_mgr = etebase_collection_manager_get_item_manager(col_mgr, col);
    EtebaseItemMetadata *item_meta = etebase_item_metadata_new();
    etebase_item_metadata_set_item_type(item_meta, "Bla");
    const char item_content[] = "Something item";
    EtebaseItem *item = etebase_item_manager_create(item_mgr, item_meta, item_content, strlen(item_content));
    etebase_item_metadata_destroy(item_meta);
    fail_if(!strcmp("", etebase_item_get_uid(item)));
    fail_if(!etebase_item_get_etag(item));

    {
        char content2[1000];
        intptr_t content2_size = etebase_item_get_content(item, &content2, sizeof(content2));
        fail_if(content2_size < 0);
        assert_int_eq(content2_size, strlen(item_content));
        content2[content2_size] = 0;
        assert_str_eq(content2, item_content);
    }

    {
        const EtebaseItem *items[] = { item };
        fail_if(etebase_item_manager_batch(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL, 0, NULL));
    }

    {
        char *old_etag = strdup(etebase_item_get_etag(item));
        const char tmp[] = "Something item2";
        etebase_item_set_content(item, tmp, strlen(tmp));
        fail_if(!strcmp(old_etag, etebase_item_get_etag(item)));
        free(old_etag);

        const EtebaseItem *items[] = { item };
        fail_if(etebase_item_manager_transaction(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL, 0, NULL));

        EtebaseItemListResponse *item_list = etebase_item_manager_list(item_mgr, NULL);
        fail_if(!item_list);
        uintptr_t list_len = etebase_item_list_response_get_data_length(item_list);
        assert_int_eq(1, list_len);

        const EtebaseItem *list_items[list_len];
        fail_if(etebase_item_list_response_get_data(item_list, list_items));
        EtebaseItem *item2 = etebase_item_clone(list_items[0]);
        etebase_item_destroy(item2);

        char content2[1000];
        intptr_t content2_size = etebase_item_get_content(list_items[0], &content2, sizeof(content2));
        fail_if(content2_size < 0);
        assert_int_eq(content2_size, strlen(tmp));
        content2[content2_size] = 0;
        assert_str_eq(content2, tmp);

        EtebaseFetchOptions *fetch_options = etebase_fetch_options_new();
        etebase_fetch_options_set_stoken(fetch_options, etebase_item_list_response_get_stoken(item_list));
        EtebaseItemListResponse *item_list2 = etebase_item_manager_list(item_mgr, fetch_options);

        uintptr_t list_len2 = etebase_item_list_response_get_data_length(item_list2);
        assert_int_eq(0, list_len2);

        etebase_fetch_options_destroy(fetch_options);
        etebase_item_list_response_destroy(item_list2);
        etebase_item_list_response_destroy(item_list);
    }

    etebase_account_logout(etebase);

    etebase_item_destroy(item);
    etebase_item_manager_destroy(item_mgr);
    etebase_collection_destroy(col);
    etebase_collection_manager_destroy(col_mgr);
    etebase_account_destroy(etebase);
    return 0;
}

int
test_bad_auth() {
    EtebaseClient *client = etebase_client_new("libetebase-test", get_test_url());
    {
        EtebaseAccount *etebase = etebase_account_login(client, "non-existent", "passward");
        fail_if(etebase);
        assert_int_eq(ETEBASE_ERROR_CODE_NOT_FOUND, etebase_error_get_code());
    }
    {
        EtebaseAccount *etebase = etebase_account_login(client, "test_user", "bad-passward");
        fail_if(etebase);
        assert_int_eq(ETEBASE_ERROR_CODE_UNAUTHORIZED, etebase_error_get_code());
    }

    EtebaseAccount *etebase = etebase_account_restore(client, TEST_USER_SESSION, NULL, 0);
    etebase_client_destroy(client);

    etebase_account_force_server_url(etebase, get_test_url());
    etebase_account_fetch_token(etebase);
    etebase_account_logout(etebase);

    EtebaseCollectionManager *col_mgr = etebase_account_get_collection_manager(etebase);

    EtebaseCollectionListResponse *col_list = etebase_collection_manager_list(col_mgr, NULL);
    fail_if(col_list);
    assert_int_eq(ETEBASE_ERROR_CODE_UNAUTHORIZED, etebase_error_get_code());

    etebase_collection_manager_destroy(col_mgr);
    etebase_account_destroy(etebase);
    return 0;
}
