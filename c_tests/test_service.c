// SPDX-FileCopyrightText: © 2020 EteSync Authors
// SPDX-License-Identifier: LGPL-2.1-only

#include "etebase.h"
#include "test_common.h"
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

const char TEST_USER_SESSION[] = "gqd2ZXJzaW9uAa1lbmNyeXB0ZWREYXRhxQGr_KWyDChQ6tXOJwJKf0Kw3QyR99itPIF3vZ5w6pVXSIq7AWul3fIXjIZOsBEwTVRumw7e9Af38D5oIL2VLNPLlmTOMjzIvuB00z3zDMFbH8pwrg2p_FvAhLHGjUGoXzU2XIxS4If7rQUfEz1zWkHPqWMrj4hACML5fks302dOUw7OsSMekcQaaVqMyj82MY3lG2qj8CL6ykSED7nW6OYWwMBJ1rSDGXhQRd5JuCGl6kgAHxKS6gkkIAWeUKjC6-Th2etk1XPKDiks0SZrQpmuXG8h_TBdd4igjRUqnIk09z5wvJFViXIU4M3pQomyFPk3Slh7KHvWhzxG0zbC2kUngQZ5h-LbVTLuT_TQWjYmHiOIihenrzl7z9MLebUq6vuwusZMRJ1Atau0Y2HcOzulYt4tLRP49d56qFEId3R4xomZ666hy-EFodsbzpxEKHeBUro3_gifOOKR8zkyLKTRz1UipZfKvnWk_RHFgZlSClRsXyaP34wstUavSiz-HNmTEmflNQKM7Awfel108FcSbW9NQAogW2Y2copP-P-R-DiHThrXmgDsWkTQFA";

const char *COL_TYPE = "some.coltype";

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

    EtebaseClient *client = etebase_client_new("libetebase-test", get_test_url());
    EtebaseAccount *etebase = etebase_account_restore(client, TEST_USER_SESSION, NULL, 0);
    etebase_client_destroy(client);

    EtebaseCollectionManager *col_mgr = etebase_account_get_collection_manager(etebase);
    EtebaseItemMetadata *col_meta = etebase_item_metadata_new();
    etebase_item_metadata_set_name(col_meta, "Name");
    const char content[] = "Something";
    EtebaseCollection *col = etebase_collection_manager_create(col_mgr, COL_TYPE, col_meta, content, strlen(content));
    etebase_item_metadata_destroy(col_meta);

    {
        char *col_type = etebase_collection_get_collection_type(col);
        assert_str_eq(col_type, COL_TYPE);
        free(col_type);
    }

    // Check we can just get the content size if we pass null as the buffer
    {
        uintptr_t len = etebase_collection_get_content(col, NULL, 0);
        assert_int_eq(len, strlen(content));
        char tmp[len];
        etebase_collection_get_content(col, tmp, len);
    }

    EtebaseCollectionInvitationManager *invitation_manager = etebase_account_get_invitation_manager(etebase);

    uintptr_t pubkey_size = etebase_invitation_manager_get_pubkey_size(invitation_manager);
    fail_if(pubkey_size == 0);
    const char *pubkey = etebase_invitation_manager_get_pubkey(invitation_manager);
    fail_if(!pubkey);

    etebase_invitation_manager_destroy(invitation_manager);
    etebase_collection_destroy(col);
    etebase_collection_manager_destroy(col_mgr);
    etebase_account_destroy(etebase);

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
test_check_etebase_server() {
    EtebaseClient *client = etebase_client_new("libetebase-test", get_test_url());
    fail_if(etebase_client_check_etebase_server(client));
    etebase_client_destroy(client);
    /*
    let test_url = format!("{}/a", test_url());
    let client = Client::new(CLIENT_NAME, &test_url)?;
    assert!(!Account::is_etebase_server(&client)?);
    */
    client = etebase_client_new("libetebase-test", "http://doesnotexist");
    fail_if(!etebase_client_check_etebase_server(client));
    etebase_client_destroy(client);

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
    EtebaseItemMetadata *col_meta = etebase_item_metadata_new();
    etebase_item_metadata_set_name(col_meta, "Name");
    const char content[] = "Something";
    EtebaseCollection *col = etebase_collection_manager_create(col_mgr, COL_TYPE, col_meta, content, strlen(content));
    etebase_item_metadata_destroy(col_meta);

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
        EtebaseCollectionListResponse *col_list = etebase_collection_manager_list(col_mgr, COL_TYPE, NULL);
        fail_if(!col_list);
        assert_int_ne(0, etebase_collection_list_response_get_data_length(col_list));

        EtebaseFetchOptions *fetch_options = etebase_fetch_options_new();
        etebase_fetch_options_set_stoken(fetch_options, etebase_collection_list_response_get_stoken(col_list));

        etebase_collection_list_response_destroy(col_list);
        col_list = etebase_collection_manager_list(col_mgr, COL_TYPE, fetch_options);
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
        fail_if(etebase_item_manager_batch(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL));
    }

    {
        char *old_etag = strdup(etebase_item_get_etag(item));
        const char tmp[] = "Something item2";
        etebase_item_set_content(item, tmp, strlen(tmp));
        fail_if(!strcmp(old_etag, etebase_item_get_etag(item)));
        free(old_etag);

        const EtebaseItem *items[] = { item };
        fail_if(etebase_item_manager_transaction(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL));

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
test_item_deps() {
    EtebaseClient *client = etebase_client_new("libetebase-test", get_test_url());
    EtebaseAccount *etebase = etebase_account_restore(client, TEST_USER_SESSION, NULL, 0);
    etebase_client_destroy(client);

    etebase_account_force_server_url(etebase, get_test_url());
    etebase_account_fetch_token(etebase);

    EtebaseCollectionManager *col_mgr = etebase_account_get_collection_manager(etebase);
    EtebaseItemMetadata *col_meta = etebase_item_metadata_new();
    etebase_item_metadata_set_name(col_meta, "Name");
    EtebaseCollection *col = etebase_collection_manager_create(col_mgr, COL_TYPE, col_meta, "", 0);
    etebase_item_metadata_destroy(col_meta);

    etebase_collection_manager_upload(col_mgr, col, NULL);

    EtebaseItemManager *item_mgr = etebase_collection_manager_get_item_manager(col_mgr, col);
    EtebaseItemMetadata *item_meta = etebase_item_metadata_new();
    const char item_content[] = "Item 1";
    EtebaseItem *item1 = etebase_item_manager_create(item_mgr, item_meta, item_content, strlen(item_content));
    const char item_content2[] = "Item 2";
    EtebaseItem *item2 = etebase_item_manager_create(item_mgr, item_meta, item_content2, strlen(item_content2));
    etebase_item_metadata_destroy(item_meta);

    {
        const EtebaseItem *items[] = { item1, item2 };
        fail_if(etebase_item_manager_batch(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL));
    }

    {
        const char *item1_uid = etebase_item_get_uid(item1);
        // -> On device B:
        EtebaseItem *item1 = etebase_item_manager_fetch(item_mgr, item1_uid, NULL);
        fail_if(!item1);
        const char tmp[] = "Something else for item1";
        etebase_item_set_content(item1, tmp, strlen(tmp));
        const EtebaseItem *items[] = { item1 };
        fail_if(etebase_item_manager_batch(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL));
        etebase_item_destroy(item1);
    }


    {
        // -> On device A (using the previously saved collection)
        const char tmp[] = "New content for item 2";
        etebase_item_set_content(item2, tmp, strlen(tmp));

        // Will both fail because item1 changed
        const EtebaseItem *items[] = { item2 };
        const EtebaseItem *deps[] = { item1 };
        fail_if(!etebase_item_manager_transaction_deps(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items),
                    deps, ETEBASE_UTILS_C_ARRAY_LEN(deps), NULL));
        fail_if(!etebase_item_manager_batch_deps(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items),
                    deps, ETEBASE_UTILS_C_ARRAY_LEN(deps), NULL));

        // Can even use the item in both the list and deps in batch
        // Will fail because item1 changed on device B

        const EtebaseItem *items2[] = { item1, item2 };
        fail_if(!etebase_item_manager_batch_deps(item_mgr, items2, ETEBASE_UTILS_C_ARRAY_LEN(items2),
                    deps, ETEBASE_UTILS_C_ARRAY_LEN(deps), NULL));
    }

    etebase_account_logout(etebase);

    etebase_item_destroy(item2);
    etebase_item_destroy(item1);
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

    EtebaseCollectionListResponse *col_list = etebase_collection_manager_list(col_mgr, COL_TYPE, NULL);
    fail_if(col_list);
    assert_int_eq(ETEBASE_ERROR_CODE_UNAUTHORIZED, etebase_error_get_code());

    etebase_collection_manager_destroy(col_mgr);
    etebase_account_destroy(etebase);
    return 0;
}

int
test_collection_transactions() {
    EtebaseClient *client = etebase_client_new("libetebase-test", get_test_url());
    EtebaseAccount *etebase = etebase_account_restore(client, TEST_USER_SESSION, NULL, 0);
    etebase_client_destroy(client);

    etebase_account_force_server_url(etebase, get_test_url());
    etebase_account_fetch_token(etebase);

    EtebaseCollectionManager *col_mgr = etebase_account_get_collection_manager(etebase);
    EtebaseItemMetadata *col_meta = etebase_item_metadata_new();
    etebase_item_metadata_set_name(col_meta, "Name");
    EtebaseCollection *col = etebase_collection_manager_create(col_mgr, COL_TYPE, col_meta, "", 0);
    etebase_item_metadata_destroy(col_meta);

    etebase_collection_manager_upload(col_mgr, col, NULL);

    const char *col_uid = etebase_collection_get_uid(col);
    {
        // -> On device A:
        EtebaseCollection *col = etebase_collection_manager_fetch(col_mgr, col_uid, NULL);


        {
            // -> On device B:
            EtebaseCollection *col = etebase_collection_manager_fetch(col_mgr, col_uid, NULL);
            EtebaseItemMetadata *col_meta = etebase_collection_get_meta(col);
            etebase_item_metadata_set_name(col_meta, "New name");
            etebase_collection_set_meta(col, col_meta);
            etebase_item_metadata_destroy(col_meta);

            etebase_collection_manager_upload(col_mgr, col, NULL);

            etebase_collection_destroy(col);
        }


        // -> On device A (using the previously saved collection)
        EtebaseItemMetadata *col_meta = etebase_collection_get_meta(col);
        etebase_item_metadata_set_name(col_meta, "Another name");
        etebase_collection_set_meta(col, col_meta);
        etebase_item_metadata_destroy(col_meta);

        // Will fail
        fail_if(!etebase_collection_manager_transaction(col_mgr, col, NULL));
        // Will succeed
        fail_if(etebase_collection_manager_upload(col_mgr, col, NULL));

        etebase_collection_destroy(col);
    }

    // Using stoken
    {
        // -> On device A:
        EtebaseCollection *col = etebase_collection_manager_fetch(col_mgr, col_uid, NULL);
        const char *stoken = etebase_collection_get_stoken(col);

        {
            // -> On device B:
            EtebaseCollection *col = etebase_collection_manager_fetch(col_mgr, col_uid, NULL);
            EtebaseItemManager *item_mgr = etebase_collection_manager_get_item_manager(col_mgr, col);
            {
                EtebaseItemMetadata *item_meta = etebase_item_metadata_new();
                etebase_item_metadata_set_name(item_meta, "Name");
                EtebaseItem *item = etebase_item_manager_create(item_mgr, item_meta, NULL, 0);
                etebase_item_metadata_destroy(item_meta);
                {
                    const EtebaseItem *items[] = { item };
                    fail_if(etebase_item_manager_batch(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL));
                }
                etebase_item_destroy(item);
            }

            etebase_item_manager_destroy(item_mgr);
            etebase_collection_destroy(col);
        }

        // -> On device A (using the previously saved collection)
        EtebaseItemMetadata *col_meta = etebase_collection_get_meta(col);
        etebase_item_metadata_set_name(col_meta, "Another name");
        etebase_collection_set_meta(col, col_meta);
        etebase_item_metadata_destroy(col_meta);

        // Will both fail
        EtebaseFetchOptions *fetch_options = etebase_fetch_options_new();
        etebase_fetch_options_set_stoken(fetch_options, stoken);
        fail_if(!etebase_collection_manager_transaction(col_mgr, col, fetch_options));
        fail_if(!etebase_collection_manager_upload(col_mgr, col, fetch_options));
        etebase_fetch_options_destroy(fetch_options);
        // Will both succeed
        fail_if(etebase_collection_manager_transaction(col_mgr, col, NULL));
        // Previous one fail_if(etebase_collection_manager_upload(col_mgr, col, NULL));

        etebase_collection_destroy(col);
    }


    etebase_account_logout(etebase);

    etebase_collection_destroy(col);
    etebase_collection_manager_destroy(col_mgr);
    etebase_account_destroy(etebase);
    return 0;
}

int
test_items_transactions() {
    EtebaseClient *client = etebase_client_new("libetebase-test", get_test_url());
    EtebaseAccount *etebase = etebase_account_restore(client, TEST_USER_SESSION, NULL, 0);
    etebase_client_destroy(client);

    etebase_account_force_server_url(etebase, get_test_url());
    etebase_account_fetch_token(etebase);

    EtebaseCollectionManager *col_mgr = etebase_account_get_collection_manager(etebase);
    EtebaseItemMetadata *col_meta = etebase_item_metadata_new();
    etebase_item_metadata_set_name(col_meta, "Name");
    EtebaseCollection *col = etebase_collection_manager_create(col_mgr, COL_TYPE, col_meta, "", 0);
    etebase_item_metadata_destroy(col_meta);

    etebase_collection_manager_upload(col_mgr, col, NULL);

    EtebaseItemManager *item_mgr = etebase_collection_manager_get_item_manager(col_mgr, col);

    EtebaseItemMetadata *item_meta = etebase_item_metadata_new();
    etebase_item_metadata_set_name(item_meta, "Item 1");
    EtebaseItem *item1 = etebase_item_manager_create(item_mgr, item_meta, "", 0);
    etebase_item_metadata_set_name(item_meta, "Item 2");
    EtebaseItem *item2 = etebase_item_manager_create(item_mgr, item_meta, "", 0);
    etebase_item_metadata_destroy(item_meta);

    const EtebaseItem *items[] = { item1, item2 };
    fail_if(etebase_item_manager_batch(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL));

    char *item1_uid = strdup(etebase_item_get_uid(item1));
    char *item2_uid = strdup(etebase_item_get_uid(item2));
    {
        // -> On device A:
        EtebaseItem *item1 = etebase_item_manager_fetch(item_mgr, item1_uid, NULL);
        EtebaseItem *item2 = etebase_item_manager_fetch(item_mgr, item2_uid, NULL);

        {
            // -> On device B:
            EtebaseItem *item1 = etebase_item_manager_fetch(item_mgr, item1_uid, NULL);
            const char tmp[] = "Something else for item 1";
            etebase_item_set_content(item1, tmp, strlen(tmp));

            const EtebaseItem *items[] = { item1 };
            etebase_item_manager_batch(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL);

            etebase_item_destroy(item1);
        }


        // -> On device A (using the previously saved item)
        const char tmp[] = "New content for item 1";
        etebase_item_set_content(item1, tmp, strlen(tmp));
        const char tmp2[] = "New content for item 2";
        etebase_item_set_content(item2, tmp2, strlen(tmp2));

        // Will fail because item1 changed on device B
        const EtebaseItem *items[] = { item1, item2 };
        fail_if(!etebase_item_manager_transaction(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL));
        // Will succeed
        fail_if(etebase_item_manager_batch(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL));
        // Will succeed because item2 hasn't changed on device B
        // const EtebaseItem *items2[] = { item2 };
        // fail_if(etebase_item_manager_transaction(item_mgr, items2, ETEBASE_UTILS_C_ARRAY_LEN(items2), NULL));

        etebase_item_destroy(item2);
        etebase_item_destroy(item1);
    }

    const char *item_uid = item1_uid;
    const char *another_item_uid = item2_uid;
    // Using stoken
    {
        // -> On device A:
        EtebaseItem *item = etebase_item_manager_fetch(item_mgr, item_uid, NULL);
        const char *stoken = etebase_collection_get_stoken(col);

        {
            // -> On device B:
            EtebaseItem *another_item = etebase_item_manager_fetch(item_mgr, another_item_uid, NULL);
            const char tmp[] = "content for another item";
            etebase_item_set_content(item1, tmp, strlen(tmp));

            const EtebaseItem *items[] = { another_item };
            etebase_item_manager_batch(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL);

            etebase_item_destroy(another_item);
        }


        // -> On device A (using the previously saved item and stoken)
        const char tmp[] = "new secret content";
        etebase_item_set_content(item, tmp, strlen(tmp));


        // Will both fail
        EtebaseFetchOptions *fetch_options = etebase_fetch_options_new();
        etebase_fetch_options_set_stoken(fetch_options, stoken);
        const EtebaseItem *items[] = { item };
        fail_if(!etebase_item_manager_transaction(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), fetch_options));
        fail_if(!etebase_item_manager_batch(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), fetch_options));

        etebase_fetch_options_destroy(fetch_options);

        // Will both succeed
        fail_if(etebase_item_manager_transaction(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL));
        // fail_if(etebase_item_manager_batch(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL));

        etebase_item_destroy(item);
    }

    // Additional dependencies
    {
        // -> On device A:
        EtebaseItem *item1 = etebase_item_manager_fetch(item_mgr, item1_uid, NULL);
        EtebaseItem *item2 = etebase_item_manager_fetch(item_mgr, item2_uid, NULL);


        {
            // -> On device B:
            EtebaseItem *item1 = etebase_item_manager_fetch(item_mgr, item1_uid, NULL);
            const char tmp[] = "Something else for item 1";
            etebase_item_set_content(item1, tmp, strlen(tmp));

            const EtebaseItem *items[] = { item1 };
            etebase_item_manager_batch(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL);

            etebase_item_destroy(item1);
        }


        // -> On device A (using the previously saved collection)
        const char tmp2[] = "New content for item 2";
        etebase_item_set_content(item2, tmp2, strlen(tmp2));

        // Will both fail because item1 changed
        {
            const EtebaseItem *items[] = { item2 };
            const EtebaseItem *deps[] = { item1 };
            fail_if(!etebase_item_manager_batch_deps(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), deps, ETEBASE_UTILS_C_ARRAY_LEN(deps), NULL));
            fail_if(!etebase_item_manager_transaction_deps(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), deps, ETEBASE_UTILS_C_ARRAY_LEN(deps), NULL));
        }

        // Can even use the item in both the list and deps in batch
        // Will fail because item1 changed on device B
        const EtebaseItem *items[] = { item1, item2 };
        const EtebaseItem *deps[] = { item1 };
        fail_if(!etebase_item_manager_batch_deps(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), deps, ETEBASE_UTILS_C_ARRAY_LEN(deps), NULL));

        etebase_item_destroy(item2);
        etebase_item_destroy(item1);
    }

    free(item2_uid);
    free(item1_uid);

    etebase_account_logout(etebase);

    etebase_item_destroy(item2);
    etebase_item_destroy(item1);
    etebase_item_manager_destroy(item_mgr);
    etebase_collection_destroy(col);
    etebase_collection_manager_destroy(col_mgr);
    etebase_account_destroy(etebase);
    return 0;
}

int
test_collection_as_item() {
    EtebaseClient *client = etebase_client_new("libetebase-test", get_test_url());
    EtebaseAccount *etebase = etebase_account_restore(client, TEST_USER_SESSION, NULL, 0);
    etebase_client_destroy(client);

    etebase_account_force_server_url(etebase, get_test_url());
    etebase_account_fetch_token(etebase);

    EtebaseCollectionManager *col_mgr = etebase_account_get_collection_manager(etebase);
    EtebaseItemMetadata *col_meta = etebase_item_metadata_new();
    etebase_item_metadata_set_name(col_meta, "Name");
    EtebaseCollection *col = etebase_collection_manager_create(col_mgr, COL_TYPE, col_meta, "", 0);
    etebase_item_metadata_destroy(col_meta);

    etebase_collection_manager_upload(col_mgr, col, NULL);

    EtebaseItemManager *item_mgr = etebase_collection_manager_get_item_manager(col_mgr, col);

    EtebaseItemMetadata *item_meta = etebase_item_metadata_new();
    etebase_item_metadata_set_name(item_meta, "Item 1");
    EtebaseItem *item1 = etebase_item_manager_create(item_mgr, item_meta, "", 0);
    etebase_item_metadata_set_name(item_meta, "Item 2");
    EtebaseItem *item2 = etebase_item_manager_create(item_mgr, item_meta, "", 0);
    etebase_item_metadata_destroy(item_meta);

    char *item1_uid = strdup(etebase_item_get_uid(item1));
    char *item2_uid = strdup(etebase_item_get_uid(item2));
    {
        // Get the item out of the collection
        EtebaseItem *col_item = etebase_collection_as_item(col);

        // The collection item can then be used like any other item:
        {
            const EtebaseItem *items[] = { col_item, item1 };
            const EtebaseItem *deps[] = { item2 };
            fail_if(!etebase_item_manager_transaction_deps(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items),
                        deps, ETEBASE_UTILS_C_ARRAY_LEN(deps), NULL));
        }
        {
            const EtebaseItem *items[] = { item1, item2 };
            const EtebaseItem *deps[] = { col_item };
            fail_if(etebase_item_manager_transaction_deps(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items),
                        deps, ETEBASE_UTILS_C_ARRAY_LEN(deps), NULL));
        }
        {
            const EtebaseItem *items[] = { col_item, item1 };
            fail_if(!etebase_item_manager_batch(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL));
        }

        // In addition, these are true:
        assert_int_eq(etebase_collection_get_meta_raw(col, NULL, 0), etebase_item_get_meta_raw(col_item, NULL, 0));
        assert_int_eq(etebase_collection_get_content(col, NULL, 0), etebase_item_get_content(col_item, NULL, 0));

        etebase_item_destroy(col_item);
    }

    free(item2_uid);
    free(item1_uid);

    etebase_account_logout(etebase);

    etebase_item_destroy(item2);
    etebase_item_destroy(item1);
    etebase_item_manager_destroy(item_mgr);
    etebase_collection_destroy(col);
    etebase_collection_manager_destroy(col_mgr);
    etebase_account_destroy(etebase);
    return 0;
}

int
test_item_revisions() {
    EtebaseClient *client = etebase_client_new("libetebase-test", get_test_url());
    EtebaseAccount *etebase = etebase_account_restore(client, TEST_USER_SESSION, NULL, 0);
    etebase_client_destroy(client);

    etebase_account_force_server_url(etebase, get_test_url());
    etebase_account_fetch_token(etebase);

    EtebaseCollectionManager *col_mgr = etebase_account_get_collection_manager(etebase);
    EtebaseItemMetadata *col_meta = etebase_item_metadata_new();
    etebase_item_metadata_set_name(col_meta, "Name");
    EtebaseCollection *col = etebase_collection_manager_create(col_mgr, COL_TYPE, col_meta, "", 0);
    etebase_item_metadata_destroy(col_meta);

    etebase_collection_manager_upload(col_mgr, col, NULL);

    EtebaseItemManager *item_mgr = etebase_collection_manager_get_item_manager(col_mgr, col);

    EtebaseItemMetadata *item_meta = etebase_item_metadata_new();
    etebase_item_metadata_set_item_type(item_meta, "file");
    const char item_content[] = "First draft";
    EtebaseItem *item = etebase_item_manager_create(item_mgr, item_meta, item_content, strlen(item_content));
    etebase_item_metadata_destroy(item_meta);

    const EtebaseItem *items[] = { item };
    fail_if(etebase_item_manager_batch(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL));

    {
        const char tmp[] = "Second draft";
        etebase_item_set_content(item, tmp, strlen(tmp));

        const EtebaseItem *items[] = { item };
        fail_if(etebase_item_manager_batch(item_mgr, items, ETEBASE_UTILS_C_ARRAY_LEN(items), NULL));
    }

    EtebaseItemRevisionsListResponse *revisions = etebase_item_manager_item_revisions(item_mgr, item, NULL);

    uintptr_t list_len = etebase_item_revisions_list_response_get_data_length(revisions);
    assert_int_eq(2, list_len);

    {
        // Revisions are normal items so we can use them as such
        const EtebaseItem *list_items[list_len];
        fail_if(etebase_item_revisions_list_response_get_data(revisions, list_items));
        char content2[100];
        intptr_t content2_size = etebase_item_get_content(list_items[1], &content2, sizeof(content2));
        content2[content2_size] = 0;
        assert_str_eq(content2, "First draft");
    }

    etebase_item_revisions_list_response_destroy(revisions);

    etebase_account_logout(etebase);

    etebase_item_destroy(item);
    etebase_item_manager_destroy(item_mgr);
    etebase_collection_destroy(col);
    etebase_collection_manager_destroy(col_mgr);
    etebase_account_destroy(etebase);
    return 0;
}

int
test_basic_invitations() {
    EtebaseClient *client = etebase_client_new("libetebase-test", get_test_url());
    EtebaseAccount *etebase = etebase_account_restore(client, TEST_USER_SESSION, NULL, 0);
    etebase_client_destroy(client);

    etebase_account_force_server_url(etebase, get_test_url());
    etebase_account_fetch_token(etebase);

    EtebaseCollectionManager *col_mgr = etebase_account_get_collection_manager(etebase);
    EtebaseItemMetadata *col_meta = etebase_item_metadata_new();
    etebase_item_metadata_set_name(col_meta, "Name");
    EtebaseCollection *col = etebase_collection_manager_create(col_mgr, COL_TYPE, col_meta, "", 0);
    etebase_item_metadata_destroy(col_meta);

    etebase_collection_manager_upload(col_mgr, col, NULL);

    EtebaseCollectionInvitationManager *invitation_manager = etebase_account_get_invitation_manager(etebase);

    // Fetch their public key
    EtebaseUserProfile *user2 = etebase_invitation_manager_fetch_user_profile(invitation_manager, "test_user2");
    fail_if(!user2);

    // Verify user2.pubkey is indeed the pubkey you expect.
    // This is done in a secure channel (e.g. encrypted chat or in person)

    // Assuming the pubkey is as expected, send the invitation
    fail_if(etebase_invitation_manager_invite(invitation_manager, col, "test_user2", etebase_user_profile_get_pubkey(user2), etebase_user_profile_get_pubkey_size(user2), ETEBASE_COLLECTION_ACCESS_LEVEL_READ_ONLY));

    {
        EtebaseCollectionMemberManager *member_manager = etebase_collection_manager_get_member_manager(col_mgr, col);

        EtebaseMemberListResponse *members = etebase_collection_member_manager_list(member_manager, NULL);

        uintptr_t data_len = etebase_member_list_response_get_data_length(members);
        const EtebaseCollectionMember *data[data_len];
        etebase_member_list_response_get_data(members, data);

        // Print the users and their access levels
        const EtebaseCollectionMember *member = data[0];
        assert_str_eq("test_user", etebase_collection_member_get_username(member));
        assert_int_eq(ETEBASE_COLLECTION_ACCESS_LEVEL_ADMIN, etebase_collection_member_get_access_level(member));

        etebase_member_list_response_destroy(members);
        etebase_collection_member_manager_destroy(member_manager);
    }

    etebase_user_profile_destroy(user2);
    etebase_invitation_manager_destroy(invitation_manager);

    etebase_account_logout(etebase);

    etebase_collection_destroy(col);
    etebase_collection_manager_destroy(col_mgr);
    etebase_account_destroy(etebase);
    return 0;
}
