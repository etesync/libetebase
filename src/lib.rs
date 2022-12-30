// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

#![allow(non_camel_case_types)]

use std::cell::RefCell;
use std::os::raw::{c_char, c_void};
use std::ffi::{CString, CStr};
use std::path::PathBuf;

use etebase::{
    DEFAULT_SERVER_URL,

    Client,
    User,
    Account,

    Collection,
    Item,
    ItemMetadata,

    CollectionAccessLevel,
    SignedInvitation,
    CollectionMember,
    RemovedCollection,

    UserProfile,

    fs_cache::FileSystemCache,

    error::Error,
    managers::{
        CollectionManager,
        ItemManager,
        CollectionInvitationManager,
        CollectionMemberManager,
    },
};

macro_rules! try_or_null {
    ($x:expr) => {
        match $x {
            Ok(val) => val,
            Err(err) => {
                update_last_error(Error::from(err));
                return std::ptr::null_mut();
            }
        };
    };
}

macro_rules! try_or_int {
    ($x:expr) => {
        match $x {
            Ok(val) => val,
            Err(err) => {
                update_last_error(Error::from(err));
                return -1;
            }
        };
    };
}

fn ptr_to_option<T>(val: *const T) -> Option<*const T> {
    if val.is_null() {
        None
    } else {
        Some(val)
    }
}

thread_local! {
    static LAST_ERROR: RefCell<Option<Error>> = RefCell::new(None);
}

fn update_last_error(err: Error) {
    LAST_ERROR.with(|prev| {
        *prev.borrow_mut() = Some(err);
    });
}

#[repr(u32)]
pub enum ErrorCode {
    NoError,

    Generic,
    UrlParse,
    MsgPack,
    ProgrammingError,
    MissingContent,
    Padding,
    Base64,
    Encryption,
    Unauthorized,
    Conflict,
    PermissionDenied,
    NotFound,

    Connection,
    TemporaryServerError,
    ServerError,
    Http,
}

/// Get the error code
///
/// Call this immediately after a failed API call
#[no_mangle]
pub extern fn etebase_error_get_code() -> ErrorCode {
    LAST_ERROR.with(|prev| {
        match *prev.borrow() {
            Some(ref err) => match err {
                Error::Generic(_) => ErrorCode::Generic,
                Error::UrlParse(_) => ErrorCode::UrlParse,
                Error::MsgPack(_) => ErrorCode::MsgPack,
                Error::ProgrammingError(_) => ErrorCode::ProgrammingError,
                Error::MissingContent(_) => ErrorCode::MissingContent,
                Error::Padding(_) => ErrorCode::Padding,
                Error::Base64(_) => ErrorCode::Base64,
                Error::Encryption(_) => ErrorCode::Encryption,
                Error::Unauthorized(_) => ErrorCode::Unauthorized,
                Error::Conflict(_) => ErrorCode::Conflict,
                Error::PermissionDenied(_) => ErrorCode::PermissionDenied,
                Error::NotFound(_) => ErrorCode::NotFound,

                Error::Connection(_) => ErrorCode::Connection,
                Error::TemporaryServerError(_) => ErrorCode::TemporaryServerError,
                Error::ServerError(_) => ErrorCode::ServerError,
                Error::Http(_) => ErrorCode::Http,
            },
            None => ErrorCode::NoError,
        }
    })
}

/// Get the error message
///
/// Call this immediately after a failed API call
#[no_mangle]
pub extern fn etebase_error_get_message() -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST_ERROR.with(|prev| {
        match *prev.borrow() {
            Some(ref err) => {
                let err = CString::new(err.to_string()).ok();
                LAST.with(|ret| {
                    *ret.borrow_mut() = err;
                    ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
                })
            },
            None => std::ptr::null(),
        }
    })
}

// Class Utils {

/// The URL of the main hosted server
#[no_mangle]
pub extern fn etebase_get_default_server_url() -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(DEFAULT_SERVER_URL).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// Convert a Base64 URL encoded string to a buffer
///
/// @param string the Base64 URL encoded string
/// @param[out] buf the output byte buffer
/// @param buf_maxlen the maximum number of bytes to be written to buf
/// @param[out] buf_len variable to store the buffer length in
#[no_mangle]
pub unsafe extern fn etebase_utils_from_base64(string: *const c_char, buf: *mut c_void, buf_maxlen: usize, buf_len: *mut usize) -> i32 {
    let string = CStr::from_ptr(string).to_str().unwrap();
    let buf_inner = try_or_int!(etebase::utils::from_base64(string));
    if buf_inner.len() > buf_maxlen {
        try_or_int!(Err(Error::ProgrammingError("buf_maxlen is too small for output")));
        return -1; // Never actually called, try_or_int returns already.
    }
    buf.copy_from_nonoverlapping(buf_inner.as_ptr() as *const c_void, buf_inner.len());
    if !buf_len.is_null() {
        *buf_len = buf_inner.len();
    }
    0
}

/// Convert a buffer to a Base64 URL encoded string
///
/// @param bytes the buffer to convert
/// @param bytes_size the size of the input buffer
/// @param[out] out the output string
/// @param out_maxlen the maximum length of string to be written
#[no_mangle]
pub unsafe extern fn etebase_utils_to_base64(bytes: *const c_void, bytes_size: usize, out: *mut c_char, out_maxlen: usize) -> i32 {
    let bytes = std::slice::from_raw_parts(bytes as *const u8, bytes_size);
    let b64 = try_or_int!(etebase::utils::to_base64(bytes));
    if b64.len() > out_maxlen {
        try_or_int!(Err(Error::ProgrammingError("out_maxlen is too small for output")));
        return -1; // Never actually called, try_or_int returns already.
    }
    out.copy_from_nonoverlapping(b64.as_ptr() as *const c_char, b64.len());
    *out.offset(b64.len() as isize) = 0;
    0
}

/// Return a buffer filled with cryptographically random bytes
///
/// @param[out] buf the output byte buffer
/// @param size the size of the returned buffer
#[no_mangle]
pub unsafe extern fn etebase_utils_randombytes(buf: *mut c_void, size: usize) -> i32 {
    let bytes = etebase::utils::randombytes(size);
    buf.copy_from_nonoverlapping(bytes.as_ptr() as *const c_void, size);
    0
}

#[no_mangle]
pub static ETEBASE_UTILS_PRETTY_FINGERPRINT_SIZE: usize =
    1 + // Null
    2 + // Newlines
    (3 * 9) + // Spacing
    (5 * 12); // Digits

/// Return a pretty formatted fingerprint of the content
///
/// For example:
/// ```
/// 45680   71497   88570   93128
/// 19189   84243   25687   20837
/// 47924   46071   54113   18789
/// ```
///
/// @param content the content to create a fingerprint for
/// @param content_size the size of the content buffer
/// @param[out] buf the output byte buffer
#[no_mangle]
pub unsafe extern fn etebase_utils_pretty_fingerprint(content: *const c_void, content_size: usize, buf: *mut c_char) -> i32 {
    let content = std::slice::from_raw_parts(content as *const u8, content_size);
    let fingerprint = etebase::pretty_fingerprint(content);
    buf.copy_from_nonoverlapping(fingerprint.as_ptr() as *const c_char, ETEBASE_UTILS_PRETTY_FINGERPRINT_SIZE);
    *buf.offset(ETEBASE_UTILS_PRETTY_FINGERPRINT_SIZE as isize) = 0;
    0
}

// }


// Class Client {

#[no_mangle]
pub unsafe extern fn etebase_client_new(client_name: *const c_char, server_url: *const c_char) -> *mut Client {
    let client_name = CStr::from_ptr(client_name).to_str().unwrap();
    let server_url = CStr::from_ptr(server_url).to_str().unwrap();
    Box::into_raw(
        Box::new(
            try_or_null!(Client::new(client_name, server_url))
        )
    )
}

#[allow(non_snake_case)]
#[no_mangle]
unsafe extern "C" fn vec_u8_from_size(size: u32) -> *mut Vec<u8> {
    let vec = Vec::with_capacity(size as usize);
    return Box::into_raw(Box::new(vec));
}

#[allow(non_snake_case)]
#[no_mangle]
unsafe extern "C" fn vec_u8_size(vec: &mut Vec<u8>) -> u32 {
    return vec.len() as u32;
}

#[allow(non_snake_case)]
#[no_mangle]
unsafe extern "C" fn vec_u8_buf(vec: &mut Vec<u8>) -> *const u8 {
    let ret = vec.as_ptr();
    return ret;
}


#[no_mangle]
pub unsafe extern fn etebase_client_set_server_url(this: &mut Client, server_url: *const c_char) -> i32 {
    let server_url = CStr::from_ptr(server_url).to_str().unwrap();
    try_or_int!(this.set_server_url(server_url));
    0
}

/// Returns 0 if client is pointing an etebase server, 1 if not, -1 on error
///
/// @param client the object handle
#[no_mangle]
pub unsafe extern fn etebase_client_check_etebase_server(client: &Client) -> i32 {
    let ret = try_or_int!(Account::is_etebase_server(client));
    if ret { 0 } else { 1 }
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_client_destroy(this: *mut Client) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class User {

/// Return a new user instance
///
/// Should be destroyed with `etebase_user_destroy`
///
/// @param username the user's username
/// @param email the user's email
#[no_mangle]
pub unsafe extern fn etebase_user_new(username: *const c_char, email: *const c_char) -> *mut User {
    let username = CStr::from_ptr(username).to_str().unwrap();
    let email = CStr::from_ptr(email).to_str().unwrap();
    Box::into_raw(
        Box::new(
            User::new(username, email)
        )
    )
}

/// Set the username
///
/// @param this_ the object handle
/// @param username the user's username
#[no_mangle]
pub unsafe extern fn etebase_user_set_username(this: &mut User, username: *const c_char) {
    let username = CStr::from_ptr(username).to_str().unwrap();
    this.set_username(username);
}

/// Get the username
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_user_get_username(this: &User) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(this.username()).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// Set the email address
///
/// @param this_ the object handle
/// @param email the user's email address
#[no_mangle]
pub unsafe extern fn etebase_user_set_email(this: &mut User, email: *const c_char) {
    let email = CStr::from_ptr(email).to_str().unwrap();
    this.set_email(email);
}

/// Get the email address
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_user_get_email(this: &User) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(this.email()).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_user_destroy(this: *mut User) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class Account {

/// Login a user and return a handle to an `EtebaseAccount` object
///
/// @param client the already setup `EtebaseClient` object
/// @param username the user's username. This is not the same as the user's email.
/// @param password the user's password
#[no_mangle]
pub unsafe extern fn etebase_account_login(client: &Client, username: *const c_char, password: *const c_char) -> *mut Account {
    let username = CStr::from_ptr(username).to_str().unwrap();
    let password = CStr::from_ptr(password).to_str().unwrap();
    Box::into_raw(
        Box::new(
            try_or_null!(Account::login(client.clone(), username, password))
        )
    )
}

/// Signup a new user account and return a handle to it
///
/// @param client the already setup `EtebaseClient` object
/// @param user the already setup `EtebaseUser` object
/// @param password the password to signup with
#[no_mangle]
pub unsafe extern fn etebase_account_signup(client: &Client, user: &User, password: *const c_char) -> *mut Account {
    let password = CStr::from_ptr(password).to_str().unwrap();
    Box::into_raw(
        Box::new(
            try_or_null!(Account::signup(client.clone(), user, password))
        )
    )
}

/// Fetch a new auth token for the account and update the `EtebaseAccount` object with it
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_account_fetch_token(this: &mut Account) -> i32 {
    try_or_int!(this.fetch_token());
    0
}

/// Fetch the link to the user dashboard of the account
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_account_fetch_dashboard_url(this: &Account) -> *mut c_char {
    let url = try_or_null!(this.fetch_dashboard_url());
    try_or_null!(CString::new(url)).into_raw()
}

/// Change the server URL for this account handle
///
/// @param this_ the object handle
/// @param server_url the new server URL to be set
#[no_mangle]
pub unsafe extern fn etebase_account_force_server_url(this: &mut Account, server_url: *const c_char) -> i32 {
    let server_url = CStr::from_ptr(server_url).to_str().unwrap();
    try_or_int!(this.force_server_url(server_url));
    0
}

/// Change the user's login password
///
/// @param this_ the object handle
/// @param password the new password to be set
#[no_mangle]
pub unsafe extern fn etebase_account_change_password(this: &mut Account, password: *const c_char) -> i32 {
    let password = CStr::from_ptr(password).to_str().unwrap();
    try_or_int!(this.change_password(password));
    0
}

/// Logout the user from the current session and invalidate the authentication token
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_account_logout(this: &mut Account) -> i32 {
    try_or_int!(this.logout());
    0
}

/// Return a `EtebaseCollectionManager` for creating, fetching and uploading collections
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_account_get_collection_manager(this: &Account) -> *mut CollectionManager {
    Box::into_raw(
        Box::new(
            try_or_null!(this.collection_manager())
        )
    )
}

/// Return a `EtebaseCollectionInvitationManager` for managing collection invitations
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_account_get_invitation_manager(this: &Account) -> *mut CollectionInvitationManager {
    Box::into_raw(
        Box::new(
            try_or_null!(this.invitation_manager())
        )
    )
}

/// Save the account object to a string for restoring it later using `etebase_account_restore`
///
/// @param this_ the object handle
/// @param encryption_key used to encrypt the returned account string to enhance security
/// @param encryption_key_size size of the encryption_key
#[no_mangle]
pub unsafe extern fn etebase_account_save(this: &Account, encryption_key: *const c_void, encryption_key_size: usize) -> *mut c_char {
    let encryption_key = if encryption_key.is_null() {
        None
    } else {
        Some(std::slice::from_raw_parts(encryption_key as *const u8, encryption_key_size))
    };
    let saved = try_or_null!(this.save(encryption_key));
    try_or_null!(CString::new(saved)).into_raw()
}

/// Restore and return the account object from the string obtained using `etebase_account_save`
///
/// @param client the already setup `EtebaseClient` object
/// @param account_data_stored the stored account string
/// @param encryption_key the same encryption key passed to `etebase_account_save` while saving the account
/// @param encryption_key_size size of the encryption_key
#[no_mangle]
pub unsafe extern fn etebase_account_restore(client: &Client, account_data_stored: *const c_char, encryption_key: *const c_void, encryption_key_size: usize) -> *mut Account {
    let account_data_stored = CStr::from_ptr(account_data_stored).to_str().unwrap();
    let encryption_key = if encryption_key.is_null() {
        None
    } else {
        Some(std::slice::from_raw_parts(encryption_key as *const u8, encryption_key_size))
    };
    Box::into_raw(
        Box::new(
            try_or_null!(Account::restore(client.clone(), account_data_stored, encryption_key))
        )
    )
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_account_destroy(this: *mut Account) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class RemovedCollection {

/// The uid of the removed collection
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_removed_collection_get_uid(this: &RemovedCollection) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(this.uid()).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_removed_collection_destroy(this: *mut RemovedCollection) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class CollectionListResponse {

type CollectionListResponse = etebase::CollectionListResponse<Collection>;

/// Sync token for the list response
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_list_response_get_stoken(this: &CollectionListResponse) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = this.stoken().map(|x| CString::new(x).unwrap());
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// List of collections included in the response
///
/// @param this_ the object handle
/// @param[out] data the array to store the collections in
#[no_mangle]
pub unsafe extern fn etebase_collection_list_response_get_data(this: &CollectionListResponse, data: *mut *const Collection) -> i32 {
    let ret: Vec<&Collection> = this.data().iter().collect();
    data.copy_from_nonoverlapping(ret.as_ptr() as *mut *const Collection, ret.len());
    0
}

/// The number of collections included in the response
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_list_response_get_data_length(this: &CollectionListResponse) -> usize {
    this.data().len()
}

/// Indicates whether there are no more collections to fetch
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_list_response_is_done(this: &CollectionListResponse) -> bool {
    this.done()
}

/// The list of collections to which the user lost access
///
/// @param this_ the object handle
/// @param[out] data the array to store the collections in
#[no_mangle]
pub unsafe extern fn etebase_collection_list_response_get_removed_memberships(this: &CollectionListResponse, data: *mut *const RemovedCollection) -> i32 {
    let removed_memberships = this.removed_memberships();
    if removed_memberships.is_none() {
        return 0;
    }

    let ret: Vec<&RemovedCollection> = this.removed_memberships().unwrap().iter().collect();
    data.copy_from_nonoverlapping(ret.as_ptr() as *mut *const RemovedCollection, ret.len());
    0
}

/// The number of collections to which the user lost access
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_list_response_get_removed_memberships_length(this: &CollectionListResponse) -> usize {
    if let Some(removed_memberships) = this.removed_memberships() {
        removed_memberships.len()
    } else {
        0
    }
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_list_response_destroy(this: *mut CollectionListResponse) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class ItemListResponse {

type ItemListResponse = etebase::ItemListResponse<Item>;

/// Sync token for the list response
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_list_response_get_stoken(this: &ItemListResponse) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = this.stoken().map(|x| CString::new(x).unwrap());
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// List of items included in the response
///
/// @param this_ the object handle
/// @param[out] data the array to store the items in
#[no_mangle]
pub unsafe extern fn etebase_item_list_response_get_data(this: &ItemListResponse, data: *mut *const Item) -> i32 {
    let ret: Vec<&Item> = this.data().iter().collect();
    data.copy_from_nonoverlapping(ret.as_ptr() as *mut *const Item, ret.len());
    0
}

/// The number of items included in the response
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_list_response_get_data_length(this: &ItemListResponse) -> usize {
    this.data().len()
}

/// Indicates whether there are no more items to fetch
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_list_response_is_done(this: &ItemListResponse) -> bool {
    this.done()
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_list_response_destroy(this: *mut ItemListResponse) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class ItemRevisionsListResponse {

type ItemRevisionsListResponse = etebase::IteratorListResponse<Item>;

/// Iterator for the list response
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_revisions_list_response_get_iterator(this: &ItemRevisionsListResponse) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = this.iterator().map(|x| CString::new(x).unwrap());
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// List of item revisions included in the response
///
/// @param this_ the object handle
/// @param[out] data the array to store the items in
#[no_mangle]
pub unsafe extern fn etebase_item_revisions_list_response_get_data(this: &ItemRevisionsListResponse, data: *mut *const Item) -> i32 {
    let ret: Vec<&Item> = this.data().iter().collect();
    data.copy_from_nonoverlapping(ret.as_ptr() as *mut *const Item, ret.len());
    0
}

/// The number of item revisions included in the response
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_revisions_list_response_get_data_length(this: &ItemRevisionsListResponse) -> usize {
    this.data().len()
}

/// Indicates whether there is no more data to fetch
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_revisions_list_response_is_done(this: &ItemRevisionsListResponse) -> bool {
    this.done()
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_revisions_list_response_destroy(this: *mut ItemRevisionsListResponse) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Enum PrefetchOption {

/// Dictates how much data to prefetch when passed to `EtebaseFetchOptions`
#[repr(u32)]
pub enum PrefetchOption {
    /// Automatically decide based on the size of the data fetched
    Auto,
    /// Attempt to fetch a more lightweight (medium) amount of data
    Medium,
}

// }


// Class FetchOptions {

/// Configuration options for data fetching
pub struct FetchOptions {
    limit: Option<usize>,
    stoken: Option<String>,
    iterator: Option<String>,
    prefetch: Option<etebase::PrefetchOption>,
    with_collection: Option<bool>,
}

impl FetchOptions {
    pub fn new() -> Self {
        Self {
            limit: None,
            stoken: None,
            iterator: None,
            prefetch: None,
            with_collection: None,
        }
    }

    pub fn limit(&mut self, limit: usize) {
        self.limit = Some(limit);
    }

    pub fn prefetch(&mut self, prefetch: PrefetchOption) {
        let prefetch = match prefetch {
            PrefetchOption::Auto => etebase::PrefetchOption::Auto,
            PrefetchOption::Medium => etebase::PrefetchOption::Medium,
        };
        self.prefetch = Some(prefetch);
    }

    pub fn with_collection(&mut self, with_collection: bool) {
        self.with_collection = Some(with_collection);
    }

    pub fn iterator(&mut self, iterator: Option<&str>) {
        self.iterator = iterator.map(str::to_string);
    }

    pub fn stoken(&mut self, stoken: Option<&str>) {
        self.stoken = stoken.map(str::to_string);
    }

    pub fn to_fetch_options<'a>(&'a self) -> etebase::FetchOptions<'a> {
        let mut ret = etebase::FetchOptions::new();
        if let Some(limit) = self.limit {
            ret = ret.limit(limit);
        }
        if let Some(prefetch) = &self.prefetch {
            ret = ret.prefetch(prefetch);
        }
        if let Some(with_collection) = self.with_collection {
            ret = ret.with_collection(with_collection);
        }
        ret = ret.iterator(self.iterator.as_deref());
        ret = ret.stoken(self.stoken.as_deref());
        ret
    }
}

/// Return a new fetch options object
///
/// Should be destroyed with `etebase_fetch_options_destroy`
#[no_mangle]
pub unsafe extern fn etebase_fetch_options_new() -> *mut FetchOptions {
    Box::into_raw(
        Box::new(
            FetchOptions::new()
        )
    )
}

/// Limit the amount of items returned
///
/// @param this_ the object handle
/// @param limit the limit to set
#[no_mangle]
pub unsafe extern fn etebase_fetch_options_set_limit(this: &mut FetchOptions, limit: usize) {
    this.limit(limit);
}

/// How much data to prefetech
///
/// @param this_ the object handle
/// @param prefetch the prefetch option to set
#[no_mangle]
pub unsafe extern fn etebase_fetch_options_set_prefetch(this: &mut FetchOptions, prefetch: PrefetchOption) {
    this.prefetch(prefetch);
}

/// Toggle fetching the collection's item
///
/// @param this_ the object handle
/// @param with_collection set whether to fetch the collection's item
#[no_mangle]
pub unsafe extern fn etebase_fetch_options_set_with_collection(this: &mut FetchOptions, with_collection: bool) {
    this.with_collection(with_collection);
}

/// The current iterator to start from (when iterating lists)
///
/// @param this_ the object handle
/// @param iterator the iterator to start from
#[no_mangle]
pub unsafe extern fn etebase_fetch_options_set_iterator(this: &mut FetchOptions, iterator: *const c_char) {
    let iterator = ptr_to_option(iterator).map(|x| CStr::from_ptr(x).to_str().unwrap());
    this.iterator(iterator);
}

/// The sync token to fetch with
///
/// @param this_ the object handle
/// @param stoken the sync token to set
#[no_mangle]
pub unsafe extern fn etebase_fetch_options_set_stoken(this: &mut FetchOptions, stoken: *const c_char) {
    let stoken = ptr_to_option(stoken).map(|x| CStr::from_ptr(x).to_str().unwrap());
    this.stoken(stoken);
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_fetch_options_destroy(this: *mut FetchOptions) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class ItemMetadata {

/// Create a new metadata object
///
/// Should be destroyed with `etebase_item_metadata_destroy`
#[no_mangle]
pub unsafe extern fn etebase_item_metadata_new() -> *mut ItemMetadata {
    Box::into_raw(
        Box::new(
            ItemMetadata::new()
        )
    )
}

/// Set the item type
///
/// @param this_ the object handle
/// @param item_type the type to be set
#[no_mangle]
pub unsafe extern fn etebase_item_metadata_set_item_type(this: &mut ItemMetadata, item_type: *const c_char) {
    let item_type = ptr_to_option(item_type).map(|x| CStr::from_ptr(x).to_str().unwrap());
    this.set_item_type(item_type);
}

/// The item type
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_metadata_get_item_type(this: &ItemMetadata) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = this.item_type().map(|x| CString::new(x).unwrap());
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// Set the item name
///
/// For example, you can set it to "Secret Note" or "todo.txt"
///
/// @param this_ the object handle
/// @param name the name to be set
#[no_mangle]
pub unsafe extern fn etebase_item_metadata_set_name(this: &mut ItemMetadata, name: *const c_char) {
    let name = ptr_to_option(name).map(|x| CStr::from_ptr(x).to_str().unwrap());
    this.set_name(name);
}

/// The item name
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_metadata_get_name(this: &ItemMetadata) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = this.name().map(|x| CString::new(x).unwrap());
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// Set the modification time of the item
///
/// @param this_ the object handle
/// @param mtime the modification time in milliseconds since epoch
#[no_mangle]
pub unsafe extern fn etebase_item_metadata_set_mtime(this: &mut ItemMetadata, mtime: *const i64) {
    let mtime = if mtime.is_null() {
        None
    } else {
        Some(*mtime)
    };
    this.set_mtime(mtime);
}

/// Modification time of the item
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_metadata_get_mtime(this: &ItemMetadata) -> *const i64 {
    thread_local! {
        static LAST: RefCell<Option<i64>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = this.mtime();
        ret.borrow().as_ref().map(|x| x as *const i64).unwrap_or(std::ptr::null())
    })
}

/// Set a description for the item
///
/// @param this_ the object handle
/// @param description the description to be set
#[no_mangle]
pub unsafe extern fn etebase_item_metadata_set_description(this: &mut ItemMetadata, description: *const c_char) {
    let description = ptr_to_option(description).map(|x| CStr::from_ptr(x).to_str().unwrap());
    this.set_description(description);
}

/// The item description
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_metadata_get_description(this: &ItemMetadata) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = this.description().map(|x| CString::new(x).unwrap());
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// Set a color for the item
///
/// @param this_ the object handle
/// @param color the color to be set in `#RRGGBB` or `#RRGGBBAA` format
#[no_mangle]
pub unsafe extern fn etebase_item_metadata_set_color(this: &mut ItemMetadata, color: *const c_char) {
    let color = ptr_to_option(color).map(|x| CStr::from_ptr(x).to_str().unwrap());
    this.set_color(color);
}

/// The item color in `#RRGGBB` or `#RRGGBBAA` format
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_metadata_get_color(this: &ItemMetadata) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = this.color().map(|x| CString::new(x).unwrap());
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_metadata_destroy(this: *mut ItemMetadata) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class CollectionManager {

/// Fetch a single collection from the server using its UID
///
/// @param this_ the object handle
/// @param col_uid the UID of the collection to be fetched
/// @param fetch_options the `EtebaseFetchOptions` to fetch with
#[no_mangle]
pub unsafe extern fn etebase_collection_manager_fetch(this: &CollectionManager, col_uid: *const c_char, fetch_options: Option<&FetchOptions>) -> *mut Collection {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    let col_uid = CStr::from_ptr(col_uid).to_str().unwrap();
    Box::into_raw(
        Box::new(
            try_or_null!(this.fetch(col_uid, fetch_options.as_ref()))
        )
    )
}

/// Create a new collection
///
/// Should be destroyed with `etebase_collection_destroy`
///
/// @param this_ the object handle
/// @param collection_type the type of [Item]s stored in the collection
/// @param meta the [ItemMetadata] for the collection
/// @param content the collection's content as a byte array. This is unrelated to the [Item]s in the collection.
/// @param content_size the content size
#[no_mangle]
pub unsafe extern fn etebase_collection_manager_create(this: &CollectionManager, collection_type: *const c_char, meta: &ItemMetadata, content: *const c_void, content_size: usize) -> *mut Collection {
    let collection_type = CStr::from_ptr(collection_type).to_str().unwrap();
    let content = std::slice::from_raw_parts(content as *const u8, content_size);
    Box::into_raw(
        Box::new(
            try_or_null!(this.create(collection_type, meta, content))
        )
    )
}

/// Create a new collection using raw metadata
///
/// Unlike `etebase_collection_manager_create`, this receives the metadata as valid `EtebaseItemMetadata`-like struct encoded using `msgpack`.
/// This can be used to create collections with custom metadata types.
///
/// Should be destroyed with `etebase_collection_destroy`
///
/// @param this_ the object handle
/// @param collection_type the type of [Item]s stored in the collection
/// @param meta the metadata for the collection as a byte array
/// @param meta_size the metadata size
/// @param content the collection's content as a byte array. This is unrelated to the [Item]s in the collection.
/// @param content_size the content size
#[no_mangle]
pub unsafe extern fn etebase_collection_manager_create_raw(this: &CollectionManager, collection_type: *const c_char, meta: *const c_void, meta_size: usize, content: *const c_void, content_size: usize) -> *mut Collection {
    let collection_type = CStr::from_ptr(collection_type).to_str().unwrap();
    let meta = std::slice::from_raw_parts(meta as *const u8, meta_size);
    let content = std::slice::from_raw_parts(content as *const u8, content_size);
    Box::into_raw(
        Box::new(
            try_or_null!(this.create_raw(collection_type, meta, content))
        )
    )
}

/// Return the item manager for the supplied collection
///
/// @param this_ the object handle
/// @param col the collection for which the item manager is required
#[no_mangle]
pub unsafe extern fn etebase_collection_manager_get_item_manager(this: &CollectionManager, col: &Collection) -> *mut ItemManager {
    Box::into_raw(
        Box::new(
            try_or_null!(this.item_manager(col))
        )
    )
}

/// Fetch all collections of a specific type from the server and return a list response
///
/// @param this_ the object handle
/// @param collection_type the type of items stored in the collection
/// @param fetch_options the `EtebaseFetchOptions` to fetch with
#[no_mangle]
pub unsafe extern fn etebase_collection_manager_list(this: &CollectionManager, collection_type: *const c_char, fetch_options: Option<&FetchOptions>) -> *mut CollectionListResponse {
    let collection_type = CStr::from_ptr(collection_type).to_str().unwrap();
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    Box::into_raw(
        Box::new(
            try_or_null!(this.list(collection_type, fetch_options.as_ref()))
        )
    )
}

/// Fetch all collections of the supplied types from the server and return a list response
///
/// @param this_ the object handle
/// @param collection_types array of strings denoting the collection types
/// @param collection_types_size size of the collection_types array
/// @param fetch_options the `EtebaseFetchOptions` to fetch with
#[no_mangle]
pub unsafe extern fn etebase_collection_manager_list_multi(this: &CollectionManager, collection_types: *const *const c_char, collection_types_size: usize, fetch_options: Option<&FetchOptions>) -> *mut CollectionListResponse {
    let collection_types = std::slice::from_raw_parts(collection_types, collection_types_size).into_iter().map(|x| CStr::from_ptr(*x).to_str().unwrap());
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    Box::into_raw(
        Box::new(
            try_or_null!(this.list_multi(collection_types, fetch_options.as_ref()))
        )
    )
}

/// Upload a collection
///
/// @param this_ the object handle
/// @param collection the collection object to be uploaded
/// @param fetch_options the `EtebaseFetchOptions` to upload with
#[no_mangle]
pub unsafe extern fn etebase_collection_manager_upload(this: &CollectionManager, collection: &Collection, fetch_options: Option<&FetchOptions>) -> i32 {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    try_or_int!(this.upload(collection, fetch_options.as_ref()));
    0
}

/// Upload a collection using a transaction
///
/// This call ensures that the collection hasn't changed since we last fetched it
///
/// @param this_ the object handle
/// @param collection the collection object to be uploaded
/// @param fetch_options the `EtebaseFetchOptions` to upload with
#[no_mangle]
pub unsafe extern fn etebase_collection_manager_transaction(this: &CollectionManager, collection: &Collection, fetch_options: Option<&FetchOptions>) -> i32 {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    try_or_int!(this.transaction(collection, fetch_options.as_ref()));
    0
}

/// Load and return a cached collection object from a byte buffer
///
/// @param this_ the object handle
/// @param cached the byte buffer holding the cached collection obtained using [cache_save]
/// @param cached_size size of the buffer
#[no_mangle]
pub unsafe extern fn etebase_collection_manager_cache_load(this: &CollectionManager, cached: *const c_void, cached_size: usize) -> *mut Collection {
    let cached = std::slice::from_raw_parts(cached as *const u8, cached_size);
    Box::into_raw(
        Box::new(
            try_or_null!(this.cache_load(cached))
        )
    )
}

/// Save the collection object to a byte buffer for caching
///
/// The collection can later be loaded using `etebase_collection_manager_cache_load`
///
/// @param this_ the object handle
/// @param collection the collection object to be cached
/// @param[out] ret_size to hold the size of the returned buffer
#[no_mangle]
pub unsafe extern fn etebase_collection_manager_cache_save(this: &CollectionManager, collection: &Collection, ret_size: *mut usize) -> *mut c_void {
    let mut ret = try_or_null!(this.cache_save(collection));
    if !ret_size.is_null() {
        *ret_size = ret.len();
    }
    let ret_raw = ret.as_mut_ptr() as *mut c_void;
    std::mem::forget(ret);
    ret_raw
}

/// Save the collection object and its content to a byte buffer for caching
///
/// The collection can later be loaded using `etebase_collection_manager_cache_load`
///
/// @param this_ the object handle
/// @param collection the collection object to be cached
/// @param[out] ret_size to hold the size of the returned buffer
#[no_mangle]
pub unsafe extern fn etebase_collection_manager_cache_save_with_content(this: &CollectionManager, collection: &Collection, ret_size: *mut usize) ->*mut c_void {
    let mut ret = try_or_null!(this.cache_save_with_content(collection));
    if !ret_size.is_null() {
        *ret_size = ret.len();
    }
    let ret_raw = ret.as_mut_ptr() as *mut c_void;
    std::mem::forget(ret);
    ret_raw
}

/// Return the collection member manager for the supplied collection
///
/// @param this_ the object handle
/// @param col the collection for which the manager is required
#[no_mangle]
pub unsafe extern fn etebase_collection_manager_get_member_manager(this: &CollectionManager, col: &Collection) -> *mut CollectionMemberManager {
    Box::into_raw(
        Box::new(
            try_or_null!(this.member_manager(col))
        )
    )
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_manager_destroy(this: *mut CollectionManager) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class ItemManager {

/// Fetch a single item from the server using its UID
///
/// @param this_ the object handle
/// @param item_uid the UID of the item to be fetched
/// @param fetch_options the `EtebaseFetchOptions` to fetch with
#[no_mangle]
pub unsafe extern fn etebase_item_manager_fetch(this: &ItemManager, item_uid: *const c_char, fetch_options: Option<&FetchOptions>) -> *mut Item {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    let item_uid = CStr::from_ptr(item_uid).to_str().unwrap();
    Box::into_raw(
        Box::new(
            try_or_null!(this.fetch(item_uid, fetch_options.as_ref()))
        )
    )
}

/// Create a new item
///
/// Should be destroyed with `etebase_item_destroy`
///
/// @param this_ the object handle
/// @param meta the [ItemMetadata] for the item
/// @param content the item's content as a byte array
/// @param content_size the content size
#[no_mangle]
pub unsafe extern fn etebase_item_manager_create(this: &ItemManager, meta: &ItemMetadata, content: *const c_void, content_size: usize) -> *mut Item {
    let content = std::slice::from_raw_parts(content as *const u8, content_size);
    Box::into_raw(
        Box::new(
            try_or_null!(this.create(meta, content))
        )
    )
}

/// Create a new item using raw metadata
///
/// Unlike `etebase_item_manager_create`, this receives the metadata as valid `EtebaseItemMetadata`-like struct encoded using `msgpack`.
/// This can be used to create collections with custom metadata types.
///
/// Should be destroyed with `etebase_item_destroy`
///
/// @param this_ the object handle
/// @param meta the metadata for the item as a byte array
/// @param meta_size the metadata size
/// @param content the item's content as a byte array
/// @param content_size the content size
#[no_mangle]
pub unsafe extern fn etebase_item_manager_create_raw(this: &ItemManager, meta: *const c_void, meta_size: usize, content: *const c_void, content_size: usize) -> *mut Item {
    let meta = std::slice::from_raw_parts(meta as *const u8, meta_size);
    let content = std::slice::from_raw_parts(content as *const u8, content_size);
    Box::into_raw(
        Box::new(
            try_or_null!(this.create_raw(meta, content))
        )
    )
}

/// Fetch all items of a collection and return a list response
///
/// @param this_ the object handle
/// @param fetch_options the `EtebaseFetchOptions` to fetch with
#[no_mangle]
pub unsafe extern fn etebase_item_manager_list(this: &ItemManager, fetch_options: Option<&FetchOptions>) -> *mut ItemListResponse {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    Box::into_raw(
        Box::new(
            try_or_null!(this.list(fetch_options.as_ref()))
        )
    )
}

/// Fetch and return a list response of items with each item as the revision
///
/// @param this_ the object handle
/// @param item the item for which to fetch the revision history
/// @param fetch_options the `EtebaseFetchOptions` to fetch with
#[no_mangle]
pub unsafe extern fn etebase_item_manager_item_revisions(this: &ItemManager, item: &Item, fetch_options: Option<&FetchOptions>) -> *mut ItemRevisionsListResponse {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    Box::into_raw(
        Box::new(
            try_or_null!(this.item_revisions(item, fetch_options.as_ref()))
        )
    )
}

/// Fetch the latest revision of the supplied items from the server and return a list response
///
/// @param this_ the object handle
/// @param items the list of items to be fetched
/// @param items_size the number of items
/// @param fetch_options the `EtebaseFetchOptions` to fetch with
#[no_mangle]
pub unsafe extern fn etebase_item_manager_fetch_updates(this: &ItemManager, items: *const &Item, items_size: usize, fetch_options: Option<&FetchOptions>) -> *mut ItemListResponse {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    let items = std::slice::from_raw_parts(items, items_size).into_iter().map(|x| *x);
    Box::into_raw(
        Box::new(
            try_or_null!(this.fetch_updates(items, fetch_options.as_ref()))
        )
    )
}

/// Fetch multiple Items using their UID
///
/// See etebase_item_manager_fetch for fetching a single item
///
/// @param this_ the object handle
/// @param items the list of item uids to be fetched
/// @param items_size the number of items
/// @param fetch_options the `EtebaseFetchOptions` to fetch with
#[no_mangle]
pub unsafe extern fn etebase_item_manager_fetch_multi(this: &ItemManager, items: *const *const c_char, items_size: usize, fetch_options: Option<&FetchOptions>) -> *mut ItemListResponse {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    let items = std::slice::from_raw_parts(items, items_size).into_iter().map(|x| CStr::from_ptr(*x).to_str().unwrap());
    Box::into_raw(
        Box::new(
            try_or_null!(this.fetch_multi(items, fetch_options.as_ref()))
        )
    )
}

/// Upload the supplied items to the server
///
/// @param this_ the object handle
/// @param items the list of items to be uploaded
/// @param items_size the number of items
/// @param fetch_options the `EtebaseFetchOptions` to upload with
#[no_mangle]
pub unsafe extern fn etebase_item_manager_batch(this: &ItemManager, items: *const &Item, items_size: usize, fetch_options: Option<&FetchOptions>) -> i32 {
    etebase_item_manager_batch_deps(this, items, items_size, std::ptr::null(), 0, fetch_options)
}

/// Upload the supplied items to the server with a list of items as dependencies
///
/// This will fail if the dependencies have changed remotely
///
/// @param this_ the object handle
/// @param items the list of items to be uploaded
/// @param items_size the number of items
/// @param deps the list of items to be treated as dependencies
/// @param deps_size the number of dependencies
/// @param fetch_options the `EtebaseFetchOptions` to upload with
#[no_mangle]
pub unsafe extern fn etebase_item_manager_batch_deps(this: &ItemManager, items: *const &Item, items_size: usize, deps: *const &Item, deps_size: usize, fetch_options: Option<&FetchOptions>) -> i32 {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    let items = std::slice::from_raw_parts(items, items_size).into_iter().map(|x| *x);
    let deps = ptr_to_option(deps);
    if let Some(deps) = deps {
        let deps = std::slice::from_raw_parts(deps, deps_size).into_iter().map(|x| *x);
        try_or_int!(this.batch_deps(items, deps, fetch_options.as_ref()));
    } else {
        try_or_int!(this.batch(items, fetch_options.as_ref()));
    }
    0
}

/// Upload items using a transaction
///
/// This call ensures that the items haven't changed since we last fetched them
///
/// @param this_ the object handle
/// @param items the list of items to be uploaded
/// @param items_size the number of items
/// @param fetch_options the `EtebaseFetchOptions` to upload with
#[no_mangle]
pub unsafe extern fn etebase_item_manager_transaction(this: &ItemManager, items: *const &Item, items_size: usize, fetch_options: Option<&FetchOptions>) -> i32 {
    etebase_item_manager_transaction_deps(this, items, items_size, std::ptr::null(), 0, fetch_options)
}

/// Upload items using a transaction with a list of items as dependencies
///
/// @param this_ the object handle
/// @param items the list of items to be uploaded
/// @param items_size the number of items
/// @param deps the list of items to be treated as dependencies
/// @param deps_size the number of dependencies
/// @param fetch_options the `EtebaseFetchOptions` to upload with
#[no_mangle]
pub unsafe extern fn etebase_item_manager_transaction_deps(this: &ItemManager, items: *const &Item, items_size: usize, deps: *const &Item, deps_size: usize, fetch_options: Option<&FetchOptions>) -> i32 {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    let items = std::slice::from_raw_parts(items, items_size).into_iter().map(|x| *x);
    let deps = ptr_to_option(deps);
    if let Some(deps) = deps {
        let deps = std::slice::from_raw_parts(deps, deps_size).into_iter().map(|x| *x);
        try_or_int!(this.transaction_deps(items, deps, fetch_options.as_ref()));
    } else {
        try_or_int!(this.transaction(items, fetch_options.as_ref()));
    }
    0
}

/// Load and return a cached item from a byte buffer
///
/// @param this_ the object handle
/// @param cached the byte buffer holding the cached item obtained using [cache_save]
/// @param cached_size size of the buffer
#[no_mangle]
pub unsafe extern fn etebase_item_manager_cache_load(this: &ItemManager, cached: *const c_void, cached_size: usize) -> *mut Item {
    let cached = std::slice::from_raw_parts(cached as *const u8, cached_size);
    Box::into_raw(
        Box::new(
            try_or_null!(this.cache_load(cached))
        )
    )
}

/// Save the item object to a byte buffer for caching
///
/// The item can later be loaded using `etebase_item_manager_cache_load`
///
/// @param this_ the object handle
/// @param item the item object to be cached
/// @param[out] ret_size to hold the size of the returned buffer
#[no_mangle]
pub unsafe extern fn etebase_item_manager_cache_save(this: &ItemManager, item: &Item, ret_size: *mut usize) -> *mut c_void {
    let mut ret = try_or_null!(this.cache_save(item));
    if !ret_size.is_null() {
        *ret_size = ret.len();
    }
    let ret_raw = ret.as_mut_ptr() as *mut c_void;
    std::mem::forget(ret);
    ret_raw
}

/// Save the item object and its content to a byte buffer for caching
///
/// The item can later be loaded using `etebase_item_manager_cache_load`
///
/// @param this_ the object handle
/// @param item the item object to be cached
/// @param[out] ret_size to hold the size of the returned buffer
#[no_mangle]
pub unsafe extern fn etebase_item_manager_cache_save_with_content(this: &ItemManager, item: &Item, ret_size: *mut usize) ->*mut c_void {
    let mut ret = try_or_null!(this.cache_save_with_content(item));
    if !ret_size.is_null() {
        *ret_size = ret.len();
    }
    let ret_raw = ret.as_mut_ptr() as *mut c_void;
    std::mem::forget(ret);
    ret_raw
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_manager_destroy(this: *mut ItemManager) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class Collection {

/// Clone a collection object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_clone(this: &Collection) -> *mut Collection {
    Box::into_raw(
        Box::new(
            this.clone()
        )
    )
}

/// Manually verify the integrity of the collection
///
/// This is also done automatically by the API
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_verify(this: &Collection) -> bool {
    this.verify().unwrap_or(false)
}

/// Set metadata for the collection object
///
/// @param this_ the object handle
/// @param meta the metadata object to be set for the collection
#[no_mangle]
pub unsafe extern fn etebase_collection_set_meta(this: &mut Collection, meta: &ItemMetadata) -> i32 {
    try_or_int!(this.set_meta(meta));
    0
}

/// Return the metadata of the collection
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_get_meta(this: &Collection) -> *mut ItemMetadata {
    Box::into_raw(
        Box::new(
            try_or_null!(this.meta())
        )
    )
}

/// Set metadata for the collection object from a byte array
///
/// @param this_ the object handle
/// @param meta the metadata for the collection. This needs to be a valid `EtebaseItemMetadata`-like struct encoded using `msgpack`.
/// @param meta_size the metadata size
#[no_mangle]
pub unsafe extern fn etebase_collection_set_meta_raw(this: &mut Collection, meta: *const c_void, meta_size: usize) -> i32 {
    let meta = std::slice::from_raw_parts(meta as *const u8, meta_size);
    try_or_int!(this.set_meta_raw(meta));
    0
}

/// Write the metadata of the collection to a byte array and return its length
///
/// @param this_ the object handle
/// @param[out] buf the output byte buffer
/// @param buf_size the maximum number of bytes to be written to buf
#[no_mangle]
pub unsafe extern fn etebase_collection_get_meta_raw(this: &Collection, buf: *mut c_void, buf_size: usize) -> isize {
    let ret = try_or_int!(this.meta_raw());
    let size = std::cmp::min(buf_size, ret.len());
    buf.copy_from_nonoverlapping(ret.as_ptr() as *const c_void, size);
    size as isize
}

/// Set the content of the collection
///
/// @param this_ the object handle
/// @param content the content of the collection as a byte array
/// @param content_size the content size
#[no_mangle]
pub unsafe extern fn etebase_collection_set_content(this: &mut Collection, content: *const c_void, content_size: usize) -> i32 {
    let content = std::slice::from_raw_parts(content as *const u8, content_size);
    try_or_int!(this.set_content(content));
    0
}

/// Write the content of the collection to a byte array and return its length
///
/// @param this_ the object handle
/// @param[out] buf the output byte buffer
/// @param buf_size the maximum number of bytes to be written to buf
#[no_mangle]
pub unsafe extern fn etebase_collection_get_content(this: &Collection, buf: *mut c_void, buf_size: usize) -> isize {
    let ret = try_or_int!(this.content());
    let size = std::cmp::min(buf_size, ret.len());
    buf.copy_from_nonoverlapping(ret.as_ptr() as *const c_void, size);
    ret.len() as isize
}

/// Mark the collection as deleted
///
/// The collection needs to be \ref uploaded `etebase_collection_manager_upload` for this to take effect
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_delete(this: &mut Collection) -> i32 {
    try_or_int!(this.delete());
    0
}

/// Check whether the collection is marked as deleted
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_is_deleted(this: &Collection) -> bool {
    this.is_deleted()
}

/// The UID of the collection
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_get_uid(this: &Collection) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(this.uid()).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// The etag of the collection
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_get_etag(this: &Collection) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(this.etag()).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// The sync token for the collection
///
/// The sync token reflects changes to the collection properties or its items on the server
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_get_stoken(this: &Collection) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = this.stoken().map(|x| CString::new(x).unwrap());
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// Return the collection as an item
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_as_item(this: &Collection) -> *mut Item {
    Box::into_raw(
        Box::new(
            try_or_null!(this.item())
        )
    )
}

/// The type of the collection
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_get_collection_type(this: &Collection) -> *mut c_char {
    CString::new(try_or_null!(this.collection_type())).unwrap().into_raw()
}

/// Return the access level of the collection for the current user
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_get_access_level(this: &Collection) -> CollectionAccessLevel {
    this.access_level()
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_destroy(this: *mut Collection) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class Item {

/// Clone an item object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_clone(this: &Item) -> *mut Item {
    Box::into_raw(
        Box::new(
            this.clone()
        )
    )
}

/// Manually verify the integrity of the item
///
/// This is also done automatically by the API
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_verify(this: &Item) -> bool {
    this.verify().unwrap_or(false)
}

/// Set metadata for the item object
///
/// @param this_ the object handle
/// @param meta the metadata object to be set for the item
#[no_mangle]
pub unsafe extern fn etebase_item_set_meta(this: &mut Item, meta: &ItemMetadata) -> i32 {
    try_or_int!(this.set_meta(meta));
    0
}

/// Return the metadata of the item
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_get_meta(this: &Item) -> *mut ItemMetadata {
    Box::into_raw(
        Box::new(
            try_or_null!(this.meta())
        )
    )
}

/// Set metadata for the item object from a byte array
///
/// @param this_ the object handle
/// @param meta the metadata for the item. This needs to be a valid `EtebaseItemMetadata`-like struct encoded using `msgpack`.
/// @param meta_size the metadata size
#[no_mangle]
pub unsafe extern fn etebase_item_set_meta_raw(this: &mut Item, meta: *const c_void, meta_size: usize) -> i32 {
    let meta = std::slice::from_raw_parts(meta as *const u8, meta_size);
    try_or_int!(this.set_meta_raw(meta));
    0
}

/// Write the metadata of the item to a byte array and return its length
///
/// @param this_ the object handle
/// @param[out] buf the output byte buffer
/// @param buf_size the maximum number of bytes to be written to buf
#[no_mangle]
pub unsafe extern fn etebase_item_get_meta_raw(this: &Item, buf: *mut c_void, buf_size: usize) -> isize {
    let ret = try_or_int!(this.meta_raw());
    let size = std::cmp::min(buf_size, ret.len());
    buf.copy_from_nonoverlapping(ret.as_ptr() as *const c_void, size);
    size as isize
}


/// Set the content of the item
///
/// @param this_ the object handle
/// @param content the content of the item as a byte array
/// @param content_size the content size
#[no_mangle]
pub unsafe extern fn etebase_item_set_content(this: &mut Item, content: *const c_void, content_size: usize) -> i32 {
    let content = std::slice::from_raw_parts(content as *const u8, content_size);
    try_or_int!(this.set_content(content));
    0
}

/// Write the content of the item to a byte array and return its length
///
/// @param this_ the object handle
/// @param[out] buf the output byte buffer
/// @param buf_size the maximum number of bytes to be written to buf
#[no_mangle]
pub unsafe extern fn etebase_item_get_content(this: &Item, buf: *mut c_void, buf_size: usize) -> isize {
    let ret = try_or_int!(this.content());
    let size = std::cmp::min(buf_size, ret.len());
    buf.copy_from_nonoverlapping(ret.as_ptr() as *const c_void, size);
    ret.len() as isize
}

/// Mark the item as deleted
///
/// The item needs to be \ref uploaded `etebase_item_manager_batch` for this to take effect
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_delete(this: &mut Item) -> i32 {
    try_or_int!(this.delete());
    0
}

/// Check whether the item is marked as deleted
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_is_deleted(this: &Item) -> bool {
    this.is_deleted()
}

/// The UID of the item
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_get_uid(this: &Item) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(this.uid()).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// The etag of the item
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_get_etag(this: &Item) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(this.etag()).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_item_destroy(this: *mut Item) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class UserProfile {

/// The user's identity public key
///
/// This is used for identifying the user and safely sending them data (such as \ref invitations EtebaseSignedInvitation).
#[no_mangle]
pub unsafe extern fn etebase_user_profile_get_pubkey(this: &UserProfile) -> *const c_void {
    this.pubkey().as_ptr() as *const c_void
}

/// The size of the user's identity public key
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_user_profile_get_pubkey_size(this: &UserProfile) -> usize {
    this.pubkey().len()
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_user_profile_destroy(this: *mut UserProfile) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// class InvitationListResponse {

type InvitationListResponse = etebase::IteratorListResponse<SignedInvitation>;

/// Iterator for the list response
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_invitation_list_response_get_iterator(this: &InvitationListResponse) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = this.iterator().map(|x| CString::new(x).unwrap());
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// List of invitations included in the response
///
/// @param this_ the object handle
/// @param[out] data the array to store the items in
#[no_mangle]
pub unsafe extern fn etebase_invitation_list_response_get_data(this: &InvitationListResponse, data: *mut *const SignedInvitation) -> i32 {
    let ret: Vec<&SignedInvitation> = this.data().iter().collect();
    data.copy_from_nonoverlapping(ret.as_ptr() as *mut *const SignedInvitation, ret.len());
    0
}

/// The number of invitations included in the response
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_invitation_list_response_get_data_length(this: &InvitationListResponse) -> usize {
    this.data().len()
}

/// Indicates whether there is no more data to fetch
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_invitation_list_response_is_done(this: &InvitationListResponse) -> bool {
    this.done()
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_invitation_list_response_destroy(this: *mut InvitationListResponse) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class InvitationManager {

/// List the incoming collection invitations for the account
///
/// @param this_ the object handle
/// @param fetch_options the `EtebaseFetchOptions` to fetch with
#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_list_incoming(this: &CollectionInvitationManager, fetch_options: Option<&FetchOptions>) -> *mut InvitationListResponse {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    Box::into_raw(
        Box::new(
            try_or_null!(this.list_incoming(fetch_options.as_ref()))
        )
    )
}

/// List the outgoing collection invitations for the account
///
/// @param this_ the object handle
/// @param fetch_options the `EtebaseFetchOptions` to fetch with
#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_list_outgoing(this: &CollectionInvitationManager, fetch_options: Option<&FetchOptions>) -> *mut InvitationListResponse {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    Box::into_raw(
        Box::new(
            try_or_null!(this.list_outgoing(fetch_options.as_ref()))
        )
    )
}

/// Accept an invitation
///
/// @param this_ the object handle
/// @param invitation the invitation to accept
#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_accept(this: &CollectionInvitationManager, invitation: &SignedInvitation) -> i32 {
    try_or_int!(this.accept(invitation));
    0
}

/// Reject an invitation
///
/// @param this_ the object handle
/// @param invitation the invitation to reject
#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_reject(this: &CollectionInvitationManager, invitation: &SignedInvitation) -> i32 {
    try_or_int!(this.accept(invitation));
    0
}

/// Fetch and return a user's profile
///
/// @param this_ the object handle
/// @param username the username of the user to fetch
#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_fetch_user_profile(this: &CollectionInvitationManager, username: *const c_char) -> *mut UserProfile {
    let username = CStr::from_ptr(username).to_str().unwrap();
    Box::into_raw(
        Box::new(
            try_or_null!(this.fetch_user_profile(username))
        )
    )
}

/// Invite a user to a collection
///
/// @param this_ the object handle
/// @param collection the collection to invite to
/// @param username the username of the user to invite
/// @param pubkey the public key of the user to invite
/// @param pubkey_size the size of the public key
/// @param access_level the level of access to give to user
#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_invite(this: &CollectionInvitationManager, collection: &Collection, username: *const c_char, pubkey: *const c_void, pubkey_size: usize, access_level: CollectionAccessLevel) -> i32 {
    let username = CStr::from_ptr(username).to_str().unwrap();
    let pubkey = std::slice::from_raw_parts(pubkey as *const u8, pubkey_size);
    try_or_int!(this.invite(collection, username, pubkey, access_level));
    0
}

/// Cancel an invitation (disinvite)
///
/// @param this_ the object handle
/// @param invitation the invitation to cancel
#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_disinvite(this: &CollectionInvitationManager, invitation: &SignedInvitation) -> i32 {
    try_or_int!(this.disinvite(invitation));
    0
}

/// Our identity's public key
///
/// This is the key users see when we send invitations.
/// Can be pretty printed with `etebase_utils_pretty_fingerprint`.
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_get_pubkey(this: &CollectionInvitationManager) -> *const c_void {
    this.pubkey().as_ptr() as *const c_void
}

/// The size of our identity's public key
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_get_pubkey_size(this: &CollectionInvitationManager) -> usize {
    this.pubkey().len()
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_destroy(this: *mut CollectionInvitationManager) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class SignedInvitation {

/// Clone the invitation object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_signed_invitation_clone(this: &SignedInvitation) -> *mut SignedInvitation {
    Box::into_raw(
        Box::new(
            this.clone()
        )
    )
}

/// The uid of the invitation
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_signed_invitation_get_uid(this: &SignedInvitation) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(this.uid()).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// The username this invitation is for
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_signed_invitation_get_username(this: &SignedInvitation) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(this.username()).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// The uid of the collection this invitation is for
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_signed_invitation_get_collection(this: &SignedInvitation) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(this.collection()).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// The access level offered in this invitation
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_signed_invitation_get_access_level(this: &SignedInvitation) -> CollectionAccessLevel {
    this.access_level()
}

/// The username this invitation is from
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_signed_invitation_get_from_username(this: &SignedInvitation) -> *const c_void {
    this.from_username().map(|x| x.as_ptr()).unwrap_or(std::ptr::null()) as *const c_void
}

/// The public key of the inviting user
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_signed_invitation_get_from_pubkey(this: &SignedInvitation) -> *const c_void {
    this.from_pubkey().as_ptr() as *const c_void
}

/// The size of the public key of the inviting user
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_signed_invitation_get_from_pubkey_size(this: &SignedInvitation) -> usize {
    this.from_pubkey().len()
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_signed_invitation_destroy(this: *mut SignedInvitation) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class CollectionMember {

/// Clone the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_member_clone(this: &CollectionMember) -> *mut CollectionMember {
    Box::into_raw(
        Box::new(
            this.clone()
        )
    )
}

/// The username of a member
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_member_get_username(this: &CollectionMember) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(this.username()).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// The access_level of the member
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_member_get_access_level(this: &CollectionMember) -> CollectionAccessLevel {
    this.access_level()
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_member_destroy(this: *mut CollectionMember) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class MemberListResponse {

type MemberListResponse = etebase::IteratorListResponse<CollectionMember>;

/// Iterator for the list response
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_member_list_response_get_iterator(this: &MemberListResponse) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = this.iterator().map(|x| CString::new(x).unwrap());
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

/// List of collection members included in the response
///
/// @param this_ the object handle
/// @param[out] data the array to store the collection members in
#[no_mangle]
pub unsafe extern fn etebase_member_list_response_get_data(this: &MemberListResponse, data: *mut *const CollectionMember) -> i32 {
    let ret: Vec<&CollectionMember> = this.data().iter().collect();
    data.copy_from_nonoverlapping(ret.as_ptr() as *mut *const CollectionMember, ret.len());
    0
}

/// The number of collection members included in the response
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_member_list_response_get_data_length(this: &MemberListResponse) -> usize {
    this.data().len()
}

/// Indicates whether there is no more data to fetch
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_member_list_response_is_done(this: &MemberListResponse) -> bool {
    this.done()
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_member_list_response_destroy(this: *mut MemberListResponse) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class CollectionMemberManager {

/// List the members of a collection
///
/// @param this_ the object handle
/// @param fetch_options the `EtebaseFetchOptions` to fetch with
#[no_mangle]
pub unsafe extern fn etebase_collection_member_manager_list(this: &CollectionMemberManager, fetch_options: Option<&FetchOptions>) -> *mut MemberListResponse {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    Box::into_raw(
        Box::new(
            try_or_null!(this.list(fetch_options.as_ref()))
        )
    )
}

/// Remove a member from the collection
///
/// @param this_ the object handle
/// @param username the member's username
#[no_mangle]
pub unsafe extern fn etebase_collection_member_manager_remove(this: &CollectionMemberManager, username: *const c_char) -> i32 {
    let username = CStr::from_ptr(username).to_str().unwrap();
    try_or_int!(this.remove(username));
    0
}

/// Leave a collection the user is a member of
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_member_manager_leave(this: &CollectionMemberManager) -> i32 {
    try_or_int!(this.leave());
    0
}

/// Modify the access level of a member
///
/// @param this_ the object handle
/// @param username the member's username
/// @param access_level the new `EtebaseCollectionAccessLevel`
#[no_mangle]
pub unsafe extern fn etebase_collection_member_manager_modify_access_level(this: &CollectionMemberManager, username: *const c_char, access_level: CollectionAccessLevel) -> i32 {
    let username = CStr::from_ptr(username).to_str().unwrap();
    try_or_int!(this.modify_access_level(username, access_level));
    0
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_collection_member_manager_destroy(this: *mut CollectionMemberManager) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class FileSystemCache {

/// Initialize a file system cache object
///
/// Should be destroyed with `etebase_fs_cache_destroy`
///
/// @param path the path to a directory to store cache in
/// @param username username of the user to cache data for
#[no_mangle]
pub unsafe extern fn etebase_fs_cache_new(path: *const c_char, username: *const c_char) -> *mut FileSystemCache {
    let path = PathBuf::from(CStr::from_ptr(path).to_str().unwrap());
    let username = CStr::from_ptr(username).to_str().unwrap();
    Box::into_raw(
        Box::new(
            try_or_null!(FileSystemCache::new(path.as_path(), username))
        )
    )
}

/// Clear all cache for the user
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_fs_cache_clear_user(this: &FileSystemCache) -> i32 {
    try_or_int!(this.clear_user_cache());
    0
}

/// Save the user account
///
/// Load it later using `etebase_fs_cache_load_account`
///
/// @param this_ the object handle
/// @param etebase the account to save
/// @param encryption_key used to encrypt the saved account string to enhance security
/// @param encryption_key_size the size of the encryption_key
#[no_mangle]
pub unsafe extern fn etebase_fs_cache_save_account(this: &FileSystemCache, etebase: &Account, encryption_key: *const c_void, encryption_key_size: usize) -> i32 {
    let encryption_key = if encryption_key.is_null() {
        None
    } else {
        Some(std::slice::from_raw_parts(encryption_key as *const u8, encryption_key_size))
    };
    try_or_int!(this.save_account(etebase, encryption_key));
    0
}

/// Load the account object from cache
///
/// @param this_ the object handle
/// @param client the already setup [Client] object
/// @param encryption_key the same encryption key passed to [Self::save_account] while saving the account
/// @param encryption_key_size the size of the encryption_key
#[no_mangle]
pub unsafe extern fn etebase_fs_cache_load_account(this: &FileSystemCache, client: &Client, encryption_key: *const c_void, encryption_key_size: usize) -> *mut Account {
    let encryption_key = if encryption_key.is_null() {
        None
    } else {
        Some(std::slice::from_raw_parts(encryption_key as *const u8, encryption_key_size))
    };
    Box::into_raw(
        Box::new(
            try_or_null!(this.load_account(client, encryption_key))
        )
    )
}

/// Save the collection list sync token
///
/// @param this_ the object handle
/// @param stoken the sync token to be saved
#[no_mangle]
pub unsafe extern fn etebase_fs_cache_save_stoken(this: &FileSystemCache, stoken: *const c_char) -> i32 {
    let stoken = CStr::from_ptr(stoken).to_str().unwrap();
    try_or_int!(this.save_stoken(stoken));
    0
}

/// Load the collection list sync token from cache
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_fs_cache_load_stoken(this: &FileSystemCache) -> *mut c_char {
    let stoken = try_or_null!(this.load_stoken());
    match stoken {
        Some(stoken) => try_or_null!(CString::new(stoken)).into_raw(),
        None => std::ptr::null_mut()
    }
}

/// Save a collection's sync token
///
/// @param this_ the object handle
/// @param col_uid the UID of the collection
/// @param stoken the sync token to be saved
#[no_mangle]
pub unsafe extern fn etebase_fs_cache_collection_save_stoken(this: &FileSystemCache, col_uid: *const c_char, stoken: *const c_char) -> i32 {
    let col_uid = CStr::from_ptr(col_uid).to_str().unwrap();
    let stoken = CStr::from_ptr(stoken).to_str().unwrap();
    try_or_int!(this.collection_save_stoken(col_uid, stoken));
    0
}

/// Load the sync token for a collection
///
/// @param this_ the object handle
/// @param col_uid the UID of the collection
#[no_mangle]
pub unsafe extern fn etebase_fs_cache_collection_load_stoken(this: &FileSystemCache, col_uid: *const c_char) -> *mut c_char {
    let col_uid = CStr::from_ptr(col_uid).to_str().unwrap();
    let stoken = try_or_null!(this.collection_load_stoken(col_uid));
    match stoken {
        Some(stoken) => try_or_null!(CString::new(stoken)).into_raw(),
        None => std::ptr::null_mut()
    }
}

/// Save a collection to cache
///
/// @param this_ the object handle
/// @param col_mgr collection manager for the account
/// @param col the collection to be saved
#[no_mangle]
pub unsafe extern fn etebase_fs_cache_collection_set(this: &FileSystemCache, col_mgr: &CollectionManager, col: &Collection) -> i32 {
    try_or_int!(this.collection_set(col_mgr, col));
    0
}

/// Remove a collection from cache
///
/// @param this_ the object handle
/// @param col_mgr collection manager for the account
/// @param col_uid the UID of the collection to remove
#[no_mangle]
pub unsafe extern fn etebase_fs_cache_collection_unset(this: &FileSystemCache, col_mgr: &CollectionManager, col_uid: *const c_char) -> i32 {
    let col_uid = CStr::from_ptr(col_uid).to_str().unwrap();
    try_or_int!(this.collection_unset(col_mgr, col_uid));
    0
}

/// Load a collection from cache
///
/// @param this_ the object handle
/// @param col_mgr collection manager for the account
/// @param col_uid the UID of the collection
#[no_mangle]
pub unsafe extern fn etebase_fs_cache_collection_get(this: &FileSystemCache, col_mgr: &CollectionManager, col_uid: *const c_char) -> *mut Collection {
    let col_uid = CStr::from_ptr(col_uid).to_str().unwrap();
    Box::into_raw(
        Box::new(
            try_or_null!(this.collection(col_mgr, col_uid))
        )
    )
}

/// Save an item to cache
///
/// @param this_ the object handle
/// @param item_mgr item manager for the parent collection
/// @param col_uid the UID of the parent collection
/// @param item the item to be saved
#[no_mangle]
pub unsafe extern fn etebase_fs_cache_item_set(this: &FileSystemCache, item_mgr: &ItemManager, col_uid: *const c_char, item: &Item) -> i32 {
    let col_uid = CStr::from_ptr(col_uid).to_str().unwrap();
    try_or_int!(this.item_set(item_mgr, col_uid, item));
    0
}

/// Remove an item from cache
///
/// @param this_ the object handle
/// @param item_mgr item manager for the parent collection
/// @param col_uid the UID of the parent collection
/// @param item_uid the UID of the item
#[no_mangle]
pub unsafe extern fn etebase_fs_cache_item_unset(this: &FileSystemCache, item_mgr: &ItemManager, col_uid: *const c_char, item_uid: *const c_char) -> i32 {
    let col_uid = CStr::from_ptr(col_uid).to_str().unwrap();
    let item_uid = CStr::from_ptr(item_uid).to_str().unwrap();
    try_or_int!(this.item_unset(item_mgr, col_uid, item_uid));
    0
}

/// Load an item from cache
///
/// @param this_ the object handle
/// @param item_mgr item manager for the parent collection
/// @param col_uid the UID of the parent collection
/// @param item_uid the UID of the item
#[no_mangle]
pub unsafe extern fn etebase_fs_cache_item_get(this: &FileSystemCache, item_mgr: &ItemManager, col_uid: *const c_char, item_uid: *const c_char) -> *mut Item {
    let col_uid = CStr::from_ptr(col_uid).to_str().unwrap();
    let item_uid = CStr::from_ptr(item_uid).to_str().unwrap();
    Box::into_raw(
        Box::new(
            try_or_null!(this.item(item_mgr, col_uid, item_uid))
        )
    )
}

/// Destroy the object
///
/// @param this_ the object handle
#[no_mangle]
pub unsafe extern fn etebase_fs_cache_destroy(this: *mut FileSystemCache) {
    let this = Box::from_raw(this);
    drop(this);
}

// }
