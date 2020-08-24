// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

#![allow(non_camel_case_types)]

use std::cell::RefCell;
use std::os::raw::{c_char, c_void};
use std::ffi::{CString, CStr};

use etebase::{
    API_URL,

    Client,
    User,
    Account,

    Collection,
    CollectionMetadata,
    Item,
    ItemMetadata,

    PrefetchOption,

    CollectionAccessLevel,
    SignedInvitation,
    CollectionMember,
    RemovedCollection,

    UserProfile,

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

#[no_mangle]
#[repr(u32)]
pub enum EtebaseErrorCode {
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

#[no_mangle]
pub extern fn etebase_error_get_code() -> EtebaseErrorCode {
    LAST_ERROR.with(|prev| {
        match *prev.borrow() {
            Some(ref err) => match err {
                Error::Generic(_) => EtebaseErrorCode::Generic,
                Error::UrlParse(_) => EtebaseErrorCode::UrlParse,
                Error::MsgPack(_) => EtebaseErrorCode::MsgPack,
                Error::ProgrammingError(_) => EtebaseErrorCode::ProgrammingError,
                Error::MissingContent(_) => EtebaseErrorCode::MissingContent,
                Error::Padding(_) => EtebaseErrorCode::Padding,
                Error::Base64(_) => EtebaseErrorCode::Base64,
                Error::Encryption(_) => EtebaseErrorCode::Encryption,
                Error::Unauthorized(_) => EtebaseErrorCode::Unauthorized,
                Error::Conflict(_) => EtebaseErrorCode::Conflict,
                Error::PermissionDenied(_) => EtebaseErrorCode::PermissionDenied,
                Error::NotFound(_) => EtebaseErrorCode::NotFound,

                Error::Connection(_) => EtebaseErrorCode::Connection,
                Error::TemporaryServerError(_) => EtebaseErrorCode::TemporaryServerError,
                Error::ServerError(_) => EtebaseErrorCode::ServerError,
                Error::Http(_) => EtebaseErrorCode::Http,
            },
            None => EtebaseErrorCode::NoError,
        }
    })
}

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

#[no_mangle]
pub extern fn etebase_get_default_server_url() -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(API_URL).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

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

#[no_mangle]
pub unsafe extern fn etebase_utils_randombytes(buf: *mut c_void, size: usize) -> i32 {
    let bytes = etebase::utils::randombytes(size);
    buf.copy_from_nonoverlapping(bytes.as_ptr() as *const c_void, size);
    0
}

#[no_mangle]
pub static ETEBASE_UTILS_PRETTY_FINGERPRINT_SIZE: usize =
    1 + // Null
    4 + // Newlines
    (3 * 12) + // Spacing
    (5 * 16); // Digits

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

#[no_mangle]
pub unsafe extern fn etebase_client_set_server_url(this: &mut Client, server_url: *const c_char) -> i32 {
    let server_url = CStr::from_ptr(server_url).to_str().unwrap();
    try_or_int!(this.set_server_url(server_url));
    0
}

#[no_mangle]
pub unsafe extern fn etebase_client_destroy(this: *mut Client) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class User {

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

#[no_mangle]
pub unsafe extern fn etebase_user_set_username(this: &mut User, username: *const c_char) {
    let username = CStr::from_ptr(username).to_str().unwrap();
    this.set_username(username);
}

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

#[no_mangle]
pub unsafe extern fn etebase_user_set_email(this: &mut User, email: *const c_char) {
    let email = CStr::from_ptr(email).to_str().unwrap();
    this.set_email(email);
}

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

#[no_mangle]
pub unsafe extern fn etebase_user_destroy(this: *mut User) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class Account {

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

#[no_mangle]
pub unsafe extern fn etebase_account_signup(client: &Client, user: &User, password: *const c_char) -> *mut Account {
    let password = CStr::from_ptr(password).to_str().unwrap();
    Box::into_raw(
        Box::new(
            try_or_null!(Account::signup(client.clone(), user, password))
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_account_fetch_token(this: &mut Account) -> i32 {
    try_or_int!(this.fetch_token());
    0
}

#[no_mangle]
pub unsafe extern fn etebase_account_force_server_url(this: &mut Account, server_url: *const c_char) -> i32 {
    let server_url = CStr::from_ptr(server_url).to_str().unwrap();
    try_or_int!(this.force_server_url(server_url));
    0
}

#[no_mangle]
pub unsafe extern fn etebase_account_change_password(this: &mut Account, password: *const c_char) -> i32 {
    let password = CStr::from_ptr(password).to_str().unwrap();
    try_or_int!(this.change_password(password));
    0
}

#[no_mangle]
pub unsafe extern fn etebase_account_logout(this: &mut Account) -> i32 {
    try_or_int!(this.logout());
    0
}

#[no_mangle]
pub unsafe extern fn etebase_account_get_collection_manager(this: &Account) -> *mut CollectionManager {
    Box::into_raw(
        Box::new(
            try_or_null!(this.collection_manager())
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_account_get_invitation_manager(this: &Account) -> *mut CollectionInvitationManager {
    Box::into_raw(
        Box::new(
            try_or_null!(this.invitation_manager())
        )
    )
}

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

#[no_mangle]
pub unsafe extern fn etebase_account_destroy(this: *mut Account) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class RemovedCollection {

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

#[no_mangle]
pub unsafe extern fn etebase_removed_collection_destroy(this: *mut RemovedCollection) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class CollectionListResponse {

type CollectionListResponse = etebase::CollectionListResponse<Collection>;

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

#[no_mangle]
pub unsafe extern fn etebase_collection_list_response_get_data(this: &CollectionListResponse, data: *mut *const Collection) -> i32 {
    let ret: Vec<&Collection> = this.data().iter().collect();
    data.copy_from_nonoverlapping(ret.as_ptr() as *mut *const Collection, ret.len());
    0
}

#[no_mangle]
pub unsafe extern fn etebase_collection_list_response_get_data_length(this: &CollectionListResponse) -> usize {
    this.data().len()
}

#[no_mangle]
pub unsafe extern fn etebase_collection_list_response_is_done(this: &CollectionListResponse) -> bool {
    this.done()
}

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

#[no_mangle]
pub unsafe extern fn etebase_collection_list_response_get_removed_memberships_length(this: &CollectionListResponse) -> usize {
    if let Some(removed_memberships) = this.removed_memberships() {
        removed_memberships.len()
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern fn etebase_collection_list_response_destroy(this: *mut CollectionListResponse) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class ItemListResponse {

type ItemListResponse = etebase::ItemListResponse<Item>;

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

#[no_mangle]
pub unsafe extern fn etebase_item_list_response_get_data(this: &ItemListResponse, data: *mut *const Item) -> i32 {
    let ret: Vec<&Item> = this.data().iter().collect();
    data.copy_from_nonoverlapping(ret.as_ptr() as *mut *const Item, ret.len());
    0
}

#[no_mangle]
pub unsafe extern fn etebase_item_list_response_get_data_length(this: &ItemListResponse) -> usize {
    this.data().len()
}

#[no_mangle]
pub unsafe extern fn etebase_item_list_response_is_done(this: &ItemListResponse) -> bool {
    this.done()
}

#[no_mangle]
pub unsafe extern fn etebase_item_list_response_destroy(this: *mut ItemListResponse) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class ItemRevisionsListResponse {

type ItemRevisionsListResponse = etebase::IteratorListResponse<Item>;

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

#[no_mangle]
pub unsafe extern fn etebase_item_revisions_list_response_get_data(this: &ItemRevisionsListResponse, data: *mut *const Item) -> i32 {
    let ret: Vec<&Item> = this.data().iter().collect();
    data.copy_from_nonoverlapping(ret.as_ptr() as *mut *const Item, ret.len());
    0
}

#[no_mangle]
pub unsafe extern fn etebase_item_revisions_list_response_get_data_length(this: &ItemRevisionsListResponse) -> usize {
    this.data().len()
}

#[no_mangle]
pub unsafe extern fn etebase_item_revisions_list_response_is_done(this: &ItemRevisionsListResponse) -> bool {
    this.done()
}

#[no_mangle]
pub unsafe extern fn etebase_item_revisions_list_response_destroy(this: *mut ItemRevisionsListResponse) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Enum PrefetchOption {

#[no_mangle]
#[repr(u32)]
pub enum EtebasePrefetchOption {
    Auto,
    Medium,
}

// }


// Class FetchOptions {

pub struct FetchOptions {
    limit: Option<usize>,
    stoken: Option<String>,
    iterator: Option<String>,
    prefetch: Option<PrefetchOption>,
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

    pub fn prefetch(&mut self, prefetch: EtebasePrefetchOption) {
        let prefetch = match prefetch {
            EtebasePrefetchOption::Auto => PrefetchOption::Auto,
            EtebasePrefetchOption::Medium => PrefetchOption::Medium,
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

#[no_mangle]
pub unsafe extern fn etebase_fetch_options_new() -> *mut FetchOptions {
    Box::into_raw(
        Box::new(
            FetchOptions::new()
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_fetch_options_set_limit(this: &mut FetchOptions, limit: usize) {
    this.limit(limit);
}

#[no_mangle]
pub unsafe extern fn etebase_fetch_options_set_prefetch(this: &mut FetchOptions, prefetch: EtebasePrefetchOption) {
    this.prefetch(prefetch);
}

#[no_mangle]
pub unsafe extern fn etebase_fetch_options_set_with_collection(this: &mut FetchOptions, with_collection: bool) {
    this.with_collection(with_collection);
}

#[no_mangle]
pub unsafe extern fn etebase_fetch_options_set_iterator(this: &mut FetchOptions, iterator: *const c_char) {
    let iterator = ptr_to_option(iterator).map(|x| CStr::from_ptr(x).to_str().unwrap());
    this.iterator(iterator);
}

#[no_mangle]
pub unsafe extern fn etebase_fetch_options_set_stoken(this: &mut FetchOptions, stoken: *const c_char) {
    let stoken = ptr_to_option(stoken).map(|x| CStr::from_ptr(x).to_str().unwrap());
    this.stoken(stoken);
}

#[no_mangle]
pub unsafe extern fn etebase_fetch_options_destroy(this: *mut FetchOptions) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class CollectionMetadata {

#[no_mangle]
pub unsafe extern fn etebase_collection_metadata_new(type_: *const c_char, name: *const c_char) -> *mut CollectionMetadata {
    let type_ = CStr::from_ptr(type_).to_str().unwrap();
    let name = CStr::from_ptr(name).to_str().unwrap();
    Box::into_raw(
        Box::new(
            CollectionMetadata::new(type_, name)
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_collection_metadata_set_collection_type(this: &mut CollectionMetadata, collection_type: *const c_char) {
    let collection_type = CStr::from_ptr(collection_type).to_str().unwrap();
    this.set_collection_type(collection_type);
}

#[no_mangle]
pub unsafe extern fn etebase_collection_metadata_get_collection_type(this: &CollectionMetadata) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(this.collection_type()).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

#[no_mangle]
pub unsafe extern fn etebase_collection_metadata_set_name(this: &mut CollectionMetadata, name: *const c_char) {
    let name = CStr::from_ptr(name).to_str().unwrap();
    this.set_name(name);
}

#[no_mangle]
pub unsafe extern fn etebase_collection_metadata_get_name(this: &CollectionMetadata) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(this.name()).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

#[no_mangle]
pub unsafe extern fn etebase_collection_metadata_set_description(this: &mut CollectionMetadata, description: *const c_char) {
    let description = ptr_to_option(description).map(|x| CStr::from_ptr(x).to_str().unwrap());
    this.set_description(description);
}

#[no_mangle]
pub unsafe extern fn etebase_collection_metadata_get_description(this: &CollectionMetadata) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = this.description().map(|x| CString::new(x).unwrap());
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

#[no_mangle]
pub unsafe extern fn etebase_collection_metadata_set_color(this: &mut CollectionMetadata, color: *const c_char) {
    let color = ptr_to_option(color).map(|x| CStr::from_ptr(x).to_str().unwrap());
    this.set_color(color);
}

#[no_mangle]
pub unsafe extern fn etebase_collection_metadata_get_color(this: &CollectionMetadata) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = this.color().map(|x| CString::new(x).unwrap());
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

#[no_mangle]
pub unsafe extern fn etebase_collection_metadata_set_mtime(this: &mut CollectionMetadata, mtime: *const i64) {
    let mtime = if mtime.is_null() {
        None
    } else {
        Some(*mtime)
    };
    this.set_mtime(mtime);
}

#[no_mangle]
pub unsafe extern fn etebase_collection_metadata_get_mtime(this: &CollectionMetadata) -> *const i64 {
    thread_local! {
        static LAST: RefCell<Option<i64>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = this.mtime();
        ret.borrow().as_ref().map(|x| x as *const i64).unwrap_or(std::ptr::null())
    })
}

#[no_mangle]
pub unsafe extern fn etebase_collection_metadata_destroy(this: *mut CollectionMetadata) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class ItemMetadata {

#[no_mangle]
pub unsafe extern fn etebase_item_metadata_new() -> *mut ItemMetadata {
    Box::into_raw(
        Box::new(
            ItemMetadata::new()
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_item_metadata_set_item_type(this: &mut ItemMetadata, item_type: *const c_char) {
    let item_type = ptr_to_option(item_type).map(|x| CStr::from_ptr(x).to_str().unwrap());
    this.set_item_type(item_type);
}

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

#[no_mangle]
pub unsafe extern fn etebase_item_metadata_set_name(this: &mut ItemMetadata, name: *const c_char) {
    let name = ptr_to_option(name).map(|x| CStr::from_ptr(x).to_str().unwrap());
    this.set_name(name);
}

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

#[no_mangle]
pub unsafe extern fn etebase_item_metadata_set_mtime(this: &mut ItemMetadata, mtime: *const i64) {
    let mtime = if mtime.is_null() {
        None
    } else {
        Some(*mtime)
    };
    this.set_mtime(mtime);
}

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

#[no_mangle]
pub unsafe extern fn etebase_item_metadata_destroy(this: *mut ItemMetadata) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class CollectionManager {

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

#[no_mangle]
pub unsafe extern fn etebase_collection_manager_create(this: &CollectionManager, meta: &CollectionMetadata, content: *const c_void, content_size: usize) -> *mut Collection {
    let content = std::slice::from_raw_parts(content as *const u8, content_size);
    Box::into_raw(
        Box::new(
            try_or_null!(this.create(meta, content))
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_collection_manager_create_raw(this: &CollectionManager, meta: *const c_void, meta_size: usize, content: *const c_void, content_size: usize) -> *mut Collection {
    let meta = std::slice::from_raw_parts(meta as *const u8, meta_size);
    let content = std::slice::from_raw_parts(content as *const u8, content_size);
    Box::into_raw(
        Box::new(
            try_or_null!(this.create_raw(meta, content))
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_collection_manager_get_item_manager(this: &CollectionManager, col: &Collection) -> *mut ItemManager {
    Box::into_raw(
        Box::new(
            try_or_null!(this.item_manager(col))
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_collection_manager_list(this: &CollectionManager, fetch_options: Option<&FetchOptions>) -> *mut CollectionListResponse {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    Box::into_raw(
        Box::new(
            try_or_null!(this.list(fetch_options.as_ref()))
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_collection_manager_upload(this: &CollectionManager, collection: &Collection, fetch_options: Option<&FetchOptions>) -> i32 {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    try_or_int!(this.upload(collection, fetch_options.as_ref()));
    0
}

#[no_mangle]
pub unsafe extern fn etebase_collection_manager_transaction(this: &CollectionManager, collection: &Collection, fetch_options: Option<&FetchOptions>) -> i32 {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    try_or_int!(this.transaction(collection, fetch_options.as_ref()));
    0
}

#[no_mangle]
pub unsafe extern fn etebase_collection_manager_cache_load(this: &CollectionManager, cached: *const c_void, cached_size: usize) -> *mut Collection {
    let cached = std::slice::from_raw_parts(cached as *const u8, cached_size);
    Box::into_raw(
        Box::new(
            try_or_null!(this.cache_load(cached))
        )
    )
}

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

#[no_mangle]
pub unsafe extern fn etebase_collection_manager_get_member_manager(this: &CollectionManager, col: &Collection) -> *mut CollectionMemberManager {
    Box::into_raw(
        Box::new(
            try_or_null!(this.member_manager(col))
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_collection_manager_destroy(this: *mut CollectionManager) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class ItemManager {

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

#[no_mangle]
pub unsafe extern fn etebase_item_manager_create(this: &ItemManager, meta: &ItemMetadata, content: *const c_void, content_size: usize) -> *mut Item {
    let content = std::slice::from_raw_parts(content as *const u8, content_size);
    Box::into_raw(
        Box::new(
            try_or_null!(this.create(meta, content))
        )
    )
}

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

#[no_mangle]
pub unsafe extern fn etebase_item_manager_list(this: &ItemManager, fetch_options: Option<&FetchOptions>) -> *mut ItemListResponse {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    Box::into_raw(
        Box::new(
            try_or_null!(this.list(fetch_options.as_ref()))
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_item_manager_item_revisions(this: &ItemManager, item: &Item, fetch_options: Option<&FetchOptions>) -> *mut ItemRevisionsListResponse {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    Box::into_raw(
        Box::new(
            try_or_null!(this.item_revisions(item, fetch_options.as_ref()))
        )
    )
}

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

#[no_mangle]
pub unsafe extern fn etebase_item_manager_batch(this: &ItemManager, items: *const &Item, items_size: usize, deps: *const &Item, deps_size: usize, fetch_options: Option<&FetchOptions>) -> i32 {
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

#[no_mangle]
pub unsafe extern fn etebase_item_manager_transaction(this: &ItemManager, items: *const &Item, items_size: usize, deps: *const &Item, deps_size: usize, fetch_options: Option<&FetchOptions>) -> i32 {
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

#[no_mangle]
pub unsafe extern fn etebase_item_manager_cache_load(this: &ItemManager, cached: *const c_void, cached_size: usize) -> *mut Item {
    let cached = std::slice::from_raw_parts(cached as *const u8, cached_size);
    Box::into_raw(
        Box::new(
            try_or_null!(this.cache_load(cached))
        )
    )
}

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

#[no_mangle]
pub unsafe extern fn etebase_item_manager_destroy(this: *mut ItemManager) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class Collection {

#[no_mangle]
pub unsafe extern fn etebase_collection_clone(this: &Collection) -> *mut Collection {
    Box::into_raw(
        Box::new(
            this.clone()
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_collection_verify(this: &Collection) -> bool {
    this.verify().unwrap_or(false)
}

#[no_mangle]
pub unsafe extern fn etebase_collection_set_meta(this: &mut Collection, meta: &CollectionMetadata) -> i32 {
    try_or_int!(this.set_meta(meta));
    0
}

#[no_mangle]
pub unsafe extern fn etebase_collection_get_meta(this: &Collection) -> *mut CollectionMetadata {
    Box::into_raw(
        Box::new(
            try_or_null!(this.meta())
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_collection_set_meta_raw(this: &mut Collection, meta: *const c_void, meta_size: usize) -> i32 {
    let meta = std::slice::from_raw_parts(meta as *const u8, meta_size);
    try_or_int!(this.set_meta_raw(meta));
    0
}

/// Returns the actual size of the buffer whether buf is NULL or not.
/// Writes at most buf_size to buf, and buf is *NOT* null terminated.
#[no_mangle]
pub unsafe extern fn etebase_collection_get_meta_raw(this: &Collection, buf: *mut c_void, buf_size: usize) -> isize {
    let ret = try_or_int!(this.meta_raw());
    let size = std::cmp::min(buf_size, ret.len());
    buf.copy_from_nonoverlapping(ret.as_ptr() as *const c_void, size);
    size as isize
}

#[no_mangle]
pub unsafe extern fn etebase_collection_set_content(this: &mut Collection, content: *const c_void, content_size: usize) -> i32 {
    let content = std::slice::from_raw_parts(content as *const u8, content_size);
    try_or_int!(this.set_content(content));
    0
}

/// Returns the actual size of the buffer whether buf is NULL or not.
/// Writes at most buf_size to buf, and buf is *NOT* null terminated.
#[no_mangle]
pub unsafe extern fn etebase_collection_get_content(this: &Collection, buf: *mut c_void, buf_size: usize) -> isize {
    let ret = try_or_int!(this.content());
    let size = std::cmp::min(buf_size, ret.len());
    buf.copy_from_nonoverlapping(ret.as_ptr() as *const c_void, size);
    size as isize
}

#[no_mangle]
pub unsafe extern fn etebase_collection_delete(this: &mut Collection) -> i32 {
    try_or_int!(this.delete());
    0
}

#[no_mangle]
pub unsafe extern fn etebase_collection_is_deleted(this: &Collection) -> bool {
    this.is_deleted()
}

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

#[no_mangle]
pub unsafe extern fn etebase_collection_get_stoken(this: &Collection) -> *const c_char {
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(this.etag()).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

#[no_mangle]
pub unsafe extern fn etebase_collection_as_item(this: &Collection) -> *mut Item {
    Box::into_raw(
        Box::new(
            try_or_null!(this.item())
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_collection_get_access_level(this: &Collection) -> *const c_char {
    let string = String::from(this.access_level());
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(&string[..]).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

#[no_mangle]
pub unsafe extern fn etebase_collection_destroy(this: *mut Collection) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class Item {

#[no_mangle]
pub unsafe extern fn etebase_item_clone(this: &Item) -> *mut Item {
    Box::into_raw(
        Box::new(
            this.clone()
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_item_verify(this: &Item) -> bool {
    this.verify().unwrap_or(false)
}

#[no_mangle]
pub unsafe extern fn etebase_item_set_meta(this: &mut Item, meta: &ItemMetadata) -> i32 {
    try_or_int!(this.set_meta(meta));
    0
}

#[no_mangle]
pub unsafe extern fn etebase_item_get_meta(this: &Item) -> *mut ItemMetadata {
    Box::into_raw(
        Box::new(
            try_or_null!(this.meta())
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_item_set_meta_raw(this: &mut Item, meta: *const c_void, meta_size: usize) -> i32 {
    let meta = std::slice::from_raw_parts(meta as *const u8, meta_size);
    try_or_int!(this.set_meta_raw(meta));
    0
}

/// Returns the actual size of the buffer whether buf is NULL or not.
/// Writes at most buf_size to buf, and buf is *NOT* null terminated.
#[no_mangle]
pub unsafe extern fn etebase_item_get_meta_raw(this: &Item, buf: *mut c_void, buf_size: usize) -> isize {
    let ret = try_or_int!(this.meta_raw());
    let size = std::cmp::min(buf_size, ret.len());
    buf.copy_from_nonoverlapping(ret.as_ptr() as *const c_void, size);
    size as isize
}


#[no_mangle]
pub unsafe extern fn etebase_item_set_content(this: &mut Item, content: *const c_void, content_size: usize) -> i32 {
    let content = std::slice::from_raw_parts(content as *const u8, content_size);
    try_or_int!(this.set_content(content));
    0
}

/// Returns the actual size of the buffer whether buf is NULL or not.
/// Writes at most buf_size to buf, and buf is *NOT* null terminated.
#[no_mangle]
pub unsafe extern fn etebase_item_get_content(this: &Item, buf: *mut c_void, buf_size: usize) -> isize {
    let ret = try_or_int!(this.content());
    let size = std::cmp::min(buf_size, ret.len());
    buf.copy_from_nonoverlapping(ret.as_ptr() as *const c_void, size);
    size as isize
}

#[no_mangle]
pub unsafe extern fn etebase_item_delete(this: &mut Item) -> i32 {
    try_or_int!(this.delete());
    0
}

#[no_mangle]
pub unsafe extern fn etebase_item_is_deleted(this: &Item) -> bool {
    this.is_deleted()
}

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

#[no_mangle]
pub unsafe extern fn etebase_item_destroy(this: *mut Item) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class UserProfile {

#[no_mangle]
pub unsafe extern fn etebase_user_profile_get_pubkey(this: &UserProfile) -> *const c_void {
    this.pubkey().as_ptr() as *const c_void
}

#[no_mangle]
pub unsafe extern fn etebase_user_profile_get_pubkey_size(this: &UserProfile) -> usize {
    this.pubkey().len()
}

#[no_mangle]
pub unsafe extern fn etebase_user_profile_destroy(this: *mut UserProfile) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// class InvitationListResponse {

type InvitationListResponse = etebase::IteratorListResponse<SignedInvitation>;

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

#[no_mangle]
pub unsafe extern fn etebase_invitation_list_response_get_data(this: &InvitationListResponse, data: *mut *const SignedInvitation) -> i32 {
    let ret: Vec<&SignedInvitation> = this.data().iter().collect();
    data.copy_from_nonoverlapping(ret.as_ptr() as *mut *const SignedInvitation, ret.len());
    0
}

#[no_mangle]
pub unsafe extern fn etebase_invitation_list_response_get_data_length(this: &InvitationListResponse) -> usize {
    this.data().len()
}

#[no_mangle]
pub unsafe extern fn etebase_invitation_list_response_is_done(this: &InvitationListResponse) -> bool {
    this.done()
}

#[no_mangle]
pub unsafe extern fn etebase_invitation_list_response_destroy(this: *mut InvitationListResponse) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class InvitationManager {

#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_list_incoming(this: &CollectionInvitationManager, fetch_options: Option<&FetchOptions>) -> *mut InvitationListResponse {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    Box::into_raw(
        Box::new(
            try_or_null!(this.list_incoming(fetch_options.as_ref()))
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_list_outgoing(this: &CollectionInvitationManager, fetch_options: Option<&FetchOptions>) -> *mut InvitationListResponse {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    Box::into_raw(
        Box::new(
            try_or_null!(this.list_outgoing(fetch_options.as_ref()))
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_accept(this: &CollectionInvitationManager, invitation: &SignedInvitation) -> i32 {
    try_or_int!(this.accept(invitation));
    0
}

#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_reject(this: &CollectionInvitationManager, invitation: &SignedInvitation) -> i32 {
    try_or_int!(this.accept(invitation));
    0
}

#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_fetch_user_profile(this: &CollectionInvitationManager, username: *const c_char) -> *mut UserProfile {
    let username = CStr::from_ptr(username).to_str().unwrap();
    Box::into_raw(
        Box::new(
            try_or_null!(this.fetch_user_profile(username))
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_invite(this: &CollectionInvitationManager, collection: &Collection, username: *const c_char, pubkey: *const c_void, pubkey_size: usize, access_level: *const c_char) -> i32 {
    let username = CStr::from_ptr(username).to_str().unwrap();
    let pubkey = std::slice::from_raw_parts(pubkey as *const u8, pubkey_size);
    let access_level = CollectionAccessLevel::from(CStr::from_ptr(access_level).to_str().unwrap());
    try_or_int!(this.invite(collection, username, pubkey, &access_level));
    0
}

#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_disinvite(this: &CollectionInvitationManager, invitation: &SignedInvitation) -> i32 {
    try_or_int!(this.disinvite(invitation));
    0
}

#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_get_pubkey(this: &CollectionInvitationManager) -> *const c_void {
    this.pubkey().as_ptr() as *const c_void
}

#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_get_pubkey_size(this: &CollectionInvitationManager) -> usize {
    this.pubkey().len()
}

#[no_mangle]
pub unsafe extern fn etebase_invitation_manager_destroy(this: *mut CollectionInvitationManager) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class SignedInvitation {

#[no_mangle]
pub unsafe extern fn etebase_signed_invitation_clone(this: &SignedInvitation) -> *mut SignedInvitation {
    Box::into_raw(
        Box::new(
            this.clone()
        )
    )
}

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

#[no_mangle]
pub unsafe extern fn etebase_signed_invitation_get_access_level(this: &SignedInvitation) -> *const c_char {
    let string = String::from(this.access_level());
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(&string[..]).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

#[no_mangle]
pub unsafe extern fn etebase_signed_invitation_get_from_pubkey(this: &SignedInvitation) -> *const c_void {
    this.from_pubkey().as_ptr() as *const c_void
}

#[no_mangle]
pub unsafe extern fn etebase_signed_invitation_get_from_pubkey_size(this: &SignedInvitation) -> usize {
    this.from_pubkey().len()
}

#[no_mangle]
pub unsafe extern fn etebase_signed_invitation_destroy(this: *mut SignedInvitation) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class CollectionMember {

#[no_mangle]
pub unsafe extern fn etebase_collection_member_clone(this: &CollectionMember) -> *mut CollectionMember {
    Box::into_raw(
        Box::new(
            this.clone()
        )
    )
}

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

#[no_mangle]
pub unsafe extern fn etebase_collection_member_get_access_level(this: &CollectionMember) -> *const c_char {
    let string = String::from(this.access_level());
    thread_local! {
        static LAST: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST.with(|ret| {
        *ret.borrow_mut() = CString::new(&string[..]).ok();
        ret.borrow().as_ref().map(|x| x.as_ptr()).unwrap_or(std::ptr::null())
    })
}

#[no_mangle]
pub unsafe extern fn etebase_collection_member_destroy(this: *mut CollectionMember) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class MemberListResponse {

type MemberListResponse = etebase::IteratorListResponse<CollectionMember>;

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

#[no_mangle]
pub unsafe extern fn etebase_member_list_response_get_data(this: &MemberListResponse, data: *mut *const CollectionMember) -> i32 {
    let ret: Vec<&CollectionMember> = this.data().iter().collect();
    data.copy_from_nonoverlapping(ret.as_ptr() as *mut *const CollectionMember, ret.len());
    0
}

#[no_mangle]
pub unsafe extern fn etebase_member_list_response_get_data_length(this: &MemberListResponse) -> usize {
    this.data().len()
}

#[no_mangle]
pub unsafe extern fn etebase_member_list_response_is_done(this: &MemberListResponse) -> bool {
    this.done()
}

#[no_mangle]
pub unsafe extern fn etebase_member_list_response_destroy(this: *mut MemberListResponse) {
    let this = Box::from_raw(this);
    drop(this);
}

// }


// Class CollectionMemberManager {

#[no_mangle]
pub unsafe extern fn etebase_collection_member_manager_list(this: &CollectionMemberManager, fetch_options: Option<&FetchOptions>) -> *mut MemberListResponse {
    let fetch_options = fetch_options.map(|x| x.to_fetch_options());
    Box::into_raw(
        Box::new(
            try_or_null!(this.list(fetch_options.as_ref()))
        )
    )
}

#[no_mangle]
pub unsafe extern fn etebase_collection_member_manager_remove(this: &CollectionMemberManager, username: *const c_char) -> i32 {
    let username = CStr::from_ptr(username).to_str().unwrap();
    try_or_int!(this.remove(username));
    0
}

#[no_mangle]
pub unsafe extern fn etebase_collection_member_manager_leave(this: &CollectionMemberManager) -> i32 {
    try_or_int!(this.leave());
    0
}

#[no_mangle]
pub unsafe extern fn etebase_collection_member_manager_modify_access_level(this: &CollectionMemberManager, username: *const c_char, access_level: *const c_char) -> i32 {
    let username = CStr::from_ptr(username).to_str().unwrap();
    let access_level = CollectionAccessLevel::from(CStr::from_ptr(access_level).to_str().unwrap());
    try_or_int!(this.modify_access_level(username, &access_level));
    0
}

#[no_mangle]
pub unsafe extern fn etebase_collection_member_manager_destroy(this: *mut CollectionMemberManager) {
    let this = Box::from_raw(this);
    drop(this);
}

// }
