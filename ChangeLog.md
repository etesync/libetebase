# Changelog

## Version 0.5.8
* Update etebase dependency.

## Version 0.5.7
* [Fix regression] Allow passing null pointers for values that allow null.
* Update dependencies (`cargo update`)

## Version 0.5.6
* Update dependencies (`cargo update`)

## Version 0.5.5
* Update to the latest etebase-rs release

## Version 0.5.4
* Fix invitation reject to actually reject (and not accept)
* Fix wrong value for ETEBASE_UTILS_PRETTY_FINGERPRINT_SIZE
* Improve macOS support

## Version 0.5.3
* Update deps to their latest versions

## Version 0.5.2
* Update openssl deps to support more recent libopenssl vesrions

## Version 0.5.1
* Update to the latest etebase-rs release

## Version 0.5.0
* Document all of the API
* Add fetch_multi te fetch items by UIDs

## Version 0.4.1
* Build the release version by default

## Version 0.4.0
* Relicense to BSD-3-Clause
* Improve Makefile
* Set SONAME for the library on Unix-like systems

## Version 0.3.1
* Fix issue with custom urls lacking a trailing slash
* Update etebase dependency

## Version 0.3.0
* Login: automatically create the account if not init
* Have global and immutable collection types (changes the create and list APIs)
* Update etebase dependency

## Version 0.2.0
* Expose a function to fetch the dashboard url of an account
* Expose the FileSystemCache module for caching the data locally
* Expose a function te check whether it's an etebase server
* Update etebase dependency

## Version 0.1.4
* Invitations: expose from_username
* Update etebase dependency

## Version 0.1.3
* Collection stoken: fix fetching a collection's stoken
* Update etebase dependency

## Version 0.1.2
* Expose the access level as int rather than string
* Add Cmake configuration file
* Update etebase dependency

## Version 0.1.1
* Split the batch/transaction functions to with and without deps

## Version 0.1.0
* Initial release
