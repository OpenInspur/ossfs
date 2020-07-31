/*
 * ossfs - FUSE-based file system backed by InspurCloud OSS
 *
 * Copyright(C) 2007 Randy Rizun <rrizun@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#ifndef OSSFS_AUTH_H_
#define OSSFS_AUTH_H_

#include <string>
#include <sys/types.h>

//-------------------------------------------------------------------
// Utility functions for Authentication
//-------------------------------------------------------------------
//
// in common_auth.cpp
//
std::string ossfs_get_content_md5(int fd);
std::string ossfs_md5sum(int fd, off_t start, ssize_t size);
std::string ossfs_sha256sum(int fd, off_t start, ssize_t size);

//
// in xxxxxx_auth.cpp
//
const char* ossfs_crypt_lib_name(void);
bool ossfs_init_global_ssl(void);
bool ossfs_destroy_global_ssl(void);
bool ossfs_init_crypt_mutex(void);
bool ossfs_destroy_crypt_mutex(void);
bool ossfs_HMAC(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen);
bool ossfs_HMAC256(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen);
size_t get_md5_digest_length(void);
unsigned char* ossfs_md5hexsum(int fd, off_t start, ssize_t size);
bool ossfs_sha256(const unsigned char* data, unsigned int datalen, unsigned char** digest, unsigned int* digestlen);
size_t get_sha256_digest_length(void);
unsigned char* ossfs_sha256hexsum(int fd, off_t start, ssize_t size);

#endif // OSSFS_AUTH_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
