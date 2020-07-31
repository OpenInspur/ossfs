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

#ifndef OSSFS_COMMON_H_
#define OSSFS_COMMON_H_

#include <stdlib.h>
#include "../config.h"

//
// Extended attribute
//
#ifdef HAVE_SYS_EXTATTR_H
#include <sys/extattr.h>
#elif HAVE_ATTR_XATTR_H
#include <attr/xattr.h>
#elif HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif

//
// Macro
//
static inline const char *SAFESTRPTR(const char *strptr) { return strptr ? strptr : ""; }

//
// Debug level
//
enum ossfs_log_level{
 OSSFS_LOG_CRIT = 0,          // LOG_CRIT
 OSSFS_LOG_ERR  = 1,          // LOG_ERR
 OSSFS_LOG_WARN = 3,          // LOG_WARNING
 OSSFS_LOG_INFO = 7,          // LOG_INFO
 OSSFS_LOG_DBG  = 15          // LOG_DEBUG
};

//
// Debug macros
//
#define IS_OSSFS_LOG_CRIT()   (OSSFS_LOG_CRIT == debug_level)
#define IS_OSSFS_LOG_ERR()    (OSSFS_LOG_ERR  == (debug_level & OSSFS_LOG_DBG))
#define IS_OSSFS_LOG_WARN()   (OSSFS_LOG_WARN == (debug_level & OSSFS_LOG_DBG))
#define IS_OSSFS_LOG_INFO()   (OSSFS_LOG_INFO == (debug_level & OSSFS_LOG_DBG))
#define IS_OSSFS_LOG_DBG()    (OSSFS_LOG_DBG  == (debug_level & OSSFS_LOG_DBG))

#define OSSFS_LOG_LEVEL_TO_SYSLOG(level) \
        ( OSSFS_LOG_DBG  == (level & OSSFS_LOG_DBG) ? LOG_DEBUG   : \
          OSSFS_LOG_INFO == (level & OSSFS_LOG_DBG) ? LOG_INFO    : \
          OSSFS_LOG_WARN == (level & OSSFS_LOG_DBG) ? LOG_WARNING : \
          OSSFS_LOG_ERR  == (level & OSSFS_LOG_DBG) ? LOG_ERR     : LOG_CRIT )

#define OSSFS_LOG_LEVEL_STRING(level) \
        ( OSSFS_LOG_DBG  == (level & OSSFS_LOG_DBG) ? "[DBG] " : \
          OSSFS_LOG_INFO == (level & OSSFS_LOG_DBG) ? "[INF] " : \
          OSSFS_LOG_WARN == (level & OSSFS_LOG_DBG) ? "[WAN] " : \
          OSSFS_LOG_ERR  == (level & OSSFS_LOG_DBG) ? "[ERR] " : "[CRT] " )

#define OSSFS_LOG_NEST_MAX    4
#define OSSFS_LOG_NEST(nest)  (nest < OSSFS_LOG_NEST_MAX ? ossfs_log_nest[nest] : ossfs_log_nest[OSSFS_LOG_NEST_MAX - 1])

#define OSSFS_LOW_LOGPRN(level, fmt, ...) \
       if(OSSFS_LOG_CRIT == level || (OSSFS_LOG_CRIT != debug_level && level == (debug_level & level))){ \
         if(foreground){ \
           fprintf(stdout, "%s%s:%s(%d): " fmt "%s\n", OSSFS_LOG_LEVEL_STRING(level), __FILE__, __func__, __LINE__, __VA_ARGS__); \
         }else{ \
           syslog(OSSFS_LOG_LEVEL_TO_SYSLOG(level), "%s%s:%s(%d): " fmt "%s", instance_name.c_str(), __FILE__, __func__, __LINE__, __VA_ARGS__); \
         } \
       }

#define OSSFS_LOW_LOGPRN2(level, nest, fmt, ...) \
       if(OSSFS_LOG_CRIT == level || (OSSFS_LOG_CRIT != debug_level && level == (debug_level & level))){ \
         if(foreground){ \
           fprintf(stdout, "%s%s%s:%s(%d): " fmt "%s\n", OSSFS_LOG_LEVEL_STRING(level), OSSFS_LOG_NEST(nest), __FILE__, __func__, __LINE__, __VA_ARGS__); \
         }else{ \
           syslog(OSSFS_LOG_LEVEL_TO_SYSLOG(level), "%s%s" fmt "%s", instance_name.c_str(), OSSFS_LOG_NEST(nest), __VA_ARGS__); \
         } \
       }

#define OSSFS_LOW_LOGPRN_EXIT(fmt, ...) \
       if(foreground){ \
         fprintf(stderr, "ossfs: " fmt "%s\n", __VA_ARGS__); \
       }else{ \
         fprintf(stderr, "ossfs: " fmt "%s\n", __VA_ARGS__); \
         syslog(OSSFS_LOG_LEVEL_TO_SYSLOG(OSSFS_LOG_CRIT), "%sossfs: " fmt "%s", instance_name.c_str(), __VA_ARGS__); \
       }

// Special macro for init message
#define OSSFS_PRN_INIT_INFO(fmt, ...) \
       if(foreground){ \
         fprintf(stdout, "%s%s%s:%s(%d): " fmt "%s\n", OSSFS_LOG_LEVEL_STRING(OSSFS_LOG_INFO), OSSFS_LOG_NEST(0), __FILE__, __func__, __LINE__, __VA_ARGS__, ""); \
       }else{ \
         syslog(OSSFS_LOG_LEVEL_TO_SYSLOG(OSSFS_LOG_INFO), "%s%s" fmt "%s", instance_name.c_str(), OSSFS_LOG_NEST(0), __VA_ARGS__, ""); \
       }

// [NOTE]
// small trick for VA_ARGS
//
#define OSSFS_PRN_EXIT(fmt, ...)   OSSFS_LOW_LOGPRN_EXIT(fmt, ##__VA_ARGS__, "")
#define OSSFS_PRN_CRIT(fmt, ...)   OSSFS_LOW_LOGPRN(OSSFS_LOG_CRIT, fmt, ##__VA_ARGS__, "")
#define OSSFS_PRN_ERR(fmt, ...)    OSSFS_LOW_LOGPRN(OSSFS_LOG_ERR,  fmt, ##__VA_ARGS__, "")
#define OSSFS_PRN_WARN(fmt, ...)   OSSFS_LOW_LOGPRN(OSSFS_LOG_WARN, fmt, ##__VA_ARGS__, "")
#define OSSFS_PRN_DBG(fmt, ...)    OSSFS_LOW_LOGPRN(OSSFS_LOG_DBG,  fmt, ##__VA_ARGS__, "")
#define OSSFS_PRN_INFO(fmt, ...)   OSSFS_LOW_LOGPRN2(OSSFS_LOG_INFO, 0, fmt, ##__VA_ARGS__, "")
#define OSSFS_PRN_INFO0(fmt, ...)  OSSFS_LOG_INFO(fmt, __VA_ARGS__)
#define OSSFS_PRN_INFO1(fmt, ...)  OSSFS_LOW_LOGPRN2(OSSFS_LOG_INFO, 1, fmt, ##__VA_ARGS__, "")
#define OSSFS_PRN_INFO2(fmt, ...)  OSSFS_LOW_LOGPRN2(OSSFS_LOG_INFO, 2, fmt, ##__VA_ARGS__, "")
#define OSSFS_PRN_INFO3(fmt, ...)  OSSFS_LOW_LOGPRN2(OSSFS_LOG_INFO, 3, fmt, ##__VA_ARGS__, "")
#define OSSFS_PRN_CURL(fmt, ...)   OSSFS_LOW_LOGPRN2(OSSFS_LOG_CRIT, 0, fmt, ##__VA_ARGS__, "")

//
// Typedef
//
struct header_nocase_cmp : public std::binary_function<std::string, std::string, bool>{
  bool operator()(const std::string &strleft, const std::string &strright) const
  {
    return (strcasecmp(strleft.c_str(), strright.c_str()) < 0);
  }
};
typedef std::map<std::string, std::string, header_nocase_cmp> headers_t;

//
// Header "x-oss-meta-xattr" is for extended attributes.
// This header is url encoded string which is json formatted.
//   x-oss-meta-xattr:urlencode({"xattr-1":"base64(value-1)","xattr-2":"base64(value-2)","xattr-3":"base64(value-3)"})
//
typedef struct xattr_value{
  unsigned char* pvalue;
  size_t         length;

  explicit xattr_value(unsigned char* pval = NULL, size_t len = 0) : pvalue(pval), length(len) {}
  ~xattr_value()
  {
    if(pvalue){
      free(pvalue);
    }
  }
}XATTRVAL, *PXATTRVAL;

typedef std::map<std::string, PXATTRVAL> xattrs_t;

//
// Global variables
//
// TODO: namespace these
extern bool           foreground;
extern bool           nomultipart;
extern bool           pathrequeststyle;
extern bool           complement_stat;
extern std::string    program_name;
extern std::string    service_path;
extern std::string    host;
extern std::string    bucket;
extern std::string    mount_prefix;
extern std::string    endpoint;
extern std::string    cipher_suites;
extern std::string    instance_name;
extern ossfs_log_level debug_level;
extern const char*    ossfs_log_nest[OSSFS_LOG_NEST_MAX];

#endif // OSSFS_COMMON_H_

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
