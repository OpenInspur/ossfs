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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>
#include <pthread.h>
#include <assert.h>
#include <curl/curl.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/tree.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <algorithm>
#include <list>
#include <vector>

#include "common.h"
#include "curl.h"
#include "string_util.h"
#include "ossfs.h"
#include "ossfs_util.h"
#include "ossfs_auth.h"
#include "addhead.h"
#include "psemaphore.h"

using namespace std;

static const std::string empty_payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

//-------------------------------------------------------------------
// Utilities
//-------------------------------------------------------------------
// [TODO]
// This function uses temporary file, but should not use it.
// For not using it, we implement function in each auth file(openssl, nss. gnutls).
//
static bool make_md5_from_string(const char* pstr, string& md5)
{
  if(!pstr || '\0' == pstr[0]){
    OSSFS_PRN_ERR("Parameter is wrong.");
    return false;
  }
  FILE* fp;
  if(NULL == (fp = tmpfile())){
    OSSFS_PRN_ERR("Could not make tmpfile.");
    return false;
  }
  size_t length = strlen(pstr);
  if(length != fwrite(pstr, sizeof(char), length, fp)){
    OSSFS_PRN_ERR("Failed to write tmpfile.");
    fclose(fp);
    return false;
  }
  int fd;
  if(0 != fflush(fp) || 0 != fseek(fp, 0L, SEEK_SET) || -1 == (fd = fileno(fp))){
    OSSFS_PRN_ERR("Failed to make MD5.");
    fclose(fp);
    return false;
  }
  // base64 md5
  md5 = ossfs_get_content_md5(fd);
  if(0 == md5.length()){
    OSSFS_PRN_ERR("Failed to make MD5.");
    fclose(fp);
    return false;
  }
  fclose(fp);
  return true;
}

static string url_to_host(const std::string &url)
{
  OSSFS_PRN_INFO3("url is %s", url.c_str());

  static const string http = "http://";
  static const string https = "https://";
  std::string hostname;

  if (url.compare(0, http.size(), http) == 0) {
    hostname = url.substr(http.size());
  } else if (url.compare(0, https.size(), https) == 0) {
    hostname = url.substr(https.size());
  } else {
    OSSFS_PRN_EXIT("url does not begin with http:// or https://");
    abort();
  }

  size_t idx;
  if ((idx = hostname.find('/')) != string::npos) {
    return hostname.substr(0, idx);
  } else {
    return hostname;
  }
}

static string get_bucket_host()
{
  if(!pathrequeststyle){
    return bucket + "." + url_to_host(host);
  }
  return url_to_host(host);
}

// compare ETag ignoring quotes
static bool etag_equals(std::string s1, std::string s2) {
  if(s1.length() > 1 && s1[0] == '\"' && s1[s1.length() - 1] == '\"'){
	s1 = s1.substr(1, s1.size() - 2);
  }
  if(s2.length() > 1 && s2[0] == '\"' && s2[s2.length() - 1] == '\"'){
	s2 = s2.substr(1, s2.size() - 2);
  }
  return s1 == s2;
}

#if 0 // noused
static string tolower_header_name(const char* head)
{
  string::size_type pos;
  string            name = head;
  string            value("");
  if(string::npos != (pos = name.find(':'))){
    value= name.substr(pos);
    name = name.substr(0, pos);
  }
  name = lower(name);
  name += value;
  return name;
}
#endif

//-------------------------------------------------------------------
// Class BodyData
//-------------------------------------------------------------------
static const int BODYDATA_RESIZE_APPEND_MIN = 1024;
static const int BODYDATA_RESIZE_APPEND_MID = 1024 * 1024;
static const int BODYDATA_RESIZE_APPEND_MAX = 10 * 1024 * 1024;

static size_t adjust_block(size_t bytes, size_t block) { return ((bytes / block) + ((bytes % block) ? 1 : 0)) * block; }

bool BodyData::Resize(size_t addbytes)
{
  if(IsSafeSize(addbytes)){
    return true;
  }

  // New size
  size_t need_size = adjust_block((lastpos + addbytes + 1) - bufsize, sizeof(off_t));

  if(BODYDATA_RESIZE_APPEND_MAX < bufsize){
    need_size = (BODYDATA_RESIZE_APPEND_MAX < need_size ? need_size : BODYDATA_RESIZE_APPEND_MAX);
  }else if(BODYDATA_RESIZE_APPEND_MID < bufsize){
    need_size = (BODYDATA_RESIZE_APPEND_MID < need_size ? need_size : BODYDATA_RESIZE_APPEND_MID);
  }else if(BODYDATA_RESIZE_APPEND_MIN < bufsize){
    need_size = ((bufsize * 2) < need_size ? need_size : (bufsize * 2));
  }else{
    need_size = (BODYDATA_RESIZE_APPEND_MIN < need_size ? need_size : BODYDATA_RESIZE_APPEND_MIN);
  }
  // realloc
  char* newtext;
  if(NULL == (newtext = (char*)realloc(text, (bufsize + need_size)))){
    OSSFS_PRN_CRIT("not enough memory (realloc returned NULL)");
    free(text);
    text = NULL;
    return false;
  }
  text     = newtext;
  bufsize += need_size;

  return true;
}

void BodyData::Clear()
{
  if(text){
    free(text);
    text = NULL;
  }
  lastpos = 0;
  bufsize = 0;
}

bool BodyData::Append(void* ptr, size_t bytes)
{
  if(!ptr){
    return false;
  }
  if(0 == bytes){
    return true;
  }
  if(!Resize(bytes)){
    return false;
  }
  memcpy(&text[lastpos], ptr, bytes);
  lastpos += bytes;
  text[lastpos] = '\0';

  return true;
}

const char* BodyData::str() const
{
  if(!text){
    static const char* strnull = "";
    return strnull;
  }
  return text;
}

//-------------------------------------------------------------------
// Class CurlHandlerPool
//-------------------------------------------------------------------
bool CurlHandlerPool::Init()
{
  if (0 != pthread_mutex_init(&mLock, NULL)) {
    OSSFS_PRN_ERR("Init curl handlers lock failed");
    return false;
  }

  for(int cnt = 0; cnt < mMaxHandlers; ++cnt){
    CURL* hCurl = curl_easy_init();
    if(!hCurl){
      OSSFS_PRN_ERR("Init curl handlers pool failed");
      Destroy();
      return false;
    }
    mPool.push_back(hCurl);
  }

  return true;
}

bool CurlHandlerPool::Destroy()
{
  while(!mPool.empty()){
    CURL* hCurl = mPool.back();
    mPool.pop_back();
    if(hCurl){
      curl_easy_cleanup(hCurl);
    }
  }
  if (0 != pthread_mutex_destroy(&mLock)) {
    OSSFS_PRN_ERR("Destroy curl handlers lock failed");
    return false;
  }

  return true;
}

CURL* CurlHandlerPool::GetHandler(bool only_pool)
{
  CURL* hCurl = NULL;
  {
    AutoLock lock(&mLock);

    if(!mPool.empty()){
      hCurl = mPool.back();
      mPool.pop_back();
      OSSFS_PRN_DBG("Get handler from pool: rest = %d", static_cast<int>(mPool.size()));
    }
  }
  if(only_pool){
    return hCurl;
  }
  if(!hCurl){
    OSSFS_PRN_INFO("Pool empty: force to create new handler");
    hCurl = curl_easy_init();
  }
  return hCurl;
}

void CurlHandlerPool::ReturnHandler(CURL* hCurl, bool restore_pool)
{
  if(!hCurl){
    return;
  }

  if(restore_pool){
    AutoLock lock(&mLock);

    OSSFS_PRN_DBG("Return handler to pool");
    mPool.push_back(hCurl);

    while(mMaxHandlers <= static_cast<int>(mPool.size())){
      CURL* hOldCurl = mPool.front();
      mPool.pop_front();
      if(hOldCurl){
        OSSFS_PRN_INFO("Pool full: destroy the oldest handler");
        curl_easy_cleanup(hOldCurl);
      }
    }
  }else{
    OSSFS_PRN_INFO("Pool full: destroy the handler");
    curl_easy_cleanup(hCurl);
  }
}

//-------------------------------------------------------------------
// Class OSSfsCurl
//-------------------------------------------------------------------
static const int MULTIPART_SIZE = 10 * 1024 * 1024;
// constant must be at least 512 MB to copy the maximum 5 TB object size
// TODO: scale part size with object size
static const int MAX_MULTI_COPY_SOURCE_SIZE = 512 * 1024 * 1024;

static const int IAM_EXPIRE_MERGIN = 20 * 60;  // update timing
static const std::string ECS_IAM_ENV_VAR = "OSS_CONTAINER_CREDENTIALS_RELATIVE_URI";
static const std::string IAMCRED_ACCESSKEYID = "AccessKeyId";
static const std::string IAMCRED_SECRETACCESSKEY = "SecretAccessKey";
static const std::string IAMCRED_ROLEARN = "RoleArn";

// [NOTICE]
// This symbol is for libcurl under 7.23.0
#ifndef CURLSHE_NOT_BUILT_IN
#define CURLSHE_NOT_BUILT_IN        5
#endif

pthread_mutex_t  OSSfsCurl::curl_handles_lock;
pthread_mutex_t  OSSfsCurl::curl_share_lock[SHARE_MUTEX_MAX];
bool             OSSfsCurl::is_initglobal_done  = false;
CurlHandlerPool* OSSfsCurl::sCurlPool           = NULL;
int              OSSfsCurl::sCurlPoolSize       = 32;
CURLSH*          OSSfsCurl::hCurlShare          = NULL;
bool             OSSfsCurl::is_cert_check       = true; // default
bool             OSSfsCurl::is_dns_cache        = true; // default
bool             OSSfsCurl::is_ssl_session_cache= true; // default
long             OSSfsCurl::connect_timeout     = 300;  // default
time_t           OSSfsCurl::readwrite_timeout   = 60;   // default
int              OSSfsCurl::retries             = 5;    // default
bool             OSSfsCurl::is_public_bucket    = false;
string           OSSfsCurl::default_acl         = "private";
storage_class_t  OSSfsCurl::storage_class       = STANDARD;
sseckeylist_t    OSSfsCurl::sseckeys;
std::string      OSSfsCurl::ssekmsid;
sse_type_t       OSSfsCurl::ssetype             = SSE_DISABLE;
bool             OSSfsCurl::is_content_md5      = false;
bool             OSSfsCurl::is_verbose          = false;
string           OSSfsCurl::OSSAccessKeyId;
string           OSSfsCurl::OSSSecretAccessKey;
string           OSSfsCurl::OSSAccessToken;
time_t           OSSfsCurl::OSSAccessTokenExpire= 0;
bool             OSSfsCurl::is_ecs              = false;
bool             OSSfsCurl::is_ibm_iam_auth     = false;
string           OSSfsCurl::IAM_cred_url        = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
size_t           OSSfsCurl::IAM_field_count     = 4;
string           OSSfsCurl::IAM_token_field     = "Token";
string           OSSfsCurl::IAM_expiry_field    = "Expiration";
string           OSSfsCurl::IAM_role;
long             OSSfsCurl::ssl_verify_hostname = 1;    // default(original code...)
curltime_t       OSSfsCurl::curl_times;
curlprogress_t   OSSfsCurl::curl_progress;
string           OSSfsCurl::curl_ca_bundle;
mimes_t          OSSfsCurl::mimeTypes;
string           OSSfsCurl::userAgent;
int              OSSfsCurl::max_parallel_cnt    = 5;              // default
int              OSSfsCurl::max_multireq        = 20;             // default
off_t            OSSfsCurl::multipart_size      = MULTIPART_SIZE; // default
bool             OSSfsCurl::is_sigv4            = false;          // default
bool             OSSfsCurl::is_ua               = true;           // default

//-------------------------------------------------------------------
// Class methods for OSSfsCurl
//-------------------------------------------------------------------
bool OSSfsCurl::InitOSSfsCurl(const char* MimeFile)
{
  if(0 != pthread_mutex_init(&OSSfsCurl::curl_handles_lock, NULL)){
    return false;
  }
  if(0 != pthread_mutex_init(&OSSfsCurl::curl_share_lock[SHARE_MUTEX_DNS], NULL)){
    return false;
  }
  if(0 != pthread_mutex_init(&OSSfsCurl::curl_share_lock[SHARE_MUTEX_SSL_SESSION], NULL)){
    return false;
  }
  if(!OSSfsCurl::InitMimeType(MimeFile)){
    return false;
  }
  if(!OSSfsCurl::InitGlobalCurl()){
    return false;
  }
  if(!OSSfsCurl::InitShareCurl()){
    return false;
  }
  if(!OSSfsCurl::InitCryptMutex()){
    return false;
  }
  // [NOTE]
  // sCurlPoolSize must be over parrallel(or multireq) count.
  //
  if(sCurlPoolSize < std::max(GetMaxParallelCount(), GetMaxMultiRequest())){
    sCurlPoolSize = std::max(GetMaxParallelCount(), GetMaxMultiRequest());
  }
  sCurlPool = new CurlHandlerPool(sCurlPoolSize);
  if (!sCurlPool->Init()) {
    return false;
  }
  return true;
}

bool OSSfsCurl::DestroyOSSfsCurl()
{
  int result = true;

  if(!OSSfsCurl::DestroyCryptMutex()){
    result = false;
  }
  if(!sCurlPool->Destroy()){
    result = false;
  }
  delete sCurlPool;
  sCurlPool = NULL;
  if(!OSSfsCurl::DestroyShareCurl()){
    result = false;
  }
  if(!OSSfsCurl::DestroyGlobalCurl()){
    result = false;
  }
  if(0 != pthread_mutex_destroy(&OSSfsCurl::curl_share_lock[SHARE_MUTEX_DNS])){
    result = false;
  }
  if(0 != pthread_mutex_destroy(&OSSfsCurl::curl_share_lock[SHARE_MUTEX_SSL_SESSION])){
    result = false;
  }
  if(0 != pthread_mutex_destroy(&OSSfsCurl::curl_handles_lock)){
    result = false;
  }
  return result;
}

bool OSSfsCurl::InitGlobalCurl()
{
  if(OSSfsCurl::is_initglobal_done){
    return false;
  }
  if(CURLE_OK != curl_global_init(CURL_GLOBAL_ALL)){
    OSSFS_PRN_ERR("init_curl_global_all returns error.");
    return false;
  }
  OSSfsCurl::is_initglobal_done = true;
  return true;
}

bool OSSfsCurl::DestroyGlobalCurl()
{
  if(!OSSfsCurl::is_initglobal_done){
    return false;
  }
  curl_global_cleanup();
  OSSfsCurl::is_initglobal_done = false;
  return true;
}

bool OSSfsCurl::InitShareCurl()
{
  CURLSHcode nSHCode;

  if(!OSSfsCurl::is_dns_cache && !OSSfsCurl::is_ssl_session_cache){
    OSSFS_PRN_INFO("Curl does not share DNS data.");
    return true;
  }
  if(OSSfsCurl::hCurlShare){
    OSSFS_PRN_WARN("already initiated.");
    return false;
  }
  if(NULL == (OSSfsCurl::hCurlShare = curl_share_init())){
    OSSFS_PRN_ERR("curl_share_init failed");
    return false;
  }
  if(CURLSHE_OK != (nSHCode = curl_share_setopt(OSSfsCurl::hCurlShare, CURLSHOPT_LOCKFUNC, OSSfsCurl::LockCurlShare))){
    OSSFS_PRN_ERR("curl_share_setopt(LOCKFUNC) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
    return false;
  }
  if(CURLSHE_OK != (nSHCode = curl_share_setopt(OSSfsCurl::hCurlShare, CURLSHOPT_UNLOCKFUNC, OSSfsCurl::UnlockCurlShare))){
    OSSFS_PRN_ERR("curl_share_setopt(UNLOCKFUNC) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
    return false;
  }
  if(OSSfsCurl::is_dns_cache){
    nSHCode = curl_share_setopt(OSSfsCurl::hCurlShare, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
    if(CURLSHE_OK != nSHCode && CURLSHE_BAD_OPTION != nSHCode && CURLSHE_NOT_BUILT_IN != nSHCode){
      OSSFS_PRN_ERR("curl_share_setopt(DNS) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
      return false;
    }else if(CURLSHE_BAD_OPTION == nSHCode || CURLSHE_NOT_BUILT_IN == nSHCode){
      OSSFS_PRN_WARN("curl_share_setopt(DNS) returns %d(%s), but continue without shared dns data.", nSHCode, curl_share_strerror(nSHCode));
    }
  }
  if(OSSfsCurl::is_ssl_session_cache){
    nSHCode = curl_share_setopt(OSSfsCurl::hCurlShare, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
    if(CURLSHE_OK != nSHCode && CURLSHE_BAD_OPTION != nSHCode && CURLSHE_NOT_BUILT_IN != nSHCode){
      OSSFS_PRN_ERR("curl_share_setopt(SSL SESSION) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
      return false;
    }else if(CURLSHE_BAD_OPTION == nSHCode || CURLSHE_NOT_BUILT_IN == nSHCode){
      OSSFS_PRN_WARN("curl_share_setopt(SSL SESSION) returns %d(%s), but continue without shared ssl session data.", nSHCode, curl_share_strerror(nSHCode));
    }
  }
  if(CURLSHE_OK != (nSHCode = curl_share_setopt(OSSfsCurl::hCurlShare, CURLSHOPT_USERDATA, (void*)&OSSfsCurl::curl_share_lock[0]))){
    OSSFS_PRN_ERR("curl_share_setopt(USERDATA) returns %d(%s)", nSHCode, curl_share_strerror(nSHCode));
    return false;
  }
  return true;
}

bool OSSfsCurl::DestroyShareCurl()
{
  if(!OSSfsCurl::hCurlShare){
    if(!OSSfsCurl::is_dns_cache && !OSSfsCurl::is_ssl_session_cache){
      return true;
    }
    OSSFS_PRN_WARN("already destroy share curl.");
    return false;
  }
  if(CURLSHE_OK != curl_share_cleanup(OSSfsCurl::hCurlShare)){
    return false;
  }
  OSSfsCurl::hCurlShare = NULL;
  return true;
}

void OSSfsCurl::LockCurlShare(CURL* handle, curl_lock_data nLockData, curl_lock_access laccess, void* useptr)
{
  if(!hCurlShare){
    return;
  }
  pthread_mutex_t* lockmutex = static_cast<pthread_mutex_t*>(useptr);
  if(CURL_LOCK_DATA_DNS == nLockData){
    pthread_mutex_lock(&lockmutex[SHARE_MUTEX_DNS]);
  }else if(CURL_LOCK_DATA_SSL_SESSION == nLockData){
    pthread_mutex_lock(&lockmutex[SHARE_MUTEX_SSL_SESSION]);
  }
}

void OSSfsCurl::UnlockCurlShare(CURL* handle, curl_lock_data nLockData, void* useptr)
{
  if(!hCurlShare){
    return;
  }
  pthread_mutex_t* lockmutex = static_cast<pthread_mutex_t*>(useptr);
  if(CURL_LOCK_DATA_DNS == nLockData){
    pthread_mutex_unlock(&lockmutex[SHARE_MUTEX_DNS]);
  }else if(CURL_LOCK_DATA_SSL_SESSION == nLockData){
    pthread_mutex_unlock(&lockmutex[SHARE_MUTEX_SSL_SESSION]);
  }
}

bool OSSfsCurl::InitCryptMutex()
{
  return ossfs_init_crypt_mutex();
}

bool OSSfsCurl::DestroyCryptMutex()
{
  return ossfs_destroy_crypt_mutex();
}

// homegrown timeout mechanism
int OSSfsCurl::CurlProgress(void *clientp, double dltotal, double dlnow, double ultotal, double ulnow)
{
  CURL* curl = static_cast<CURL*>(clientp);
  time_t now = time(0);
  progress_t p(dlnow, ulnow);

  AutoLock lock(&OSSfsCurl::curl_handles_lock);

  // any progress?
  if(p != OSSfsCurl::curl_progress[curl]){
    // yes!
    OSSfsCurl::curl_times[curl]    = now;
    OSSfsCurl::curl_progress[curl] = p;
  }else{
    // timeout?
    if(now - OSSfsCurl::curl_times[curl] > readwrite_timeout){
      OSSFS_PRN_ERR("timeout now: %jd, curl_times[curl]: %jd, readwrite_timeout: %jd",
                      (intmax_t)now, (intmax_t)(OSSfsCurl::curl_times[curl]), (intmax_t)readwrite_timeout);
      return CURLE_ABORTED_BY_CALLBACK;
    }
  }

  return 0;
}

bool OSSfsCurl::InitMimeType(const char* MimeFile)
{
  if(!MimeFile){
    MimeFile = "/etc/mime.types";  // default
  }

  string line;
  ifstream MT(MimeFile);
  if(MT.good()){
    while(getline(MT, line)){
      if(line[0]=='#'){
        continue;
      }
      if(line.empty()){
        continue;
      }

      istringstream tmp(line);
      string mimeType;
      tmp >> mimeType;
      while(tmp){
        string ext;
        tmp >> ext;
        if(ext.empty()){
          continue;
        }
        OSSfsCurl::mimeTypes[ext] = mimeType;
      }
    }
  }
  return true;
}

void OSSfsCurl::InitUserAgent()
{
  if(OSSfsCurl::userAgent.empty()){
    OSSfsCurl::userAgent =  "ossfs/";
    OSSfsCurl::userAgent += VERSION;
    OSSfsCurl::userAgent += " (commit hash ";
    OSSfsCurl::userAgent += COMMIT_HASH_VAL;
    OSSfsCurl::userAgent += "; ";
    OSSfsCurl::userAgent += ossfs_crypt_lib_name();
    OSSfsCurl::userAgent += ")";
    OSSfsCurl::userAgent += instance_name;
  }
}

//
// @param s e.g., "index.html"
// @return e.g., "text/html"
//
string OSSfsCurl::LookupMimeType(const string& name)
{
  string result("application/octet-stream");
  string::size_type last_pos = name.find_last_of('.');
  string::size_type first_pos = name.find_first_of('.');
  string prefix, ext, ext2;

  // No dots in name, just return
  if(last_pos == string::npos){
    return result;
  }
  // extract the last extension
  ext = name.substr(1+last_pos, string::npos);

  if (last_pos != string::npos) {
     // one dot was found, now look for another
     if (first_pos != string::npos && first_pos < last_pos) {
        prefix = name.substr(0, last_pos);
        // Now get the second to last file extension
        string::size_type next_pos = prefix.find_last_of('.');
        if (next_pos != string::npos) {
           ext2 = prefix.substr(1+next_pos, string::npos);
        }
     }
  }

  // if we get here, then we have an extension (ext)
  mimes_t::const_iterator iter = OSSfsCurl::mimeTypes.find(ext);
  // if the last extension matches a mimeType, then return
  // that mime type
  if (iter != OSSfsCurl::mimeTypes.end()) {
    result = (*iter).second;
    return result;
  }

  // return with the default result if there isn't a second extension
  if(first_pos == last_pos){
     return result;
  }

  // Didn't find a mime-type for the first extension
  // Look for second extension in mimeTypes, return if found
  iter = OSSfsCurl::mimeTypes.find(ext2);
  if (iter != OSSfsCurl::mimeTypes.end()) {
     result = (*iter).second;
     return result;
  }

  // neither the last extension nor the second-to-last extension
  // matched a mimeType, return the default mime type 
  return result;
}

bool OSSfsCurl::LocateBundle()
{
  // See if environment variable CURL_CA_BUNDLE is set
  // if so, check it, if it is a good path, then set the
  // curl_ca_bundle variable to it
  if(OSSfsCurl::curl_ca_bundle.empty()){
    char* CURL_CA_BUNDLE = getenv("CURL_CA_BUNDLE");
    if(CURL_CA_BUNDLE != NULL)  {
      // check for existence and readability of the file
      ifstream BF(CURL_CA_BUNDLE);
      if(!BF.good()){
        OSSFS_PRN_ERR("%s: file specified by CURL_CA_BUNDLE environment variable is not readable", program_name.c_str());
        return false;
      }
      BF.close();
      OSSfsCurl::curl_ca_bundle.assign(CURL_CA_BUNDLE); 
      return true;
    }
  }else{
    // Already set ca bundle variable
    return true;
  }

  // not set via environment variable, look in likely locations

  ///////////////////////////////////////////
  // following comment from curl's (7.21.2) acinclude.m4 file
  ///////////////////////////////////////////
  // dnl CURL_CHECK_CA_BUNDLE
  // dnl -------------------------------------------------
  // dnl Check if a default ca-bundle should be used
  // dnl
  // dnl regarding the paths this will scan:
  // dnl /etc/ssl/certs/ca-certificates.crt Debian systems
  // dnl /etc/pki/tls/certs/ca-bundle.crt Redhat and Mandriva
  // dnl /usr/share/ssl/certs/ca-bundle.crt old(er) Redhat
  // dnl /usr/local/share/certs/ca-root.crt FreeBSD
  // dnl /etc/ssl/cert.pem OpenBSD
  // dnl /etc/ssl/certs/ (ca path) SUSE
  ///////////////////////////////////////////
  // Within CURL the above path should have been checked
  // according to the OS. Thus, although we do not need
  // to check files here, we will only examine some files.
  //
  ifstream BF("/etc/pki/tls/certs/ca-bundle.crt"); 
  if(BF.good()){
    BF.close();
    OSSfsCurl::curl_ca_bundle.assign("/etc/pki/tls/certs/ca-bundle.crt"); 
  }else{
    BF.open("/etc/ssl/certs/ca-certificates.crt");
    if(BF.good()){
      BF.close();
      OSSfsCurl::curl_ca_bundle.assign("/etc/ssl/certs/ca-certificates.crt");
    }else{
      BF.open("/usr/share/ssl/certs/ca-bundle.crt");
      if(BF.good()){
        BF.close();
        OSSfsCurl::curl_ca_bundle.assign("/usr/share/ssl/certs/ca-bundle.crt");
      }else{
        BF.open("/usr/local/share/certs/ca-root.crt");
        if(BF.good()){
          BF.close();
          OSSfsCurl::curl_ca_bundle.assign("/usr/share/ssl/certs/ca-bundle.crt");
        }else{
          OSSFS_PRN_ERR("%s: /.../ca-bundle.crt is not readable", program_name.c_str());
          return false;
        }
      }
    }
  }
  return true;
}

size_t OSSfsCurl::WriteMemoryCallback(void* ptr, size_t blockSize, size_t numBlocks, void* data)
{
  BodyData* body  = static_cast<BodyData*>(data);

  if(!body->Append(ptr, blockSize, numBlocks)){
    OSSFS_PRN_CRIT("BodyData.Append() returned false.");
    OSSFS_FUSE_EXIT();
    return -1;
  }
  return (blockSize * numBlocks);
}

size_t OSSfsCurl::ReadCallback(void* ptr, size_t size, size_t nmemb, void* userp)
{
  OSSfsCurl* pCurl = reinterpret_cast<OSSfsCurl*>(userp);

  if(1 > (size * nmemb)){
    return 0;
  }
  if(0 >= pCurl->postdata_remaining){
    return 0;
  }
  int copysize = std::min((int)(size * nmemb), pCurl->postdata_remaining);
  memcpy(ptr, pCurl->postdata, copysize);

  pCurl->postdata_remaining = (pCurl->postdata_remaining > copysize ? (pCurl->postdata_remaining - copysize) : 0);
  pCurl->postdata          += static_cast<size_t>(copysize);

  return copysize;
}

size_t OSSfsCurl::HeaderCallback(void* data, size_t blockSize, size_t numBlocks, void* userPtr)
{
  headers_t* headers = reinterpret_cast<headers_t*>(userPtr);
  string header(reinterpret_cast<char*>(data), blockSize * numBlocks);
  string key;
  istringstream ss(header);

  if(getline(ss, key, ':')){
    // Force to lower, only "x-oss"
    string lkey = key;
    transform(lkey.begin(), lkey.end(), lkey.begin(), static_cast<int (*)(int)>(std::tolower));
    if(lkey.compare(0, 5, "x-oss") == 0){
      key = lkey;
    }
    string value;
    getline(ss, value);
    (*headers)[key] = trim(value);
  }
  return blockSize * numBlocks;
}

size_t OSSfsCurl::UploadReadCallback(void* ptr, size_t size, size_t nmemb, void* userp)
{
  OSSfsCurl* pCurl = reinterpret_cast<OSSfsCurl*>(userp);

  if(1 > (size * nmemb)){
    return 0;
  }
  if(-1 == pCurl->partdata.fd || 0 >= pCurl->partdata.size){
    return 0;
  }
  // read size
  ssize_t copysize = (size * nmemb) < (size_t)pCurl->partdata.size ? (size * nmemb) : (size_t)pCurl->partdata.size;
  ssize_t readbytes;
  ssize_t totalread;
  // read and set
  for(totalread = 0, readbytes = 0; totalread < copysize; totalread += readbytes){
    readbytes = pread(pCurl->partdata.fd, &((char*)ptr)[totalread], (copysize - totalread), pCurl->partdata.startpos + totalread);
    if(0 == readbytes){
      // eof
      break;
    }else if(-1 == readbytes){
      // error
      OSSFS_PRN_ERR("read file error(%d).", errno);
      return 0;
    }
  }
  pCurl->partdata.startpos += totalread;
  pCurl->partdata.size     -= totalread;

  return totalread;
}

size_t OSSfsCurl::DownloadWriteCallback(void* ptr, size_t size, size_t nmemb, void* userp)
{
  OSSfsCurl* pCurl = reinterpret_cast<OSSfsCurl*>(userp);

  if(1 > (size * nmemb)){
    return 0;
  }
  if(-1 == pCurl->partdata.fd || 0 >= pCurl->partdata.size){
    return 0;
  }

  // write size
  ssize_t copysize = (size * nmemb) < (size_t)pCurl->partdata.size ? (size * nmemb) : (size_t)pCurl->partdata.size;
  ssize_t writebytes;
  ssize_t totalwrite;

  // write
  for(totalwrite = 0, writebytes = 0; totalwrite < copysize; totalwrite += writebytes){
    writebytes = pwrite(pCurl->partdata.fd, &((char*)ptr)[totalwrite], (copysize - totalwrite), pCurl->partdata.startpos + totalwrite);
    if(0 == writebytes){
      // eof?
      break;
    }else if(-1 == writebytes){
      // error
      OSSFS_PRN_ERR("write file error(%d).", errno);
      return 0;
    }
  }
  pCurl->partdata.startpos += totalwrite;
  pCurl->partdata.size     -= totalwrite;

  return totalwrite;
}

bool OSSfsCurl::SetCheckCertificate(bool isCertCheck) {
    bool old = OSSfsCurl::is_cert_check;
    OSSfsCurl::is_cert_check = isCertCheck;
    return old;
}

bool OSSfsCurl::SetDnsCache(bool isCache)
{
  bool old = OSSfsCurl::is_dns_cache;
  OSSfsCurl::is_dns_cache = isCache;
  return old;
}

bool OSSfsCurl::SetSslSessionCache(bool isCache)
{
  bool old = OSSfsCurl::is_ssl_session_cache;
  OSSfsCurl::is_ssl_session_cache = isCache;
  return old;
}

long OSSfsCurl::SetConnectTimeout(long timeout)
{
  long old = OSSfsCurl::connect_timeout;
  OSSfsCurl::connect_timeout = timeout;
  return old;
}

time_t OSSfsCurl::SetReadwriteTimeout(time_t timeout)
{
  time_t old = OSSfsCurl::readwrite_timeout;
  OSSfsCurl::readwrite_timeout = timeout;
  return old;
}

int OSSfsCurl::SetRetries(int count)
{
  int old = OSSfsCurl::retries;
  OSSfsCurl::retries = count;
  return old;
}

bool OSSfsCurl::SetPublicBucket(bool flag)
{
  bool old = OSSfsCurl::is_public_bucket;
  OSSfsCurl::is_public_bucket = flag;
  return old;
}

string OSSfsCurl::SetDefaultAcl(const char* acl)
{
  string old = OSSfsCurl::default_acl;
  OSSfsCurl::default_acl = acl ? acl : "";
  return old;
}

string OSSfsCurl::GetDefaultAcl()
{
  return OSSfsCurl::default_acl;
}

storage_class_t OSSfsCurl::SetStorageClass(storage_class_t storage_class)
{
  storage_class_t old = OSSfsCurl::storage_class;
  OSSfsCurl::storage_class = storage_class;
  return old;
}

bool OSSfsCurl::PushbackSseKeys(string& onekey)
{
  onekey = trim(onekey);
  if(onekey.empty()){
    return false;
  }
  if('#' == onekey[0]){
    return false;
  }
  // make base64 if the key is short enough, otherwise assume it is already so
  string base64_key;
  string raw_key;
  if(onekey.length() > 256 / 8){
    char* p_key;
    size_t keylength;

    if(NULL != (p_key = (char *)ossfs_decode64(onekey.c_str(), &keylength))) {
      raw_key = string(p_key, keylength);
      base64_key = onekey;
      free(p_key);
    } else {
      OSSFS_PRN_ERR("Failed to convert base64 to SSE-C key %s", onekey.c_str());
      return false;
    }
  } else {
    char* pbase64_key;

    if(NULL != (pbase64_key = ossfs_base64((unsigned char*)onekey.c_str(), onekey.length()))) {
      raw_key = onekey;
      base64_key = pbase64_key;
      free(pbase64_key);
    } else {
      OSSFS_PRN_ERR("Failed to convert base64 from SSE-C key %s", onekey.c_str());
      return false;
    }
  }

  // make MD5
  string strMd5;
  if(!make_md5_from_string(raw_key.c_str(), strMd5)){
    OSSFS_PRN_ERR("Could not make MD5 from SSE-C keys(%s).", raw_key.c_str());
    return false;
  }
  // mapped MD5 = SSE Key
  sseckeymap_t md5map;
  md5map.clear();
  md5map[strMd5] = base64_key;
  OSSfsCurl::sseckeys.push_back(md5map);
  return true;
}

sse_type_t OSSfsCurl::SetSseType(sse_type_t type)
{
  sse_type_t    old = OSSfsCurl::ssetype;
  OSSfsCurl::ssetype = type;
  return old;
}

bool OSSfsCurl::SetSseCKeys(const char* filepath)
{
  if(!filepath){
    OSSFS_PRN_ERR("SSE-C keys filepath is empty.");
    return false;
  }
  struct stat st;
  if(0 != stat(filepath, &st)){
    OSSFS_PRN_ERR("could not open use_sse keys file(%s).", filepath);
    return false;
  }
  if(st.st_mode & (S_IXUSR | S_IRWXG | S_IRWXO)){
    OSSFS_PRN_ERR("use_sse keys file %s should be 0600 permissions.", filepath);
    return false;
  }

  OSSfsCurl::sseckeys.clear();

  ifstream ssefs(filepath);
  if(!ssefs.good()){
    OSSFS_PRN_ERR("Could not open SSE-C keys file(%s).", filepath);
    return false;
  }

  string   line;
  while(getline(ssefs, line)){
    OSSfsCurl::PushbackSseKeys(line);
  }
  if(OSSfsCurl::sseckeys.empty()){
    OSSFS_PRN_ERR("There is no SSE Key in file(%s).", filepath);
    return false;
  }
  return true;
}

bool OSSfsCurl::SetSseKmsid(const char* kmsid)
{
  if(!kmsid || '\0' == kmsid[0]){
    OSSFS_PRN_ERR("SSE-KMS kms id is empty.");
    return false;
  }
  OSSfsCurl::ssekmsid = kmsid;
  return true;
}

// [NOTE]
// Because SSE is set by some options and environment, 
// this function check the integrity of the SSE data finally.
bool OSSfsCurl::FinalCheckSse()
{
  if(SSE_DISABLE == OSSfsCurl::ssetype){
    OSSfsCurl::ssekmsid.erase();
  }else if(SSE_OSS == OSSfsCurl::ssetype){
    OSSfsCurl::ssekmsid.erase();
  }else if(SSE_C == OSSfsCurl::ssetype){
    if(OSSfsCurl::sseckeys.empty()){
      OSSFS_PRN_ERR("sse type is SSE-C, but there is no custom key.");
      return false;
    }
    OSSfsCurl::ssekmsid.erase();
  }else if(SSE_KMS == OSSfsCurl::ssetype){
    if(OSSfsCurl::ssekmsid.empty()){
      OSSFS_PRN_ERR("sse type is SSE-KMS, but there is no specified kms id.");
      return false;
    }
    if(!OSSfsCurl::IsSignatureV4()){
      OSSFS_PRN_ERR("sse type is SSE-KMS, but signature type is not v4. SSE-KMS require signature v4.");
      return false;
    }
  }else{
    OSSFS_PRN_ERR("sse type is unknown(%d).", OSSfsCurl::ssetype);
    return false;
  }
  return true;
}
                                                                                                                                                   
bool OSSfsCurl::LoadEnvSseCKeys()
{
  char* envkeys = getenv("OSSSSECKEYS");
  if(NULL == envkeys){
    // nothing to do
    return true;
  }
  OSSfsCurl::sseckeys.clear();

  istringstream fullkeys(envkeys);
  string        onekey;
  while(getline(fullkeys, onekey, ':')){
    OSSfsCurl::PushbackSseKeys(onekey);
  }
  if(OSSfsCurl::sseckeys.empty()){
    OSSFS_PRN_ERR("There is no SSE Key in environment(OSSSSECKEYS=%s).", envkeys);
    return false;
  }
  return true;
}

bool OSSfsCurl::LoadEnvSseKmsid()
{
  char* envkmsid = getenv("OSSSSEKMSID");
  if(NULL == envkmsid){
    // nothing to do
    return true;
  }
  return OSSfsCurl::SetSseKmsid(envkmsid);
}

//
// If md5 is empty, returns first(current) sse key.
//
bool OSSfsCurl::GetSseKey(string& md5, string& ssekey)
{
  for(sseckeylist_t::const_iterator iter = OSSfsCurl::sseckeys.begin(); iter != OSSfsCurl::sseckeys.end(); ++iter){
    if(0 == md5.length() || md5 == (*iter).begin()->first){
      md5    = iter->begin()->first;
      ssekey = iter->begin()->second;
      return true;
    }
  }
  return false;
}

bool OSSfsCurl::GetSseKeyMd5(int pos, string& md5)
{
  if(pos < 0){
    return false;
  }
  if(OSSfsCurl::sseckeys.size() <= static_cast<size_t>(pos)){
    return false;
  }
  int cnt = 0;
  for(sseckeylist_t::const_iterator iter = OSSfsCurl::sseckeys.begin(); iter != OSSfsCurl::sseckeys.end(); ++iter, ++cnt){
    if(pos == cnt){
      md5 = iter->begin()->first;
      return true;
    }
  }
  return false;
}

int OSSfsCurl::GetSseKeyCount()
{
  return OSSfsCurl::sseckeys.size();
}

bool OSSfsCurl::SetContentMd5(bool flag)
{
  bool old = OSSfsCurl::is_content_md5;
  OSSfsCurl::is_content_md5 = flag;
  return old;
}

bool OSSfsCurl::SetVerbose(bool flag)
{
  bool old = OSSfsCurl::is_verbose;
  OSSfsCurl::is_verbose = flag;
  return old;
}

bool OSSfsCurl::SetAccessKey(const char* AccessKeyId, const char* SecretAccessKey)
{
  if((!OSSfsCurl::is_ibm_iam_auth && (!AccessKeyId || '\0' == AccessKeyId[0])) || !SecretAccessKey || '\0' == SecretAccessKey[0]){
    return false;
  }
  OSSAccessKeyId     = AccessKeyId;
  OSSSecretAccessKey = SecretAccessKey;
  return true;
}

long OSSfsCurl::SetSslVerifyHostname(long value)
{
  if(0 != value && 1 != value){
    return -1;
  }
  long old = OSSfsCurl::ssl_verify_hostname;
  OSSfsCurl::ssl_verify_hostname = value;
  return old;
}

bool OSSfsCurl::SetIsIBMIAMAuth(bool flag)
{
  bool old = OSSfsCurl::is_ibm_iam_auth;
  OSSfsCurl::is_ibm_iam_auth = flag;
  return old;
}

bool OSSfsCurl::SetIsECS(bool flag)
{
  bool old = OSSfsCurl::is_ecs;
  OSSfsCurl::is_ecs = flag;
  return old;
}

string OSSfsCurl::SetIAMRole(const char* role)
{
  string old = OSSfsCurl::IAM_role;
  OSSfsCurl::IAM_role = role ? role : "";
  return old;
}

size_t OSSfsCurl::SetIAMFieldCount(size_t field_count)
{
  size_t old = OSSfsCurl::IAM_field_count;
  OSSfsCurl::IAM_field_count = field_count;
  return old;
}

string OSSfsCurl::SetIAMCredentialsURL(const char* url)
{
  string old = OSSfsCurl::IAM_cred_url;
  OSSfsCurl::IAM_cred_url = url ? url : "";
  return old;
}

string OSSfsCurl::SetIAMTokenField(const char* token_field)
{
  string old = OSSfsCurl::IAM_token_field;
  OSSfsCurl::IAM_token_field = token_field ? token_field : "";
  return old;
}

string OSSfsCurl::SetIAMExpiryField(const char* expiry_field)
{
  string old = OSSfsCurl::IAM_expiry_field;
  OSSfsCurl::IAM_expiry_field = expiry_field ? expiry_field : "";
  return old;
}

bool OSSfsCurl::SetMultipartSize(off_t size)
{
  size = size * 1024 * 1024;
  if(size < MIN_MULTIPART_SIZE){
    return false;
  }
  OSSfsCurl::multipart_size = size;
  return true;
}

int OSSfsCurl::SetMaxParallelCount(int value)
{
  int old = OSSfsCurl::max_parallel_cnt;
  OSSfsCurl::max_parallel_cnt = value;
  return old;
}

int OSSfsCurl::SetMaxMultiRequest(int max)
{
  int old = OSSfsCurl::max_multireq;
  OSSfsCurl::max_multireq = max;
  return old;
}

bool OSSfsCurl::UploadMultipartPostCallback(OSSfsCurl* ossfscurl)
{
  if(!ossfscurl){
    return false;
  }

  return ossfscurl->UploadMultipartPostComplete();
}

OSSfsCurl* OSSfsCurl::UploadMultipartPostRetryCallback(OSSfsCurl* ossfscurl)
{
  if(!ossfscurl){
    return NULL;
  }
  // parse and get part_num, upload_id.
  string upload_id;
  string part_num_str;
  int    part_num;
  if(!get_keyword_value(ossfscurl->url, "uploadId", upload_id)){
    return NULL;
  }
  if(!get_keyword_value(ossfscurl->url, "partNumber", part_num_str)){
    return NULL;
  }
  part_num = atoi(part_num_str.c_str());

  if(ossfscurl->retry_count >= OSSfsCurl::retries){
    OSSFS_PRN_ERR("Over retry count(%d) limit(%s:%d).", ossfscurl->retry_count, ossfscurl->path.c_str(), part_num);
    return NULL;
  }

  // duplicate request
  OSSfsCurl* newcurl            = new OSSfsCurl(ossfscurl->IsUseAhbe());
  newcurl->partdata.etaglist   = ossfscurl->partdata.etaglist;
  newcurl->partdata.etagpos    = ossfscurl->partdata.etagpos;
  newcurl->partdata.fd         = ossfscurl->partdata.fd;
  newcurl->partdata.startpos   = ossfscurl->b_partdata_startpos;
  newcurl->partdata.size       = ossfscurl->b_partdata_size;
  newcurl->b_partdata_startpos = ossfscurl->b_partdata_startpos;
  newcurl->b_partdata_size     = ossfscurl->b_partdata_size;
  newcurl->retry_count         = ossfscurl->retry_count + 1;

  // setup new curl object
  if(0 != newcurl->UploadMultipartPostSetup(ossfscurl->path.c_str(), part_num, upload_id)){
    OSSFS_PRN_ERR("Could not duplicate curl object(%s:%d).", ossfscurl->path.c_str(), part_num);
    delete newcurl;
    return NULL;
  }
  return newcurl;
}

OSSfsCurl* OSSfsCurl::CopyMultipartPostRetryCallback(OSSfsCurl* ossfscurl)
{
  if(!ossfscurl){
    return NULL;
  }
  // parse and get part_num, upload_id.
  string upload_id;
  string part_num_str;
  int    part_num;
  if(!get_keyword_value(ossfscurl->url, "uploadId", upload_id)){
    return NULL;
  }
  if(!get_keyword_value(ossfscurl->url, "partNumber", part_num_str)){
    return NULL;
  }
  part_num = atoi(part_num_str.c_str());

  if(ossfscurl->retry_count >= OSSfsCurl::retries){
    OSSFS_PRN_ERR("Over retry count(%d) limit(%s:%d).", ossfscurl->retry_count, ossfscurl->path.c_str(), part_num);
    return NULL;
  }

  // duplicate request
  OSSfsCurl* newcurl            = new OSSfsCurl(ossfscurl->IsUseAhbe());
  newcurl->partdata.etaglist   = ossfscurl->partdata.etaglist;
  newcurl->partdata.etagpos    = ossfscurl->partdata.etagpos;
  newcurl->retry_count         = ossfscurl->retry_count + 1;

  // setup new curl object
  if(0 != newcurl->UploadMultipartPostSetup(ossfscurl->path.c_str(), part_num, upload_id)){
    OSSFS_PRN_ERR("Could not duplicate curl object(%s:%d).", ossfscurl->path.c_str(), part_num);
    delete newcurl;
    return NULL;
  }
  return newcurl;
}

int OSSfsCurl::ParallelMultipartUploadRequest(const char* tpath, headers_t& meta, int fd)
{
  int            result;
  string         upload_id;
  struct stat    st;
  int            fd2;
  etaglist_t     list;
  off_t          remaining_bytes;
  OSSfsCurl       ossfscurl(true);

  OSSFS_PRN_INFO3("[tpath=%s][fd=%d]", SAFESTRPTR(tpath), fd);

  // duplicate fd
  if(-1 == (fd2 = dup(fd)) || 0 != lseek(fd2, 0, SEEK_SET)){
    OSSFS_PRN_ERR("Could not duplicate file descriptor(errno=%d)", errno);
    if(-1 != fd2){
      close(fd2);
    }
    return -errno;
  }
  if(-1 == fstat(fd2, &st)){
    OSSFS_PRN_ERR("Invalid file descriptor(errno=%d)", errno);
    close(fd2);
    return -errno;
  }

  if(0 != (result = ossfscurl.PreMultipartPostRequest(tpath, meta, upload_id, false))){
    close(fd2);
    return result;
  }
  ossfscurl.DestroyCurlHandle();

  // Initialize OSSfsMultiCurl
  OSSfsMultiCurl curlmulti(GetMaxParallelCount());
  curlmulti.SetSuccessCallback(OSSfsCurl::UploadMultipartPostCallback);
  curlmulti.SetRetryCallback(OSSfsCurl::UploadMultipartPostRetryCallback);

  // cycle through open fd, pulling off 10MB chunks at a time
  for(remaining_bytes = st.st_size; 0 < remaining_bytes; ){
    off_t chunk = remaining_bytes > OSSfsCurl::multipart_size ? OSSfsCurl::multipart_size : remaining_bytes;

    // ossfscurl sub object
    OSSfsCurl* ossfscurl_para            = new OSSfsCurl(true);
    ossfscurl_para->partdata.fd         = fd2;
    ossfscurl_para->partdata.startpos   = st.st_size - remaining_bytes;
    ossfscurl_para->partdata.size       = chunk;
    ossfscurl_para->b_partdata_startpos = ossfscurl_para->partdata.startpos;
    ossfscurl_para->b_partdata_size     = ossfscurl_para->partdata.size;
    ossfscurl_para->partdata.add_etag_list(&list);

    // initiate upload part for parallel
    if(0 != (result = ossfscurl_para->UploadMultipartPostSetup(tpath, list.size(), upload_id))){
      OSSFS_PRN_ERR("failed uploading part setup(%d)", result);
      close(fd2);
      delete ossfscurl_para;
      return result;
    }

    // set into parallel object
    if(!curlmulti.SetOSSfsCurlObject(ossfscurl_para)){
      OSSFS_PRN_ERR("Could not make curl object into multi curl(%s).", tpath);
      close(fd2);
      delete ossfscurl_para;
      return -1;
    }

    remaining_bytes -= chunk;
  }

  // Multi request
  if(0 != (result = curlmulti.Request())){
    OSSFS_PRN_ERR("error occurred in multi request(errno=%d).", result);

    OSSfsCurl ossfscurl_abort(true);
    int result2 = ossfscurl_abort.AbortMultipartUpload(tpath, upload_id);
    ossfscurl_abort.DestroyCurlHandle();
    if(result2 != 0){
      OSSFS_PRN_ERR("error aborting multipart upload(errno=%d).", result2);
    }

    return result;
  }

  close(fd2);

  if(0 != (result = ossfscurl.CompleteMultipartPostRequest(tpath, upload_id, list))){
    return result;
  }
  return 0;
}

OSSfsCurl* OSSfsCurl::ParallelGetObjectRetryCallback(OSSfsCurl* ossfscurl)
{
  int result;

  if(!ossfscurl){
    return NULL;
  }
  if(ossfscurl->retry_count >= OSSfsCurl::retries){
    OSSFS_PRN_ERR("Over retry count(%d) limit(%s).", ossfscurl->retry_count, ossfscurl->path.c_str());
    return NULL;
  }

  // duplicate request(setup new curl object)
  OSSfsCurl* newcurl = new OSSfsCurl(ossfscurl->IsUseAhbe());
  if(0 != (result = newcurl->PreGetObjectRequest(ossfscurl->path.c_str(), ossfscurl->partdata.fd,
     ossfscurl->partdata.startpos, ossfscurl->partdata.size, ossfscurl->b_ssetype, ossfscurl->b_ssevalue)))
  {
    OSSFS_PRN_ERR("failed downloading part setup(%d)", result);
    delete newcurl;
    return NULL;;
  }
  newcurl->retry_count = ossfscurl->retry_count + 1;

  return newcurl;
}

int OSSfsCurl::ParallelGetObjectRequest(const char* tpath, int fd, off_t start, ssize_t size)
{
  OSSFS_PRN_INFO3("[tpath=%s][fd=%d]", SAFESTRPTR(tpath), fd);

  sse_type_t ssetype;
  string     ssevalue;
  if(!get_object_sse_type(tpath, ssetype, ssevalue)){
    OSSFS_PRN_WARN("Failed to get SSE type for file(%s).", SAFESTRPTR(tpath));
  }
  int        result = 0;
  ssize_t    remaining_bytes;

  // cycle through open fd, pulling off 10MB chunks at a time
  for(remaining_bytes = size; 0 < remaining_bytes; ){
    OSSfsMultiCurl curlmulti(GetMaxParallelCount());
    int           para_cnt;
    off_t         chunk;

    // Initialize OSSfsMultiCurl
    //curlmulti.SetSuccessCallback(NULL);   // not need to set success callback
    curlmulti.SetRetryCallback(OSSfsCurl::ParallelGetObjectRetryCallback);

    // Loop for setup parallel upload(multipart) request.
    for(para_cnt = 0; para_cnt < OSSfsCurl::max_parallel_cnt && 0 < remaining_bytes; para_cnt++, remaining_bytes -= chunk){
      // chunk size
      chunk = remaining_bytes > OSSfsCurl::multipart_size ? OSSfsCurl::multipart_size : remaining_bytes;

      // ossfscurl sub object
      OSSfsCurl* ossfscurl_para = new OSSfsCurl();
      if(0 != (result = ossfscurl_para->PreGetObjectRequest(tpath, fd, (start + size - remaining_bytes), chunk, ssetype, ssevalue))){
        OSSFS_PRN_ERR("failed downloading part setup(%d)", result);
        delete ossfscurl_para;
        return result;
      }

      // set into parallel object
      if(!curlmulti.SetOSSfsCurlObject(ossfscurl_para)){
        OSSFS_PRN_ERR("Could not make curl object into multi curl(%s).", tpath);
        delete ossfscurl_para;
        return -1;
      }
    }

    // Multi request
    if(0 != (result = curlmulti.Request())){
      OSSFS_PRN_ERR("error occurred in multi request(errno=%d).", result);
      break;
    }

    // reinit for loop.
    curlmulti.Clear();
  }
  return result;
}

bool OSSfsCurl::UploadMultipartPostSetCurlOpts(OSSfsCurl* ossfscurl)
{
  if(!ossfscurl){
    return false;
  }
  if(!ossfscurl->CreateCurlHandle()){
    return false;
  }
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_URL, ossfscurl->url.c_str());
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_UPLOAD, true);              // HTTP PUT
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_WRITEDATA, (void*)(ossfscurl->bodydata));
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_HEADERDATA, (void*)&(ossfscurl->responseHeaders));
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_HEADERFUNCTION, HeaderCallback);
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(ossfscurl->partdata.size)); // Content-Length
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_READFUNCTION, UploadReadCallback);
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_READDATA, (void*)ossfscurl);
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_HTTPHEADER, ossfscurl->requestHeaders);
  OSSfsCurl::AddUserAgent(ossfscurl->hCurl);                            // put User-Agent

  return true;
}

bool OSSfsCurl::CopyMultipartPostSetCurlOpts(OSSfsCurl* ossfscurl)
{
  if(!ossfscurl){
    return false;
  }
  if(!ossfscurl->CreateCurlHandle()){
    return false;
  }

  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_URL, ossfscurl->url.c_str());
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_UPLOAD, true);                // HTTP PUT
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_WRITEDATA, (void*)(ossfscurl->bodydata));
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_HEADERDATA, (void*)(ossfscurl->headdata));
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_INFILESIZE, 0);               // Content-Length
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_HTTPHEADER, ossfscurl->requestHeaders);
  OSSfsCurl::AddUserAgent(ossfscurl->hCurl);                                // put User-Agent

  return true;
}

bool OSSfsCurl::PreGetObjectRequestSetCurlOpts(OSSfsCurl* ossfscurl)
{
  if(!ossfscurl){
    return false;
  }
  if(!ossfscurl->CreateCurlHandle()){
    return false;
  }

  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_URL, ossfscurl->url.c_str());
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_HTTPHEADER, ossfscurl->requestHeaders);
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_WRITEFUNCTION, DownloadWriteCallback);
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_WRITEDATA, (void*)ossfscurl);
  OSSfsCurl::AddUserAgent(ossfscurl->hCurl);        // put User-Agent

  return true;
}

bool OSSfsCurl::PreHeadRequestSetCurlOpts(OSSfsCurl* ossfscurl)
{
  if(!ossfscurl){
    return false;
  }
  if(!ossfscurl->CreateCurlHandle()){
    return false;
  }

  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_URL, ossfscurl->url.c_str());
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_NOBODY, true);   // HEAD
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_FILETIME, true); // Last-Modified
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_HTTPHEADER, ossfscurl->requestHeaders);

  // responseHeaders
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_HEADERDATA, (void*)&(ossfscurl->responseHeaders));
  curl_easy_setopt(ossfscurl->hCurl, CURLOPT_HEADERFUNCTION, HeaderCallback);
  OSSfsCurl::AddUserAgent(ossfscurl->hCurl);                   // put User-Agent

  return true;
}

bool OSSfsCurl::ParseIAMCredentialResponse(const char* response, iamcredmap_t& keyval)
{
  if(!response){
    return false;
  }
  istringstream sscred(response);
  string        oneline;
  keyval.clear();
  while(getline(sscred, oneline, ',')){
    string::size_type pos;
    string            key;
    string            val;
    if(string::npos != (pos = oneline.find(IAMCRED_ACCESSKEYID))){
      key = IAMCRED_ACCESSKEYID;
    }else if(string::npos != (pos = oneline.find(IAMCRED_SECRETACCESSKEY))){
      key = IAMCRED_SECRETACCESSKEY;
    }else if(string::npos != (pos = oneline.find(OSSfsCurl::IAM_token_field))){
      key = OSSfsCurl::IAM_token_field;
    }else if(string::npos != (pos = oneline.find(OSSfsCurl::IAM_expiry_field))){
      key = OSSfsCurl::IAM_expiry_field;
    }else if(string::npos != (pos = oneline.find(IAMCRED_ROLEARN))){
      key = IAMCRED_ROLEARN;
    }else{
      continue;
    }
    if(string::npos == (pos = oneline.find(':', pos + key.length()))){
      continue;
    }

    if(OSSfsCurl::is_ibm_iam_auth && key == OSSfsCurl::IAM_expiry_field){
      // parse integer value
      if(string::npos == (pos = oneline.find_first_of("0123456789", pos))){
        continue;
      }
      oneline = oneline.substr(pos);
      if(string::npos == (pos = oneline.find_last_of("0123456789"))){
        continue;
      }
      val = oneline.substr(0, pos+1);
    }else{
      // parse string value (starts and ends with quotes)
      if(string::npos == (pos = oneline.find('\"', pos))){
        continue;
      }
      oneline = oneline.substr(pos + sizeof(char));
      if(string::npos == (pos = oneline.find('\"'))){
        continue;
      }
      val = oneline.substr(0, pos);
    }
    keyval[key] = val;
  }
  return true;
}

bool OSSfsCurl::SetIAMCredentials(const char* response)
{
  OSSFS_PRN_INFO3("IAM credential response = \"%s\"", response);

  iamcredmap_t keyval;

  if(!ParseIAMCredentialResponse(response, keyval)){
    return false;
  }

  if(OSSfsCurl::IAM_field_count != keyval.size()){
    return false;
  }

  OSSfsCurl::OSSAccessToken       = keyval[string(OSSfsCurl::IAM_token_field)];

  if(OSSfsCurl::is_ibm_iam_auth){
    OSSfsCurl::OSSAccessTokenExpire = strtol(keyval[string(OSSfsCurl::IAM_expiry_field)].c_str(), NULL, 10);
  }else{
    OSSfsCurl::OSSAccessKeyId       = keyval[string(IAMCRED_ACCESSKEYID)];
    OSSfsCurl::OSSSecretAccessKey   = keyval[string(IAMCRED_SECRETACCESSKEY)];
    OSSfsCurl::OSSAccessTokenExpire = cvtIAMExpireStringToTime(keyval[OSSfsCurl::IAM_expiry_field].c_str());
  }

  return true;
}

bool OSSfsCurl::CheckIAMCredentialUpdate()
{
  if(OSSfsCurl::IAM_role.empty() && !OSSfsCurl::is_ecs && !OSSfsCurl::is_ibm_iam_auth){
    return true;
  }
  if(time(NULL) + IAM_EXPIRE_MERGIN <= OSSfsCurl::OSSAccessTokenExpire){
    return true;
  }
  // update
  OSSfsCurl ossfscurl;
  if(0 != ossfscurl.GetIAMCredentials()){
    return false;
  }
  return true;
}

bool OSSfsCurl::ParseIAMRoleFromMetaDataResponse(const char* response, string& rolename)
{
  if(!response){
    return false;
  }
  // [NOTE]
  // expected following strings.
  // 
  // myrolename
  //
  istringstream ssrole(response);
  string        oneline;
  if (getline(ssrole, oneline, '\n')){
    rolename = oneline;
    return !rolename.empty();
  }
  return false;
}

bool OSSfsCurl::SetIAMRoleFromMetaData(const char* response)
{
  OSSFS_PRN_INFO3("IAM role name response = \"%s\"", response);

  string rolename;

  if(!OSSfsCurl::ParseIAMRoleFromMetaDataResponse(response, rolename)){
    return false;
  }

  SetIAMRole(rolename.c_str());
  return true;
}

bool OSSfsCurl::AddUserAgent(CURL* hCurl)
{
  if(!hCurl){
    return false;
  }
  if(OSSfsCurl::IsUserAgentFlag()){
    curl_easy_setopt(hCurl, CURLOPT_USERAGENT, OSSfsCurl::userAgent.c_str());
  }
  return true;
}

int OSSfsCurl::CurlDebugFunc(CURL* hcurl, curl_infotype type, char* data, size_t size, void* userptr)
{
  if(!hcurl){
    // something wrong...
    return 0;
  }
  switch(type){
    case CURLINFO_TEXT:
      // Swap tab indentation with spaces so it stays pretty in syslog
      int indent;
      indent = 0;
      while (*data == '\t' && size > 0) {
        indent += 4;
        size--;
        data++;
      }
      OSSFS_PRN_CURL("* %*s%.*s", indent, "", (int)size, data);
      break;
    case CURLINFO_HEADER_IN:
    case CURLINFO_HEADER_OUT:
      size_t remaining;
      char* p;

      // Print each line individually for tidy output
      remaining = size;
      p = data;
      do {
        char* eol = (char*)memchr(p, '\n', remaining);
        int newline = 0;
        if (eol == NULL) {
          eol = (char*)memchr(p, '\r', remaining);
        } else {
          if (eol > p && *(eol - 1) == '\r') {
            newline++;
          }
          newline++;
          eol++;
        }
        size_t length = eol - p;
        OSSFS_PRN_CURL("%c %.*s", CURLINFO_HEADER_IN == type ? '<' : '>', (int)length - newline, p);
        remaining -= length;
        p = eol;
      } while (p != NULL && remaining > 0);
      break;
    case CURLINFO_DATA_IN:
    case CURLINFO_DATA_OUT:
    case CURLINFO_SSL_DATA_IN:
    case CURLINFO_SSL_DATA_OUT:
      // not put
      break;
    default:
      // why
      break;
  }
  return 0;
}

//-------------------------------------------------------------------
// Methods for OSSfsCurl
//-------------------------------------------------------------------
OSSfsCurl::OSSfsCurl(bool ahbe) : 
    hCurl(NULL), type(REQTYPE_UNSET), path(""), base_path(""), saved_path(""), url(""), requestHeaders(NULL),
    bodydata(NULL), headdata(NULL), LastResponseCode(-1), postdata(NULL), postdata_remaining(0), is_use_ahbe(ahbe),
    retry_count(0), b_infile(NULL), b_postdata(NULL), b_postdata_remaining(0), b_partdata_startpos(0), b_partdata_size(0),
    b_ssekey_pos(-1), b_ssevalue(""), b_ssetype(SSE_DISABLE), op(""), query_string(""),
    sem(NULL), completed_tids_lock(NULL), completed_tids(NULL), fpLazySetup(NULL)
{
}

OSSfsCurl::~OSSfsCurl()
{
  DestroyCurlHandle();
}

bool OSSfsCurl::ResetHandle()
{
  curl_easy_reset(hCurl);
  curl_easy_setopt(hCurl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(hCurl, CURLOPT_FOLLOWLOCATION, true);
  curl_easy_setopt(hCurl, CURLOPT_CONNECTTIMEOUT, OSSfsCurl::connect_timeout);
  curl_easy_setopt(hCurl, CURLOPT_NOPROGRESS, 0);
  curl_easy_setopt(hCurl, CURLOPT_PROGRESSFUNCTION, OSSfsCurl::CurlProgress);
  curl_easy_setopt(hCurl, CURLOPT_PROGRESSDATA, hCurl);
  // curl_easy_setopt(hCurl, CURLOPT_FORBID_REUSE, 1);
  curl_easy_setopt(hCurl, CURLOPT_TCP_KEEPALIVE, 1);
  // curl_easy_setopt(hCurl, CURLOPT_KEEP_SENDING_ON_ERROR, 1);    // after 7.51.0
  // curl_easy_setopt(hCurl, CURLOPT_SSL_ENABLE_ALPN, 0);          // after 7.36.0 for disable ALPN for oss server

  if(type != REQTYPE_IAMCRED && type != REQTYPE_IAMROLE){
    // REQTYPE_IAMCRED and REQTYPE_IAMROLE are always HTTP
    if(0 == OSSfsCurl::ssl_verify_hostname){
      curl_easy_setopt(hCurl, CURLOPT_SSL_VERIFYHOST, 0);
    }
    if(!OSSfsCurl::curl_ca_bundle.empty()){
      curl_easy_setopt(hCurl, CURLOPT_CAINFO, OSSfsCurl::curl_ca_bundle.c_str());
    }
  }
  if((OSSfsCurl::is_dns_cache || OSSfsCurl::is_ssl_session_cache) && OSSfsCurl::hCurlShare){
    curl_easy_setopt(hCurl, CURLOPT_SHARE, OSSfsCurl::hCurlShare);
  }
  if(!OSSfsCurl::is_cert_check) {
    OSSFS_PRN_DBG("'no_check_certificate' option in effect.")
    OSSFS_PRN_DBG("The server certificate won't be checked against the available certificate authorities.")
    curl_easy_setopt(hCurl, CURLOPT_SSL_VERIFYPEER, false);
  }
  if(OSSfsCurl::is_verbose){
    curl_easy_setopt(hCurl, CURLOPT_VERBOSE, true);
    if(!foreground){
      curl_easy_setopt(hCurl, CURLOPT_DEBUGFUNCTION, OSSfsCurl::CurlDebugFunc);
    }
  }
  if(!cipher_suites.empty()) {
    curl_easy_setopt(hCurl, CURLOPT_SSL_CIPHER_LIST, cipher_suites.c_str());
  }

  OSSfsCurl::curl_times[hCurl]    = time(0);
  OSSfsCurl::curl_progress[hCurl] = progress_t(-1, -1);

  return true;
}

bool OSSfsCurl::CreateCurlHandle(bool only_pool, bool remake)
{
  AutoLock lock(&OSSfsCurl::curl_handles_lock);

  if(hCurl && remake){
    if(!DestroyCurlHandle(false)){
      OSSFS_PRN_ERR("could not destroy handle.");
      return false;
    }
    OSSFS_PRN_INFO3("already has handle, so destroyed it or restored it to pool.");
  }

  if(!hCurl){
    if(NULL == (hCurl = sCurlPool->GetHandler(only_pool))){
      if(!only_pool){
        OSSFS_PRN_ERR("Failed to create handle.");
        return false;
      }else{
        // [NOTE]
        // urther initialization processing is left to lazy processing to be executed later.
        // (Currently we do not use only_pool=true, but this code is remained for the future)
        return true;
      }
    }
  }

  // [NOTE]
  // If type is REQTYPE_IAMCRED or REQTYPE_IAMROLE, do not clear type.
  // Because that type only uses HTTP protocol, then the special
  // logic in ResetHandle function.
  //
  if(type != REQTYPE_IAMCRED && type != REQTYPE_IAMROLE){
    type = REQTYPE_UNSET;
  }

  ResetHandle();

  return true;
}

bool OSSfsCurl::DestroyCurlHandle(bool restore_pool, bool clear_internal_data)
{
  if(clear_internal_data){
    ClearInternalData();
  }

  if(hCurl){
    AutoLock lock(&OSSfsCurl::curl_handles_lock);

    OSSfsCurl::curl_times.erase(hCurl);
    OSSfsCurl::curl_progress.erase(hCurl);
    sCurlPool->ReturnHandler(hCurl, restore_pool);
    hCurl = NULL;
  }else{
    return false;
  }
  return true;
}

bool OSSfsCurl::ClearInternalData()
{
  // Always clear internal data
  //
  type        = REQTYPE_UNSET;
  path        = "";
  base_path   = "";
  saved_path  = "";
  url         = "";
  op          = "";
  query_string= "";
  if(requestHeaders){
    curl_slist_free_all(requestHeaders);
    requestHeaders = NULL;
  }
  responseHeaders.clear();
  if(bodydata){
    delete bodydata;
    bodydata = NULL;
  }
  if(headdata){
    delete headdata;
    headdata = NULL;
  }
  LastResponseCode     = -1;
  postdata             = NULL;
  postdata_remaining   = 0;
  retry_count          = 0;
  b_infile             = NULL;
  b_postdata           = NULL;
  b_postdata_remaining = 0;
  b_partdata_startpos  = 0;
  b_partdata_size      = 0;
  partdata.clear();

  fpLazySetup          = NULL;

  OSSFS_MALLOCTRIM(0);

  return true;
}

bool OSSfsCurl::SetUseAhbe(bool ahbe)
{
  bool old = is_use_ahbe;
  is_use_ahbe = ahbe;
  return old;
}

bool OSSfsCurl::GetResponseCode(long& responseCode, bool from_curl_handle)
{
  responseCode = -1;

  if(!from_curl_handle){
    responseCode = LastResponseCode;
  }else{
    if(!hCurl){
      return false;
    }
    if(CURLE_OK != curl_easy_getinfo(hCurl, CURLINFO_RESPONSE_CODE, &LastResponseCode)){
      return false;
    }
    responseCode = LastResponseCode;
  }
  return true;
}

//
// Reset all options for retrying
//
bool OSSfsCurl::RemakeHandle()
{
  OSSFS_PRN_INFO3("Retry request. [type=%d][url=%s][path=%s]", type, url.c_str(), path.c_str());

  if(REQTYPE_UNSET == type){
    return false;
  }

  // rewind file
  struct stat st;
  if(b_infile){
    rewind(b_infile);
    if(-1 == fstat(fileno(b_infile), &st)){
      OSSFS_PRN_WARN("Could not get file stat(fd=%d)", fileno(b_infile));
      return false;
    }
  }

  // reinitialize internal data
  responseHeaders.clear();
  if(bodydata){
    bodydata->Clear();
  }
  if(headdata){
    headdata->Clear();
  }
  LastResponseCode   = -1;

  // count up(only use for multipart)
  retry_count++;

  // set from backup
  postdata           = b_postdata;
  postdata_remaining = b_postdata_remaining;
  partdata.startpos  = b_partdata_startpos;
  partdata.size      = b_partdata_size;

  // reset handle
  ResetHandle();

  // set options
  switch(type){
    case REQTYPE_DELETE:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_CUSTOMREQUEST, "DELETE");
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    case REQTYPE_HEAD:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_NOBODY, true);
      curl_easy_setopt(hCurl, CURLOPT_FILETIME, true);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      // responseHeaders
      curl_easy_setopt(hCurl, CURLOPT_HEADERDATA, (void*)&responseHeaders);
      curl_easy_setopt(hCurl, CURLOPT_HEADERFUNCTION, HeaderCallback);
      break;

    case REQTYPE_PUTHEAD:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    case REQTYPE_PUT:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      if(b_infile){
        curl_easy_setopt(hCurl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(st.st_size));
        curl_easy_setopt(hCurl, CURLOPT_INFILE, b_infile);
      }else{
        curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0);
      }
      break;

    case REQTYPE_GET:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, OSSfsCurl::DownloadWriteCallback);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)this);
      break;

    case REQTYPE_CHKBUCKET:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    case REQTYPE_LISTBUCKET:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    case REQTYPE_PREMULTIPOST:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_POST, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, 0);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    case REQTYPE_COMPLETEMULTIPOST:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      curl_easy_setopt(hCurl, CURLOPT_POST, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, static_cast<curl_off_t>(postdata_remaining));
      curl_easy_setopt(hCurl, CURLOPT_READDATA, (void*)this);
      curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, OSSfsCurl::ReadCallback);
      break;

    case REQTYPE_UPLOADMULTIPOST:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_HEADERDATA, (void*)&responseHeaders);
      curl_easy_setopt(hCurl, CURLOPT_HEADERFUNCTION, HeaderCallback);
      curl_easy_setopt(hCurl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(partdata.size));
      curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, OSSfsCurl::UploadReadCallback);
      curl_easy_setopt(hCurl, CURLOPT_READDATA, (void*)this);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    case REQTYPE_COPYMULTIPOST:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_HEADERDATA, (void*)headdata);
      curl_easy_setopt(hCurl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    case REQTYPE_MULTILIST:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    case REQTYPE_IAMCRED:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      if(OSSfsCurl::is_ibm_iam_auth){
        curl_easy_setopt(hCurl, CURLOPT_POST, true);
        curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, static_cast<curl_off_t>(postdata_remaining));
        curl_easy_setopt(hCurl, CURLOPT_READDATA, (void*)this);
        curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, OSSfsCurl::ReadCallback);
      }
      break;

    case REQTYPE_ABORTMULTIUPLOAD:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_CUSTOMREQUEST, "DELETE");
      curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
      break;

    case REQTYPE_IAMROLE:
      curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
      curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
      break;

    default:
      OSSFS_PRN_ERR("request type is unknown(%d)", type);
      return false;
  }
  OSSfsCurl::AddUserAgent(hCurl);        // put User-Agent

  return true;
}

//
// returns curl return code
//
int OSSfsCurl::RequestPerform()
{
  if(IS_OSSFS_LOG_DBG()){
    char* ptr_url = NULL;
    curl_easy_getinfo(hCurl, CURLINFO_EFFECTIVE_URL , &ptr_url);
    OSSFS_PRN_DBG("connecting to URL %s", SAFESTRPTR(ptr_url));
  }

  // 1 attempt + retries...
  for(int retrycnt = 0; retrycnt < OSSfsCurl::retries; ++retrycnt){
    // Requests
    CURLcode curlCode = curl_easy_perform(hCurl);

    // Check result
    switch(curlCode){
      case CURLE_OK:
        // Need to look at the HTTP response code
        if(0 != curl_easy_getinfo(hCurl, CURLINFO_RESPONSE_CODE, &LastResponseCode)){
          OSSFS_PRN_ERR("curl_easy_getinfo failed while trying to retrieve HTTP response code");
          return -EIO;
        }
        if(LastResponseCode >= 200 && LastResponseCode < 300){
          OSSFS_PRN_INFO3("HTTP response code %ld", LastResponseCode);
          return 0;
        }

        // Service response codes which are >= 300 && < 500
        switch(LastResponseCode){
          case 301:
          case 307:
            OSSFS_PRN_ERR("HTTP response code 301(Moved Permanently: also happens when bucket's region is incorrect), returning EIO. Body Text: %s", (bodydata ? bodydata->str() : ""));
            OSSFS_PRN_ERR("The options of url and endpoint may be useful for solving, please try to use both options.");
            return -EIO;

          case 400:
            OSSFS_PRN_ERR("HTTP response code %ld, returning EIO. Body Text: %s", LastResponseCode, (bodydata ? bodydata->str() : ""));
            return -EIO;

          case 403:
            OSSFS_PRN_ERR("HTTP response code %ld, returning EPERM. Body Text: %s", LastResponseCode, (bodydata ? bodydata->str() : ""));
            return -EPERM;

          case 404:
            OSSFS_PRN_INFO3("HTTP response code 404 was returned, returning ENOENT");
            OSSFS_PRN_DBG("Body Text: %s", (bodydata ? bodydata->str() : ""));
            return -ENOENT;

          case 501:
            OSSFS_PRN_INFO3("HTTP response code 501 was returned, returning ENOTSUP");
            OSSFS_PRN_DBG("Body Text: %s", (bodydata ? bodydata->str() : ""));
            return -ENOTSUP;

          case 503:
            OSSFS_PRN_INFO3("HTTP response code 503 was returned, slowing down");
            OSSFS_PRN_DBG("Body Text: %s", (bodydata ? bodydata->str() : ""));
            sleep(4 << retry_count);
            break;

          default:
            OSSFS_PRN_ERR("HTTP response code %ld, returning EIO. Body Text: %s", LastResponseCode, (bodydata ? bodydata->str() : ""));
            return -EIO;
        }
        break;

      case CURLE_WRITE_ERROR:
        OSSFS_PRN_ERR("### CURLE_WRITE_ERROR");
        sleep(2);
        break; 

      case CURLE_OPERATION_TIMEDOUT:
        OSSFS_PRN_ERR("### CURLE_OPERATION_TIMEDOUT");
        sleep(2);
        break; 

      case CURLE_COULDNT_RESOLVE_HOST:
        OSSFS_PRN_ERR("### CURLE_COULDNT_RESOLVE_HOST");
        sleep(2);
        break; 

      case CURLE_COULDNT_CONNECT:
        OSSFS_PRN_ERR("### CURLE_COULDNT_CONNECT");
        sleep(4);
        break; 

      case CURLE_GOT_NOTHING:
        OSSFS_PRN_ERR("### CURLE_GOT_NOTHING");
        sleep(4);
        break; 

      case CURLE_ABORTED_BY_CALLBACK:
        OSSFS_PRN_ERR("### CURLE_ABORTED_BY_CALLBACK");
        sleep(4);
        OSSfsCurl::curl_times[hCurl] = time(0);
        break; 

      case CURLE_PARTIAL_FILE:
        OSSFS_PRN_ERR("### CURLE_PARTIAL_FILE");
        sleep(4);
        break; 

      case CURLE_SEND_ERROR:
        OSSFS_PRN_ERR("### CURLE_SEND_ERROR");
        sleep(2);
        break;

      case CURLE_RECV_ERROR:
        OSSFS_PRN_ERR("### CURLE_RECV_ERROR");
        sleep(2);
        break;

      case CURLE_SSL_CONNECT_ERROR:
        OSSFS_PRN_ERR("### CURLE_SSL_CONNECT_ERROR");
        sleep(2);
        break;

      case CURLE_SSL_CACERT:
        OSSFS_PRN_ERR("### CURLE_SSL_CACERT");

        // try to locate cert, if successful, then set the
        // option and continue
        if(OSSfsCurl::curl_ca_bundle.empty()){
          if(!OSSfsCurl::LocateBundle()){
            OSSFS_PRN_ERR("could not get CURL_CA_BUNDLE.");
            return -EIO;
          }
          break; // retry with CAINFO
        }
        OSSFS_PRN_ERR("curlCode: %d  msg: %s", curlCode, curl_easy_strerror(curlCode));
        return -EIO;
        break;

#ifdef CURLE_PEER_FAILED_VERIFICATION
      case CURLE_PEER_FAILED_VERIFICATION:
        OSSFS_PRN_ERR("### CURLE_PEER_FAILED_VERIFICATION");

        first_pos = bucket.find_first_of(".");
        if(first_pos != string::npos){
          OSSFS_PRN_INFO("curl returned a CURL_PEER_FAILED_VERIFICATION error");
          OSSFS_PRN_INFO("security issue found: buckets with periods in their name are incompatible with http");
          OSSFS_PRN_INFO("This check can be over-ridden by using the -o ssl_verify_hostname=0");
          OSSFS_PRN_INFO("The certificate will still be checked but the hostname will not be verified.");
          OSSFS_PRN_INFO("A more secure method would be to use a bucket name without periods.");
        }else{
          OSSFS_PRN_INFO("my_curl_easy_perform: curlCode: %d -- %s", curlCode, curl_easy_strerror(curlCode));
        }
        return -EIO;
        break;
#endif

      // This should be invalid since curl option HTTP FAILONERROR is now off
      case CURLE_HTTP_RETURNED_ERROR:
        OSSFS_PRN_ERR("### CURLE_HTTP_RETURNED_ERROR");

        if(0 != curl_easy_getinfo(hCurl, CURLINFO_RESPONSE_CODE, &LastResponseCode)){
          return -EIO;
        }
        OSSFS_PRN_INFO3("HTTP response code =%ld", LastResponseCode);

        // Let's try to retrieve the 
        if(404 == LastResponseCode){
          return -ENOENT;
        }
        if(500 > LastResponseCode){
          return -EIO;
        }
        break;

      // Unknown CURL return code
      default:
        OSSFS_PRN_ERR("###curlCode: %d  msg: %s", curlCode, curl_easy_strerror(curlCode));
        return -EIO;
        break;
    }
    OSSFS_PRN_INFO("### retrying...");

    if(!RemakeHandle()){
      OSSFS_PRN_INFO("Failed to reset handle and internal data for retrying.");
      return -EIO;
    }
  }
  OSSFS_PRN_ERR("### giving up");

  return -EIO;
}

//
// Returns the InspurCloud OSS signature for the given parameters.
//
// @param method e.g., "GET"
// @param content_type e.g., "application/x-directory"
// @param date e.g., get_date_rfc850()
// @param resource e.g., "/pub"
//
string OSSfsCurl::CalcSignatureV2(const string& method, const string& strMD5, const string& content_type, const string& date, const string& resource)
{
  string Signature;
  string StringToSign;

  if(!OSSfsCurl::IAM_role.empty() || OSSfsCurl::is_ecs){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-security-token", OSSfsCurl::OSSAccessToken.c_str());
  }

  StringToSign += method + "\n";
  StringToSign += strMD5 + "\n";        // md5
  StringToSign += content_type + "\n";
  StringToSign += date + "\n";
  StringToSign += get_canonical_headers(requestHeaders, true);
  StringToSign += resource;

  const void* key            = OSSfsCurl::OSSSecretAccessKey.data();
  int key_len                = OSSfsCurl::OSSSecretAccessKey.size();
  const unsigned char* sdata = reinterpret_cast<const unsigned char*>(StringToSign.data());
  int sdata_len              = StringToSign.size();
  unsigned char* md          = NULL;
  unsigned int md_len        = 0;;

  ossfs_HMAC(key, key_len, sdata, sdata_len, &md, &md_len);

  char* base64;
  if(NULL == (base64 = ossfs_base64(md, md_len))){
    free(md);
    return string("");  // ENOMEM
  }
  free(md);

  Signature = base64;
  free(base64);

  return Signature;
}

string OSSfsCurl::CalcSignature(const string& method, const string& canonical_uri, const string& query_string, const string& strdate, const string& payload_hash, const string& date8601)
{
  string Signature, StringCQ, StringToSign;
  string uriencode;

  if(!OSSfsCurl::IAM_role.empty()  || OSSfsCurl::is_ecs){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-security-token", OSSfsCurl::OSSAccessToken.c_str());
  }

  uriencode = urlEncode(canonical_uri);
  StringCQ  = method + "\n";
  if(0 == strcmp(method.c_str(),"HEAD") || 0 == strcmp(method.c_str(),"PUT") || 0 == strcmp(method.c_str(),"DELETE")){
    StringCQ += uriencode + "\n";
  }else if (0 == strcmp(method.c_str(), "GET") && 0 == strcmp(uriencode.c_str(), "")) {
    StringCQ +="/\n";
  }else if (0 == strcmp(method.c_str(), "GET") && 0 == strncmp(uriencode.c_str(), "/", 1)) {
    StringCQ += uriencode +"\n";
  }else if (0 == strcmp(method.c_str(), "GET") && 0 != strncmp(uriencode.c_str(), "/", 1)) {
    StringCQ += "/\n" + urlEncode2(canonical_uri) +"\n";
  }else if (0 == strcmp(method.c_str(), "POST")) {
    StringCQ += uriencode + "\n";
  }
  StringCQ += urlEncode2(query_string) + "\n";
  StringCQ += get_canonical_headers(requestHeaders) + "\n";
  StringCQ += get_sorted_header_keys(requestHeaders) + "\n";
  StringCQ += payload_hash;

  char          kSecret[128];
  unsigned char *kDate, *kRegion, *kService, *kSigning, *sRequest               = NULL;
  unsigned int  kDate_len,kRegion_len, kService_len, kSigning_len, sRequest_len = 0;
  char          hexsRequest[64 + 1];
  int           kSecret_len = snprintf(kSecret, sizeof(kSecret), "OSS4%s", OSSfsCurl::OSSSecretAccessKey.c_str());
  unsigned int  cnt;

  ossfs_HMAC256(kSecret, kSecret_len, reinterpret_cast<const unsigned char*>(strdate.data()), strdate.size(), &kDate, &kDate_len);
  ossfs_HMAC256(kDate, kDate_len, reinterpret_cast<const unsigned char*>(endpoint.c_str()), endpoint.size(), &kRegion, &kRegion_len);
  ossfs_HMAC256(kRegion, kRegion_len, reinterpret_cast<const unsigned char*>("oss"), sizeof("oss") - 1, &kService, &kService_len);
  ossfs_HMAC256(kService, kService_len, reinterpret_cast<const unsigned char*>("oss4_request"), sizeof("oss4_request") - 1, &kSigning, &kSigning_len);
  free(kDate);
  free(kRegion);
  free(kService);

  const unsigned char* cRequest     = reinterpret_cast<const unsigned char*>(StringCQ.c_str());
  unsigned int         cRequest_len = StringCQ.size();
  ossfs_sha256(cRequest, cRequest_len, &sRequest, &sRequest_len);
  for(cnt = 0; cnt < sRequest_len; cnt++){
    sprintf(&hexsRequest[cnt * 2], "%02x", sRequest[cnt]);
  }
  free(sRequest);

  StringToSign  = "OSS4-HMAC-SHA256\n";
  StringToSign += date8601 + "\n";
  StringToSign += strdate + "/" + endpoint + "/oss/oss4_request\n";
  StringToSign += hexsRequest;

  const unsigned char* cscope     = reinterpret_cast<const unsigned char*>(StringToSign.c_str());
  unsigned int         cscope_len = StringToSign.size();
  unsigned char*       md         = NULL;
  unsigned int         md_len     = 0;
  char                 hexSig[64 + 1];

  ossfs_HMAC256(kSigning, kSigning_len, cscope, cscope_len, &md, &md_len);
  for(cnt = 0; cnt < md_len; cnt++){
    sprintf(&hexSig[cnt * 2], "%02x", md[cnt]);
  }
  free(kSigning);
  free(md);

  Signature = hexSig;

  return Signature;
}

// XML in BodyData has UploadId, Parse XML body for UploadId
bool OSSfsCurl::GetUploadId(string& upload_id)
{
  bool result = false;

  if(!bodydata){
    return result;
  }
  upload_id.clear();

  xmlDocPtr doc;
  if(NULL == (doc = xmlReadMemory(bodydata->str(), bodydata->size(), "", NULL, 0))){
    return result;
  }
  if(NULL == doc->children){
    OSSFS_XMLFREEDOC(doc);
    return result;
  }
  for(xmlNodePtr cur_node = doc->children->children; NULL != cur_node; cur_node = cur_node->next){
    // For DEBUG
    // string cur_node_name(reinterpret_cast<const char *>(cur_node->name));
    // printf("cur_node_name: %s\n", cur_node_name.c_str());

    if(XML_ELEMENT_NODE == cur_node->type){
      string elementName = reinterpret_cast<const char*>(cur_node->name);
      // For DEBUG
      // printf("elementName: %s\n", elementName.c_str());

      if(cur_node->children){
        if(XML_TEXT_NODE == cur_node->children->type){
          if(elementName == "UploadId") {
            upload_id = reinterpret_cast<const char *>(cur_node->children->content);
            result    = true;
            break;
          }
        }
      }
    }
  }
  OSSFS_XMLFREEDOC(doc);

  return result;
}

void OSSfsCurl::insertV4Headers()
{
  string server_path = type == REQTYPE_LISTBUCKET ? "/" : path;
  string payload_hash;
  switch (type) {
    case REQTYPE_PUT:
      payload_hash = ossfs_sha256sum(b_infile == NULL ? -1 : fileno(b_infile), 0, -1);
      break;

    case REQTYPE_COMPLETEMULTIPOST:
    {
      unsigned int         cRequest_len = strlen(reinterpret_cast<const char *>(b_postdata));
      unsigned char*       sRequest     = NULL;
      unsigned int         sRequest_len = 0;
      char                 hexsRequest[64 + 1];
      unsigned int         cnt;
      ossfs_sha256(b_postdata, cRequest_len, &sRequest, &sRequest_len);
      for(cnt = 0; cnt < sRequest_len; cnt++){
        sprintf(&hexsRequest[cnt * 2], "%02x", sRequest[cnt]);
      }
      free(sRequest);
      payload_hash.assign(hexsRequest, &hexsRequest[sRequest_len * 2]);
      break;
    }

    case REQTYPE_UPLOADMULTIPOST:
      payload_hash = ossfs_sha256sum(partdata.fd, partdata.startpos, partdata.size);
      break;
    default:
      break;
  }

  OSSFS_PRN_INFO3("computing signature [%s] [%s] [%s] [%s]", op.c_str(), server_path.c_str(), query_string.c_str(), payload_hash.c_str());
  string strdate;
  string date8601;
  get_date_sigv3(strdate, date8601);

  string contentSHA256 = payload_hash.empty() ? empty_payload_hash : payload_hash;
  const std::string realpath = pathrequeststyle ? "/" + bucket + server_path : server_path;

  //string canonical_headers, signed_headers;
  requestHeaders = curl_slist_sort_insert(requestHeaders, "host", get_bucket_host().c_str());
  requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-content-sha256", contentSHA256.c_str());
  requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-date", date8601.c_str());
	
  if(!OSSfsCurl::IsPublicBucket()){
    string Signature = CalcSignature(op, realpath, query_string + (type == REQTYPE_PREMULTIPOST || type == REQTYPE_MULTILIST ? "=" : ""), strdate, contentSHA256, date8601);
    string auth = "OSS4-HMAC-SHA256 Credential=" + OSSAccessKeyId + "/" + strdate + "/" + endpoint +
        "/oss/oss4_request, SignedHeaders=" + get_sorted_header_keys(requestHeaders) + ", Signature=" + Signature;
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Authorization", auth.c_str());
  }
}

void OSSfsCurl::insertV2Headers()
{
  string resource;
  string turl;
  string server_path = type == REQTYPE_LISTBUCKET ? "/" : path;
  MakeUrlResource(server_path.c_str(), resource, turl);
  if(!query_string.empty() && type != REQTYPE_LISTBUCKET){
    resource += "?" + query_string;
  }

  string date    = get_date_rfc850();
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Date", date.c_str());
  if(op != "PUT" && op != "POST"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", NULL);
  }

  if(!OSSfsCurl::IsPublicBucket()){
    string Signature = CalcSignatureV2(op, get_header_value(requestHeaders, "Content-MD5"), get_header_value(requestHeaders, "Content-Type"), date, resource);
    requestHeaders   = curl_slist_sort_insert(requestHeaders, "Authorization", string("OSS " + OSSAccessKeyId + ":" + Signature).c_str());
  }
}

void OSSfsCurl::insertIBMIAMHeaders()
{
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Authorization", ("Bearer " + OSSfsCurl::OSSAccessToken).c_str());

  if(op == "PUT" && path == mount_prefix + "/"){
    // ibm-service-instance-id header is required for bucket creation requests
    requestHeaders = curl_slist_sort_insert(requestHeaders, "ibm-service-instance-id", OSSfsCurl::OSSAccessKeyId.c_str());
  }
}

void OSSfsCurl::insertAuthHeaders()
{
  if(!OSSfsCurl::CheckIAMCredentialUpdate()){
    OSSFS_PRN_ERR("An error occurred in checking IAM credential.");
    return; // do not insert auth headers on error
  }

  if(OSSfsCurl::is_ibm_iam_auth){
    insertIBMIAMHeaders();
  }else if(!OSSfsCurl::is_sigv4){
    insertV2Headers();
  }else{
    insertV4Headers();
  }
}

int OSSfsCurl::DeleteRequest(const char* tpath)
{
  OSSFS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(!CreateCurlHandle()){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  requestHeaders  = NULL;
  responseHeaders.clear();

  op = "DELETE";
  type = REQTYPE_DELETE;
  insertAuthHeaders();

  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_CUSTOMREQUEST, "DELETE");
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
  OSSfsCurl::AddUserAgent(hCurl);        // put User-Agent

  return RequestPerform();
}

//
// Get AccessKeyId/SecretAccessKey/AccessToken/Expiration by IAM role,
// and Set these value to class variable.
//
int OSSfsCurl::GetIAMCredentials()
{
  if (!OSSfsCurl::is_ecs && !OSSfsCurl::is_ibm_iam_auth) {
    OSSFS_PRN_INFO3("[IAM role=%s]", OSSfsCurl::IAM_role.c_str());

    if(OSSfsCurl::IAM_role.empty()) {
      OSSFS_PRN_ERR("IAM role name is empty.");
      return -EIO;
    }
  }

  // at first set type for handle
  type = REQTYPE_IAMCRED;

  if(!CreateCurlHandle()){
    return -EIO;
  }

  // url
  if (is_ecs) {
    url = string(OSSfsCurl::IAM_cred_url) + std::getenv(ECS_IAM_ENV_VAR.c_str());
  }
  else {
    url = string(OSSfsCurl::IAM_cred_url) + OSSfsCurl::IAM_role;
  }

  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();
  string postContent;

  if(OSSfsCurl::is_ibm_iam_auth){
    url = string(OSSfsCurl::IAM_cred_url);

    // make contents
    postContent += "grant_type=urn:ibm:params:oauth:grant-type:apikey";
    postContent += "&response_type=cloud_iam";
    postContent += "&apikey=" + OSSfsCurl::OSSSecretAccessKey;

    // set postdata
    postdata             = reinterpret_cast<const unsigned char*>(postContent.c_str());
    b_postdata           = postdata;
    postdata_remaining   = postContent.size(); // without null
    b_postdata_remaining = postdata_remaining;

    requestHeaders = curl_slist_sort_insert(requestHeaders, "Authorization", "Basic Yng6Yng=");

    curl_easy_setopt(hCurl, CURLOPT_POST, true);              // POST
    curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, static_cast<curl_off_t>(postdata_remaining));
    curl_easy_setopt(hCurl, CURLOPT_READDATA, (void*)this);
    curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, OSSfsCurl::ReadCallback);
  }

  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
  OSSfsCurl::AddUserAgent(hCurl);        // put User-Agent

  int result = RequestPerform();

  // analyzing response
  if(0 == result && !OSSfsCurl::SetIAMCredentials(bodydata->str())){
    OSSFS_PRN_ERR("Something error occurred, could not get IAM credential.");
    result = -EIO;
  }
  delete bodydata;
  bodydata = NULL;

  return result;
}

//
// Get IAM role name automatically.
//
bool OSSfsCurl::LoadIAMRoleFromMetaData()
{
  OSSFS_PRN_INFO3("Get IAM Role name");

  // at first set type for handle
  type = REQTYPE_IAMROLE;

  if(!CreateCurlHandle()){
    return false;
  }

  // url
  url             = string(OSSfsCurl::IAM_cred_url);
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  OSSfsCurl::AddUserAgent(hCurl);        // put User-Agent

  int result = RequestPerform();

  // analyzing response
  if(0 == result && !OSSfsCurl::SetIAMRoleFromMetaData(bodydata->str())){
    OSSFS_PRN_ERR("Something error occurred, could not get IAM role name.");
    result = -EIO;
  }
  delete bodydata;
  bodydata = NULL;

  return (0 == result);
}

bool OSSfsCurl::AddSseRequestHead(sse_type_t ssetype, string& ssevalue, bool is_only_c, bool is_copy)
{
  // TODO: encryption support in rgw
  return false;
  if(SSE_OSS == ssetype){
    if(!is_only_c){
      requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-server-side-encryption", "AES256");
    }
  }else if(SSE_C == ssetype){
    string sseckey;
    if(OSSfsCurl::GetSseKey(ssevalue, sseckey)){
      if(is_copy){
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-copy-source-server-side-encryption-customer-algorithm", "AES256");
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-copy-source-server-side-encryption-customer-key",       sseckey.c_str());
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-copy-source-server-side-encryption-customer-key-md5",   ssevalue.c_str());
      }else{
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-server-side-encryption-customer-algorithm", "AES256");
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-server-side-encryption-customer-key",       sseckey.c_str());
        requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-server-side-encryption-customer-key-md5",   ssevalue.c_str());
      }
    }else{
      OSSFS_PRN_WARN("Failed to insert SSE-C header.");
    }

  }else if(SSE_KMS == ssetype){
    if(!is_only_c){
      if(ssevalue.empty()){
        ssevalue = OSSfsCurl::GetSseKmsId();
      }
      requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-server-side-encryption", "oss:kms");
      requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-server-side-encryption-oss-kms-key-id", ssevalue.c_str());
    }
  }
  return true;
}

//
// tpath :      target path for head request
// bpath :      saved into base_path
// savedpath :  saved into saved_path
// ssekey_pos : -1    means "not" SSE-C type
//              0 - X means SSE-C type and position for SSE-C key(0 is latest key)
//
bool OSSfsCurl::PreHeadRequest(const char* tpath, const char* bpath, const char* savedpath, int ssekey_pos)
{
  OSSFS_PRN_INFO3("[tpath=%s][bpath=%s][save=%s][sseckeypos=%d]", SAFESTRPTR(tpath), SAFESTRPTR(bpath), SAFESTRPTR(savedpath), ssekey_pos);

  if(!tpath){
    return false;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  // libcurl 7.17 does deep copy of url, deep copy "stable" url
  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  base_path       = SAFESTRPTR(bpath);
  saved_path      = SAFESTRPTR(savedpath);
  requestHeaders  = NULL;
  responseHeaders.clear();

  // requestHeaders
  if(0 <= ssekey_pos){
    string md5;
    if(!OSSfsCurl::GetSseKeyMd5(ssekey_pos, md5) || !AddSseRequestHead(SSE_C, md5, true, false)){
      OSSFS_PRN_ERR("Failed to set SSE-C headers for sse-c key pos(%d)(=md5(%s)).", ssekey_pos, md5.c_str());
      return false;
    }
  }
  b_ssekey_pos = ssekey_pos;

  op = "HEAD";
  type = REQTYPE_HEAD;
  insertAuthHeaders();

  // set lazy function
  fpLazySetup = PreHeadRequestSetCurlOpts;

  return true;
}

int OSSfsCurl::HeadRequest(const char* tpath, headers_t& meta)
{
  int result = -1;

  OSSFS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

  // At first, try to get without SSE-C headers
  if(!PreHeadRequest(tpath) || !fpLazySetup || !fpLazySetup(this) || 0 != (result = RequestPerform())){
    // If has SSE-C keys, try to get with all SSE-C keys.
    for(int pos = 0; static_cast<size_t>(pos) < OSSfsCurl::sseckeys.size(); pos++){
      if(!DestroyCurlHandle()){
        break;
      }
      if(!PreHeadRequest(tpath, NULL, NULL, pos)){
        break;
      }
      if(!fpLazySetup || !fpLazySetup(this)){
        OSSFS_PRN_ERR("Failed to lazy setup in single head request.");
        break;
      }
      if(0 == (result = RequestPerform())){
        break;
      }
    }
    if(0 != result){
      DestroyCurlHandle();  // not check result.
      return result;
    }
  }

  // file exists in oss
  // fixme: clean this up.
  meta.clear();
  for(headers_t::iterator iter = responseHeaders.begin(); iter != responseHeaders.end(); ++iter){
    string key   = lower(iter->first);
    string value = iter->second;
    if(key == "content-type"){
      meta[iter->first] = value;
    }else if(key == "content-length"){
      meta[iter->first] = value;
    }else if(key == "etag"){
      meta[iter->first] = value;
    }else if(key == "last-modified"){
      meta[iter->first] = value;
    }else if(key.substr(0, 5) == "x-oss"){
      meta[key] = value;		// key is lower case for "x-oss"
    }
  }
  return 0;
}

int OSSfsCurl::PutHeadRequest(const char* tpath, headers_t& meta, bool is_copy)
{
  OSSFS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(!CreateCurlHandle()){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  // Make request headers
  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string key   = lower(iter->first);
    string value = iter->second;
    if(key == "content-type"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key.substr(0, 9) == "x-oss-acl"){
      // not set value, but after set it.
    }else if(key.substr(0, 10) == "x-oss-meta"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key == "x-oss-copy-source"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key == "x-oss-server-side-encryption"){
	  //XXX
	  //requestHeaders = curl_slist_sort_insert(requestHeaders, string(key + ":" + value).c_str());
      // Only copy mode.
      if(is_copy && !AddSseRequestHead(SSE_OSS, value, false, true)){
        OSSFS_PRN_WARN("Failed to insert SSE-OSS header.");
      }
    }else if(key == "x-oss-server-side-encryption-customer-algorithm"){
      // Only copy mode.
      if(is_copy && !value.empty() && !AddSseRequestHead(SSE_KMS, value, false, true)){
        OSSFS_PRN_WARN("Failed to insert SSE-KMS header.");
      }
    }else if(key == "x-oss-server-side-encryption-customer-key-md5"){
      // Only copy mode.
      if(is_copy){
        if(!AddSseRequestHead(SSE_C, value, true, true) || !AddSseRequestHead(SSE_C, value, true, false)){
          OSSFS_PRN_WARN("Failed to insert SSE-C header.");
        }
      }
    }
  }

  // "x-oss-acl", storage class, sse
  if(!OSSfsCurl::default_acl.empty()){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-acl", OSSfsCurl::default_acl.c_str());
  }
  // TODO: storage_class
  // if(REDUCED_REDUNDANCY == GetStorageClass()){
  //   requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-storage-class", "REDUCED_REDUNDANCY");
  // } else if(STANDARD_IA == GetStorageClass()){
  //   requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-storage-class", "STANDARD_IA");
  // } else if(ONEZONE_IA == GetStorageClass()){
  //   requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-storage-class", "ONEZONE_IA");
  // }
  // SSE
  if(!is_copy){
    string ssevalue;
    if(!AddSseRequestHead(OSSfsCurl::GetSseType(), ssevalue, false, false)){
      OSSFS_PRN_WARN("Failed to set SSE header, but continue...");
    }
  }
  if(is_use_ahbe){
    // set additional header by ahbe conf
    requestHeaders = AdditionalHeader::get()->AddHeader(requestHeaders, tpath);
  }

  op = "PUT";
  type = REQTYPE_PUTHEAD;
  insertAuthHeaders();

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);                // HTTP PUT
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0);               // Content-Length
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
  OSSfsCurl::AddUserAgent(hCurl);                                // put User-Agent

  OSSFS_PRN_INFO3("copying... [path=%s]", tpath);

  int result = RequestPerform();
  if(0 == result){
    // PUT returns 200 status code with something error, thus
    // we need to check body.
    //
    // example error body:
    //     <?xml version="1.0" encoding="UTF-8"?>
    //     <Error>
    //       <Code>AccessDenied</Code>
    //       <Message>Access Denied</Message>
    //       <RequestId>E4CA6F6767D6685C</RequestId>
    //       <HostId>BHzLOATeDuvN8Es1wI8IcERq4kl4dc2A9tOB8Yqr39Ys6fl7N4EJ8sjGiVvu6wLP</HostId>
    //     </Error>
    //
    const char* pstrbody = bodydata->str();
    if(!pstrbody || NULL != strcasestr(pstrbody, "<Error>")){
      OSSFS_PRN_ERR("PutHeadRequest get 200 status response, but it included error body(or NULL). The request failed during copying the object in OSS.");
      OSSFS_PRN_DBG("PutHeadRequest Response Body : %s", (pstrbody ? pstrbody : "(null)"));
      result = -EIO;
    }
  }
  delete bodydata;
  bodydata = NULL;

  return result;
}

int OSSfsCurl::PutRequest(const char* tpath, headers_t& meta, int fd)
{
  struct stat st;
  FILE*       file = NULL;

  OSSFS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(-1 != fd){
    // duplicate fd
    int fd2;
    if(-1 == (fd2 = dup(fd)) || -1 == fstat(fd2, &st) || 0 != lseek(fd2, 0, SEEK_SET) || NULL == (file = fdopen(fd2, "rb"))){
      OSSFS_PRN_ERR("Could not duplicate file descriptor(errno=%d)", errno);
      if(-1 != fd2){
        close(fd2);
      }
      return -errno;
    }
    b_infile = file;
  }else{
    // This case is creating zero byte object.(calling by create_file_object())
    OSSFS_PRN_INFO3("create zero byte file object.");
  }

  if(!CreateCurlHandle()){
    if(file){
      fclose(file);
    }
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  // Make request headers
  string strMD5;
  if(-1 != fd && OSSfsCurl::is_content_md5){
    strMD5         = ossfs_get_content_md5(fd);
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-MD5", strMD5.c_str());
  }

  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string key   = lower(iter->first);
    string value = iter->second;
    if(key == "content-type"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key.substr(0, 9) == "x-oss-acl"){
      // not set value, but after set it.
    }else if(key.substr(0, 10) == "x-oss-meta"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key == "x-oss-server-side-encryption" && value != "oss:kms"){
      // skip this header, because this header is specified after logic.
    }else if(key == "x-oss-server-side-encryption-oss-kms-key-id"){
      // skip this header, because this header is specified after logic.
    }else if(key == "x-oss-server-side-encryption-customer-key-md5"){
      // skip this header, because this header is specified after logic.
    }
  }
  // "x-oss-acl", storage class, sse
  if(!OSSfsCurl::default_acl.empty()){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-acl", OSSfsCurl::default_acl.c_str());
  }
  // TODO: storage_class
  // if(REDUCED_REDUNDANCY == GetStorageClass()){
  //   requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-storage-class", "REDUCED_REDUNDANCY");
  // } else if(STANDARD_IA == GetStorageClass()){
  //   requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-storage-class", "STANDARD_IA");
  // } else if(ONEZONE_IA == GetStorageClass()){
  //   requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-storage-class", "ONEZONE_IA");
  // }
  // SSE
  string ssevalue;
  if(!AddSseRequestHead(OSSfsCurl::GetSseType(), ssevalue, false, false)){
    OSSFS_PRN_WARN("Failed to set SSE header, but continue...");
  }
  if(is_use_ahbe){
    // set additional header by ahbe conf
    requestHeaders = AdditionalHeader::get()->AddHeader(requestHeaders, tpath);
  }

  op = "PUT";
  type = REQTYPE_PUT;
  insertAuthHeaders();

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_UPLOAD, true);                // HTTP PUT
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
  if(file){
    curl_easy_setopt(hCurl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(st.st_size)); // Content-Length
    curl_easy_setopt(hCurl, CURLOPT_INFILE, file);
  }else{
    curl_easy_setopt(hCurl, CURLOPT_INFILESIZE, 0);             // Content-Length: 0
  }
  OSSfsCurl::AddUserAgent(hCurl);                                // put User-Agent

  OSSFS_PRN_INFO3("uploading... [path=%s][fd=%d][size=%jd]", tpath, fd, (intmax_t)(-1 != fd ? st.st_size : 0));

  int result = RequestPerform();
  delete bodydata;
  bodydata = NULL;
  if(file){
    fclose(file);
  }

  return result;
}

int OSSfsCurl::PreGetObjectRequest(const char* tpath, int fd, off_t start, ssize_t size, sse_type_t ssetype, string& ssevalue)
{
  OSSFS_PRN_INFO3("[tpath=%s][start=%jd][size=%jd]", SAFESTRPTR(tpath), (intmax_t)start, (intmax_t)size);

  if(!tpath || -1 == fd || 0 > start || 0 > size){
    return -1;
  }

  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  requestHeaders  = NULL;
  responseHeaders.clear();

  if(-1 != start && 0 < size){
    string range = "bytes=";
    range       += str(start);
    range       += "-";
    range       += str(start + size - 1);
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Range", range.c_str());
  }
  // SSE
  if(!AddSseRequestHead(ssetype, ssevalue, true, false)){
    OSSFS_PRN_WARN("Failed to set SSE header, but continue...");
  }

  op = "GET";
  type = REQTYPE_GET;
  insertAuthHeaders();

  // set lazy function
  fpLazySetup = PreGetObjectRequestSetCurlOpts;

  // set info for callback func.
  // (use only fd, startpos and size, other member is not used.)
  partdata.clear();
  partdata.fd         = fd;
  partdata.startpos   = start;
  partdata.size       = size;
  b_partdata_startpos = start;
  b_partdata_size     = size;
  b_ssetype           = ssetype;
  b_ssevalue          = ssevalue;
  b_ssekey_pos        = -1;         // not use this value for get object.

  return 0;
}

int OSSfsCurl::GetObjectRequest(const char* tpath, int fd, off_t start, ssize_t size)
{
  int result;

  OSSFS_PRN_INFO3("[tpath=%s][start=%jd][size=%jd]", SAFESTRPTR(tpath), (intmax_t)start, (intmax_t)size);

  if(!tpath){
    return -1;
  }
  sse_type_t ssetype;
  string     ssevalue;
  if(!get_object_sse_type(tpath, ssetype, ssevalue)){
    OSSFS_PRN_WARN("Failed to get SSE type for file(%s).", SAFESTRPTR(tpath));
  }

  if(0 != (result = PreGetObjectRequest(tpath, fd, start, size, ssetype, ssevalue))){
    return result;
  }
  if(!fpLazySetup || !fpLazySetup(this)){
    OSSFS_PRN_ERR("Failed to lazy setup in single get object request.");
    return -1;
  }

  OSSFS_PRN_INFO3("downloading... [path=%s][fd=%d]", tpath, fd);

  result = RequestPerform();
  partdata.clear();

  return result;
}

int OSSfsCurl::CheckBucket()
{
  OSSFS_PRN_INFO3("check a bucket.");

  if(!CreateCurlHandle()){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath("/").c_str(), resource, turl);

  url             = prepare_url(turl.c_str());
  path            = get_realpath("/");
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  op = "GET";
  type = REQTYPE_CHKBUCKET;
  insertAuthHeaders();

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
  OSSfsCurl::AddUserAgent(hCurl);        // put User-Agent

  int result = RequestPerform();
  if (result != 0) {
    OSSFS_PRN_ERR("Check bucket failed, OSS response: %s", (bodydata ? bodydata->str() : ""));
  }
  return result;
}

int OSSfsCurl::ListBucketRequest(const char* tpath, const char* query)
{
  OSSFS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(!CreateCurlHandle()){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource("", resource, turl);    // NOTICE: path is "".
  if(query){
    turl += "?";
    turl += query;
    query_string = query;
  }

  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  op = "GET";
  type = REQTYPE_LISTBUCKET;
  insertAuthHeaders();

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
  OSSfsCurl::AddUserAgent(hCurl);        // put User-Agent

  return RequestPerform();
}

//
// Initialize multipart upload
//
// Example :
//   POST /example-object?uploads HTTP/1.1
//   Host: example-bucket.cn-north-3.inspurcloudoss.com
//   Date: Mon, 1 Nov 2010 20:34:56 GMT
//   Authorization: OSS VGhpcyBtZXNzYWdlIHNpZ25lZCBieSBlbHZpbmc=
//
int OSSfsCurl::PreMultipartPostRequest(const char* tpath, headers_t& meta, string& upload_id, bool is_copy)
{
  OSSFS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(!CreateCurlHandle()){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  query_string   = "uploads";
  turl          += "?" + query_string;
  url            = prepare_url(turl.c_str());
  path           = get_realpath(tpath);
  requestHeaders = NULL;
  bodydata       = new BodyData();
  responseHeaders.clear();

  string contype = OSSfsCurl::LookupMimeType(string(tpath));

  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string key   = lower(iter->first);
    string value = iter->second;
    if(key.substr(0, 9) == "x-oss-acl"){
      // not set value, but after set it.
    }else if(key.substr(0, 10) == "x-oss-meta"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key == "x-oss-server-side-encryption" && value != "oss:kms"){
      // Only copy mode.
      if(is_copy && !AddSseRequestHead(SSE_OSS, value, false, true)){
        OSSFS_PRN_WARN("Failed to insert SSE-OSS header.");
      }
    }else if(key == "x-oss-server-side-encryption-oss-kms-key-id"){
      // Only copy mode.
      if(is_copy && !value.empty() && !AddSseRequestHead(SSE_KMS, value, false, true)){
        OSSFS_PRN_WARN("Failed to insert SSE-KMS header.");
      }
    }else if(key == "x-oss-server-side-encryption-customer-key-md5"){
      // Only copy mode.
      if(is_copy){
        if(!AddSseRequestHead(SSE_C, value, true, true) || !AddSseRequestHead(SSE_C, value, true, false)){
          OSSFS_PRN_WARN("Failed to insert SSE-C header.");
        }
      }
    }
  }
  // "x-oss-acl", storage class, sse
  if(!OSSfsCurl::default_acl.empty()){
    requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-acl", OSSfsCurl::default_acl.c_str());
  }
  // TODO: storage_class
  // if(REDUCED_REDUNDANCY == GetStorageClass()){
  //   requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-storage-class", "REDUCED_REDUNDANCY");
  // } else if(STANDARD_IA == GetStorageClass()){
  //   requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-storage-class", "STANDARD_IA");
  // } else if(ONEZONE_IA == GetStorageClass()){
  //   requestHeaders = curl_slist_sort_insert(requestHeaders, "x-oss-storage-class", "ONEZONE_IA");
  // }
  // SSE
  if(!is_copy){
    string ssevalue;
    if(!AddSseRequestHead(OSSfsCurl::GetSseType(), ssevalue, false, false)){
      OSSFS_PRN_WARN("Failed to set SSE header, but continue...");
    }
  }
  if(is_use_ahbe){
    // set additional header by ahbe conf
    requestHeaders = AdditionalHeader::get()->AddHeader(requestHeaders, tpath);
  }

  requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", NULL);
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Length", NULL);
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());

  op = "POST";
  type = REQTYPE_PREMULTIPOST;
  insertAuthHeaders();

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_POST, true);              // POST
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, 0);
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
  OSSfsCurl::AddUserAgent(hCurl);                            // put User-Agent

  // request
  int result;
  if(0 != (result = RequestPerform())){
    delete bodydata;
    bodydata = NULL;
    return result;
  }

  // Parse XML body for UploadId
  if(!OSSfsCurl::GetUploadId(upload_id)){
    delete bodydata;
    bodydata = NULL;
    return -1;
  }

  delete bodydata;
  bodydata = NULL;
  return 0;
}

int OSSfsCurl::CompleteMultipartPostRequest(const char* tpath, string& upload_id, etaglist_t& parts)
{
  OSSFS_PRN_INFO3("[tpath=%s][parts=%zu]", SAFESTRPTR(tpath), parts.size());

  if(!tpath){
    return -1;
  }

  // make contents
  string postContent;
  postContent += "<CompleteMultipartUpload>\n";
  for(int cnt = 0; cnt < (int)parts.size(); cnt++){
    if(0 == parts[cnt].length()){
      OSSFS_PRN_ERR("%d file part is not finished uploading.", cnt + 1);
      return -1;
    }
    postContent += "<Part>\n";
    postContent += "  <PartNumber>" + str(cnt + 1) + "</PartNumber>\n";
    postContent += "  <ETag>" + parts[cnt] + "</ETag>\n";
    postContent += "</Part>\n";
  }  
  postContent += "</CompleteMultipartUpload>\n";

  // set postdata
  postdata             = reinterpret_cast<const unsigned char*>(postContent.c_str());
  b_postdata           = postdata;
  postdata_remaining   = postContent.size(); // without null
  b_postdata_remaining = postdata_remaining;

  if(!CreateCurlHandle()){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  query_string         = "uploadId=" + upload_id;
  turl                += "?" + query_string;
  url                  = prepare_url(turl.c_str());
  path                 = get_realpath(tpath);
  requestHeaders       = NULL;
  bodydata             = new BodyData();
  responseHeaders.clear();
  string contype       = OSSfsCurl::LookupMimeType(string(tpath));

  requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", NULL);
  requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-Type", contype.c_str());

  op = "POST";
  type = REQTYPE_COMPLETEMULTIPOST;
  insertAuthHeaders();

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
  curl_easy_setopt(hCurl, CURLOPT_POST, true);              // POST
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_POSTFIELDSIZE, static_cast<curl_off_t>(postdata_remaining));
  curl_easy_setopt(hCurl, CURLOPT_READDATA, (void*)this);
  curl_easy_setopt(hCurl, CURLOPT_READFUNCTION, OSSfsCurl::ReadCallback);
  OSSfsCurl::AddUserAgent(hCurl);                            // put User-Agent

  // request
  int result = RequestPerform();
  delete bodydata;
  bodydata = NULL;
  postdata = NULL;

  return result;
}

int OSSfsCurl::MultipartListRequest(string& body)
{
  OSSFS_PRN_INFO3("list request(multipart)");

  if(!CreateCurlHandle()){
    return -1;
  }
  string resource;
  string turl;
  path            = get_realpath("/");
  MakeUrlResource(path.c_str(), resource, turl);

  query_string    = "uploads";
  turl           += "?" + query_string;
  url             = prepare_url(turl.c_str());
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();

  requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", NULL);

  op = "GET";
  type = REQTYPE_MULTILIST;
  insertAuthHeaders();

  // setopt
  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, (void*)bodydata);
  curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
  OSSfsCurl::AddUserAgent(hCurl);        // put User-Agent

  int result;
  if(0 == (result = RequestPerform()) && 0 < bodydata->size()){
    body = bodydata->str();
  }else{
    body = "";
  }
  delete bodydata;
  bodydata = NULL;

  return result;
}

int OSSfsCurl::AbortMultipartUpload(const char* tpath, string& upload_id)
{
  OSSFS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

  if(!tpath){
    return -1;
  }
  if(!CreateCurlHandle()){
    return -1;
  }
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  query_string    = "uploadId=" + upload_id;
  turl           += "?" + query_string;
  url             = prepare_url(turl.c_str());
  path            = get_realpath(tpath);
  requestHeaders  = NULL;
  responseHeaders.clear();

  op = "DELETE";
  type = REQTYPE_ABORTMULTIUPLOAD;
  insertAuthHeaders();

  curl_easy_setopt(hCurl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(hCurl, CURLOPT_CUSTOMREQUEST, "DELETE");
  curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, requestHeaders);
  OSSfsCurl::AddUserAgent(hCurl);        // put User-Agent

  return RequestPerform();
}

//
// PUT /ObjectName?partNumber=PartNumber&uploadId=UploadId HTTP/1.1
// Host: BucketName.cn-north-3.inspurcloudoss.com
// Date: date
// Content-Length: Size
// Authorization: Signature
//
// PUT /my-movie.m2ts?partNumber=1&uploadId=VCVsb2FkIElEIGZvciBlbZZpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZR HTTP/1.1
// Host: example-bucket.cn-north-3.inspurcloudoss.com
// Date:  Mon, 1 Nov 2010 20:34:56 GMT
// Content-Length: 10485760
// Content-MD5: pUNXr/BjKK5G2UKvaRRrOA==
// Authorization: OSS VGhpcyBtZXNzYWdlIHNpZ25lZGGieSRlbHZpbmc=
//

int OSSfsCurl::UploadMultipartPostSetup(const char* tpath, int part_num, const string& upload_id)
{
  OSSFS_PRN_INFO3("[tpath=%s][start=%jd][size=%jd][part=%d]", SAFESTRPTR(tpath), (intmax_t)(partdata.startpos), (intmax_t)(partdata.size), part_num);

  if(-1 == partdata.fd || -1 == partdata.startpos || -1 == partdata.size){
    return -1;
  }

  requestHeaders = NULL;

  // make md5 and file pointer
  if(OSSfsCurl::is_content_md5){
    unsigned char *md5raw = ossfs_md5hexsum(partdata.fd, partdata.startpos, partdata.size);
    if(md5raw == NULL){
      OSSFS_PRN_ERR("Could not make md5 for file(part %d)", part_num);
      return -1;
    }
    partdata.etag = ossfs_hex(md5raw, get_md5_digest_length());
    char* md5base64p = ossfs_base64(md5raw, get_md5_digest_length());
    requestHeaders = curl_slist_sort_insert(requestHeaders, "Content-MD5", md5base64p);
    free(md5base64p);
    free(md5raw);
  }

  // make request
  query_string        = "partNumber=" + str(part_num) + "&uploadId=" + upload_id;
  string urlargs      = "?" + query_string;
  string resource;
  string turl;
  MakeUrlResource(get_realpath(tpath).c_str(), resource, turl);

  turl              += urlargs;
  url                = prepare_url(turl.c_str());
  path               = get_realpath(tpath);
  bodydata           = new BodyData();
  headdata           = new BodyData();
  responseHeaders.clear();

  // SSE
  if(SSE_C == OSSfsCurl::GetSseType()){
    string ssevalue;
    if(!AddSseRequestHead(OSSfsCurl::GetSseType(), ssevalue, false, false)){
      OSSFS_PRN_WARN("Failed to set SSE header, but continue...");
    }
  }

  requestHeaders = curl_slist_sort_insert(requestHeaders, "Accept", NULL);

  op = "PUT";
  type = REQTYPE_UPLOADMULTIPOST;
  insertAuthHeaders();

  // set lazy function
  fpLazySetup = UploadMultipartPostSetCurlOpts;

  return 0;
}

int OSSfsCurl::UploadMultipartPostRequest(const char* tpath, int part_num, const string& upload_id)
{
  int result;

  OSSFS_PRN_INFO3("[tpath=%s][start=%jd][size=%jd][part=%d]", SAFESTRPTR(tpath), (intmax_t)(partdata.startpos), (intmax_t)(partdata.size), part_num);

  // setup
  if(0 != (result = OSSfsCurl::UploadMultipartPostSetup(tpath, part_num, upload_id))){
    return result;
  }

  // request
  if(0 == (result = RequestPerform())){
    // UploadMultipartPostComplete returns true on success -> convert to 0
    result = !UploadMultipartPostComplete();
  }

  // closing
  delete bodydata;
  bodydata = NULL;
  delete headdata;
  headdata = NULL;

  return result;
}

int OSSfsCurl::CopyMultipartPostSetup(const char* from, const char* to, int part_num, string& upload_id, headers_t& meta)
{
  OSSFS_PRN_INFO3("[from=%s][to=%s][part=%d]", SAFESTRPTR(from), SAFESTRPTR(to), part_num);

  if(!from || !to){
    return -1;
  }
  query_string       = "partNumber=" + str(part_num) + "&uploadId=" + upload_id;
  string urlargs     = "?" + query_string;
  string resource;
  string turl;
  MakeUrlResource(get_realpath(to).c_str(), resource, turl);

  turl           += urlargs;
  url             = prepare_url(turl.c_str());
  path            = get_realpath(to);
  requestHeaders  = NULL;
  responseHeaders.clear();
  bodydata        = new BodyData();
  headdata        = new BodyData();

  // Make request headers
  for(headers_t::iterator iter = meta.begin(); iter != meta.end(); ++iter){
    string key   = lower(iter->first);
    string value = iter->second;
    if(key == "content-type"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key == "x-oss-copy-source"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }else if(key == "x-oss-copy-source-range"){
      requestHeaders = curl_slist_sort_insert(requestHeaders, iter->first.c_str(), value.c_str());
    }
    // NOTICE: x-oss-acl, x-oss-server-side-encryption is not set!
  }

  op = "PUT";
  type = REQTYPE_COPYMULTIPOST;
  insertAuthHeaders();

  // set lazy function
  fpLazySetup = CopyMultipartPostSetCurlOpts;

  // request
  OSSFS_PRN_INFO3("copying... [from=%s][to=%s][part=%d]", from, to, part_num);

  return 0;
}

bool OSSfsCurl::UploadMultipartPostComplete()
{
  headers_t::iterator it = responseHeaders.find("ETag");
  if (it == responseHeaders.end()) {
    return false;
  }

  // check etag(md5);
  //
  // The ETAG when using SSE_C and SSE_KMS does not reflect the MD5 we sent  
  // SSE_C: https://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUT.html
  // SSE_KMS is ignored in the above, but in the following it states the same in the highlights:  
  // https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html
  //
  if(OSSfsCurl::is_content_md5 && SSE_C != OSSfsCurl::GetSseType() && SSE_KMS != OSSfsCurl::GetSseType()){
    if(!etag_equals(it->second, partdata.etag)){
      return false;
    }
  }
  partdata.etaglist->at(partdata.etagpos).assign(it->second);
  partdata.uploaded = true;

  return true;
}

bool OSSfsCurl::CopyMultipartPostCallback(OSSfsCurl* ossfscurl)
{
  if(!ossfscurl){
    return false;
  }

  return ossfscurl->CopyMultipartPostComplete();
}

bool OSSfsCurl::CopyMultipartPostComplete()
{
  // parse ETag from response
  xmlDocPtr doc;
  if(NULL == (doc = xmlReadMemory(bodydata->str(), bodydata->size(), "", NULL, 0))){
    return false;
  }
  if(NULL == doc->children){
    OSSFS_XMLFREEDOC(doc);
    return false;
  }
  for(xmlNodePtr cur_node = doc->children->children; NULL != cur_node; cur_node = cur_node->next){
    if(XML_ELEMENT_NODE == cur_node->type){
      string elementName = reinterpret_cast<const char*>(cur_node->name);
      if(cur_node->children){
        if(XML_TEXT_NODE == cur_node->children->type){
          if(elementName == "ETag") {
            string etag = reinterpret_cast<const char *>(cur_node->children->content);
            if(etag.size() >= 2 && *etag.begin() == '"' && *etag.rbegin() == '"'){
              etag.assign(etag.substr(1, etag.size() - 2));
            }
            partdata.etaglist->at(partdata.etagpos).assign(etag);
            partdata.uploaded = true;
          }
        }
      }
    }
  }
  OSSFS_XMLFREEDOC(doc);

  delete bodydata;
  bodydata = NULL;
  delete headdata;
  headdata = NULL;

  return true;
}

int OSSfsCurl::MultipartHeadRequest(const char* tpath, off_t size, headers_t& meta, bool is_copy)
{
  int            result;
  string         upload_id;
  off_t          chunk;
  off_t          bytes_remaining;
  etaglist_t     list;
  ostringstream  strrange;

  OSSFS_PRN_INFO3("[tpath=%s]", SAFESTRPTR(tpath));

  if(0 != (result = PreMultipartPostRequest(tpath, meta, upload_id, is_copy))){
    return result;
  }
  DestroyCurlHandle();

  for(bytes_remaining = size, chunk = 0; 0 < bytes_remaining; bytes_remaining -= chunk){
    chunk = bytes_remaining > MAX_MULTI_COPY_SOURCE_SIZE ? MAX_MULTI_COPY_SOURCE_SIZE : bytes_remaining;

    strrange << "bytes=" << (size - bytes_remaining) << "-" << (size - bytes_remaining + chunk - 1);
    meta["x-oss-copy-source-range"] = strrange.str();
    strrange.str("");
    strrange.clear(stringstream::goodbit);

    if(0 != (result = CopyMultipartPostSetup(tpath, tpath, (list.size() + 1), upload_id, meta))){
      return result;
    }
    list.push_back(partdata.etag);
    DestroyCurlHandle();
  }

  if(0 != (result = CompleteMultipartPostRequest(tpath, upload_id, list))){
    return result;
  }
  return 0;
}

int OSSfsCurl::MultipartUploadRequest(const char* tpath, headers_t& meta, int fd, bool is_copy)
{
  int            result;
  string         upload_id;
  struct stat    st;
  int            fd2;
  etaglist_t     list;
  off_t          remaining_bytes;
  off_t          chunk;

  OSSFS_PRN_INFO3("[tpath=%s][fd=%d]", SAFESTRPTR(tpath), fd);

  // duplicate fd
  if(-1 == (fd2 = dup(fd)) || 0 != lseek(fd2, 0, SEEK_SET)){
    OSSFS_PRN_ERR("Could not duplicate file descriptor(errno=%d)", errno);
    if(-1 != fd2){
      close(fd2);
    }
    return -errno;
  }
  if(-1 == fstat(fd2, &st)){
    OSSFS_PRN_ERR("Invalid file descriptor(errno=%d)", errno);
    close(fd2);
    return -errno;
  }

  if(0 != (result = PreMultipartPostRequest(tpath, meta, upload_id, is_copy))){
    close(fd2);
    return result;
  }
  DestroyCurlHandle();

  // cycle through open fd, pulling off 10MB chunks at a time
  for(remaining_bytes = st.st_size; 0 < remaining_bytes; remaining_bytes -= chunk){
    // chunk size
    chunk = remaining_bytes > OSSfsCurl::multipart_size ? OSSfsCurl::multipart_size : remaining_bytes;

    // set
    partdata.fd         = fd2;
    partdata.startpos   = st.st_size - remaining_bytes;
    partdata.size       = chunk;
    b_partdata_startpos = partdata.startpos;
    b_partdata_size     = partdata.size;
    partdata.add_etag_list(&list);

    // upload part
    if(0 != (result = UploadMultipartPostRequest(tpath, list.size(), upload_id))){
      OSSFS_PRN_ERR("failed uploading part(%d)", result);
      close(fd2);
      return result;
    }
    DestroyCurlHandle();
  }
  close(fd2);

  if(0 != (result = CompleteMultipartPostRequest(tpath, upload_id, list))){
    return result;
  }
  return 0;
}

int OSSfsCurl::MultipartUploadRequest(const string& upload_id, const char* tpath, int fd, off_t offset, size_t size, etaglist_t& list)
{
  OSSFS_PRN_INFO3("[upload_id=%s][tpath=%s][fd=%d][offset=%jd][size=%jd]", upload_id.c_str(), SAFESTRPTR(tpath), fd, (intmax_t)offset, (intmax_t)size);

  // duplicate fd
  int fd2;
  if(-1 == (fd2 = dup(fd)) || 0 != lseek(fd2, 0, SEEK_SET)){
    OSSFS_PRN_ERR("Could not duplicate file descriptor(errno=%d)", errno);
    if(-1 != fd2){
      close(fd2);
    }
    return -errno;
  }

  // set
  partdata.fd         = fd2;
  partdata.startpos   = offset;
  partdata.size       = size;
  b_partdata_startpos = partdata.startpos;
  b_partdata_size     = partdata.size;
  partdata.add_etag_list(&list);

  // upload part
  int   result;
  if(0 != (result = UploadMultipartPostRequest(tpath, list.size(), upload_id))){
    OSSFS_PRN_ERR("failed uploading part(%d)", result);
    close(fd2);
    return result;
  }
  DestroyCurlHandle();
  close(fd2);

  return 0;
}

int OSSfsCurl::MultipartRenameRequest(const char* from, const char* to, headers_t& meta, off_t size)
{
  int            result;
  string         upload_id;
  off_t          chunk;
  off_t          bytes_remaining;
  etaglist_t     list;
  ostringstream  strrange;

  OSSFS_PRN_INFO3("[from=%s][to=%s]", SAFESTRPTR(from), SAFESTRPTR(to));

  string srcresource;
  string srcurl;
  MakeUrlResource(get_realpath(from).c_str(), srcresource, srcurl);

  meta["Content-Type"]      = OSSfsCurl::LookupMimeType(string(to));
  meta["x-oss-copy-source"] = srcresource;

  if(0 != (result = PreMultipartPostRequest(to, meta, upload_id, true))){
    return result;
  }
  DestroyCurlHandle();

  // Initialize OSSfsMultiCurl
  OSSfsMultiCurl curlmulti(GetMaxParallelCount());
  curlmulti.SetSuccessCallback(OSSfsCurl::CopyMultipartPostCallback);
  curlmulti.SetRetryCallback(OSSfsCurl::CopyMultipartPostRetryCallback);

  for(bytes_remaining = size, chunk = 0; 0 < bytes_remaining; bytes_remaining -= chunk){
    chunk = bytes_remaining > MAX_MULTI_COPY_SOURCE_SIZE ? MAX_MULTI_COPY_SOURCE_SIZE : bytes_remaining;

    strrange << "bytes=" << (size - bytes_remaining) << "-" << (size - bytes_remaining + chunk - 1);
    meta["x-oss-copy-source-range"] = strrange.str();
    strrange.str("");
    strrange.clear(stringstream::goodbit);

    // ossfscurl sub object
    OSSfsCurl* ossfscurl_para            = new OSSfsCurl(true);
    ossfscurl_para->partdata.add_etag_list(&list);

    // initiate upload part for parallel
    if(0 != (result = ossfscurl_para->CopyMultipartPostSetup(from, to, list.size(), upload_id, meta))){
      OSSFS_PRN_ERR("failed uploading part setup(%d)", result);
      delete ossfscurl_para;
      return result;
    }

    // set into parallel object
    if(!curlmulti.SetOSSfsCurlObject(ossfscurl_para)){
      OSSFS_PRN_ERR("Could not make curl object into multi curl(%s).", to);
      delete ossfscurl_para;
      return -1;
    }
  }

  // Multi request
  if(0 != (result = curlmulti.Request())){
    OSSFS_PRN_ERR("error occurred in multi request(errno=%d).", result);

    OSSfsCurl ossfscurl_abort(true);
    int result2 = ossfscurl_abort.AbortMultipartUpload(to, upload_id);
    ossfscurl_abort.DestroyCurlHandle();
    if(result2 != 0){
      OSSFS_PRN_ERR("error aborting multipart upload(errno=%d).", result2);
    }

    return result;
  }

  if(0 != (result = CompleteMultipartPostRequest(to, upload_id, list))){
    return result;
  }
  return 0;
}

//-------------------------------------------------------------------
// method for OSSfsMultiCurl 
//-------------------------------------------------------------------
OSSfsMultiCurl::OSSfsMultiCurl(int maxParallelism)
  : maxParallelism(maxParallelism)
  , SuccessCallback(NULL)
  , RetryCallback(NULL)
{
  int res;
  if (0 != (res = pthread_mutex_init(&completed_tids_lock, NULL))) {
    OSSFS_PRN_ERR("could not initialize completed_tids_lock: %i", res);
  }
}

OSSfsMultiCurl::~OSSfsMultiCurl()
{
  Clear();
  int res;
  if(0 != (res = pthread_mutex_destroy(&completed_tids_lock))){
    OSSFS_PRN_ERR("could not destroy completed_tids_lock: %i", res);
  }
}

bool OSSfsMultiCurl::ClearEx(bool is_all)
{
  ossfscurllist_t::iterator iter;
  for(iter = clist_req.begin(); iter != clist_req.end(); ++iter){
    OSSfsCurl* ossfscurl = *iter;
    if(ossfscurl){
      ossfscurl->DestroyCurlHandle();
      delete ossfscurl;  // with destroy curl handle.
    }
  }
  clist_req.clear();

  if(is_all){
    for(iter = clist_all.begin(); iter != clist_all.end(); ++iter){
      OSSfsCurl* ossfscurl = *iter;
      ossfscurl->DestroyCurlHandle();
      delete ossfscurl;
    }
    clist_all.clear();
  }

  OSSFS_MALLOCTRIM(0);

  return true;
}

OSSfsMultiSuccessCallback OSSfsMultiCurl::SetSuccessCallback(OSSfsMultiSuccessCallback function)
{
  OSSfsMultiSuccessCallback old = SuccessCallback;
  SuccessCallback = function;
  return old;
}
  
OSSfsMultiRetryCallback OSSfsMultiCurl::SetRetryCallback(OSSfsMultiRetryCallback function)
{
  OSSfsMultiRetryCallback old = RetryCallback;
  RetryCallback = function;
  return old;
}
  
bool OSSfsMultiCurl::SetOSSfsCurlObject(OSSfsCurl* ossfscurl)
{
  if(!ossfscurl){
    return false;
  }
  clist_all.push_back(ossfscurl);

  return true;
}

int OSSfsMultiCurl::MultiPerform()
{
  std::vector<pthread_t>   threads;
  bool                     success = true;
  bool                     isMultiHead = false;
  Semaphore                sem(GetMaxParallelism());
  int                      rc;

  for(ossfscurllist_t::iterator iter = clist_req.begin(); iter != clist_req.end(); ++iter) {
    pthread_t   thread;
    OSSfsCurl*   ossfscurl = *iter;
    ossfscurl->sem = &sem;
    ossfscurl->completed_tids_lock = &completed_tids_lock;
    ossfscurl->completed_tids = &completed_tids;

    sem.wait();

    {
      AutoLock lock(&completed_tids_lock);
      for(std::vector<pthread_t>::iterator it = completed_tids.begin(); it != completed_tids.end(); ++it){
        void*   retval;

        rc = pthread_join(*it, &retval);
        if (rc) {
          success = false;
          OSSFS_PRN_ERR("failed pthread_join - rc(%d) %s", rc, strerror(rc));
        } else {
          int int_retval = (int)(intptr_t)(retval);
          if (int_retval && !(int_retval == -ENOENT && isMultiHead)) {
            OSSFS_PRN_WARN("thread failed - rc(%d)", int_retval);
          }
        }
      }
      completed_tids.clear();
    }

    isMultiHead |= ossfscurl->GetOp() == "HEAD";

    rc = pthread_create(&thread, NULL, OSSfsMultiCurl::RequestPerformWrapper, static_cast<void*>(ossfscurl));
    if (rc != 0) {
      success = false;
      OSSFS_PRN_ERR("failed pthread_create - rc(%d)", rc);
      break;
    }

    threads.push_back(thread);
  }

  for(int i = 0; i < sem.get_value(); ++i){
    sem.wait();
  }

  AutoLock lock(&completed_tids_lock);
  for (std::vector<pthread_t>::iterator titer = completed_tids.begin(); titer != completed_tids.end(); ++titer) {
    void*   retval;

    rc = pthread_join(*titer, &retval);
    if (rc) {
      success = false;
      OSSFS_PRN_ERR("failed pthread_join - rc(%d)", rc);
    } else {
      int int_retval = (int)(intptr_t)(retval);
      if (int_retval && !(int_retval == -ENOENT && isMultiHead)) {
        OSSFS_PRN_WARN("thread failed - rc(%d)", int_retval);
      }
    }
  }
  completed_tids.clear();

  return success ? 0 : -EIO;
}

int OSSfsMultiCurl::MultiRead()
{
  for(ossfscurllist_t::iterator iter = clist_req.begin(); iter != clist_req.end(); ++iter) {
    OSSfsCurl* ossfscurl = *iter;

    bool isRetry = false;

    long responseCode = -1;
    if(ossfscurl->GetResponseCode(responseCode, false)){
      if(400 > responseCode){
        // add into stat cache
        if(SuccessCallback && !SuccessCallback(ossfscurl)){
          OSSFS_PRN_WARN("error from callback function(%s).", ossfscurl->url.c_str());
        }
      }else if(400 == responseCode){
        // as possibly in multipart
        OSSFS_PRN_WARN("failed a request(%ld: %s)", responseCode, ossfscurl->url.c_str());
        isRetry = true;
      }else if(404 == responseCode){
        // not found
        // HEAD requests on readdir_multi_head can return 404
        if(ossfscurl->GetOp() != "HEAD"){
          OSSFS_PRN_WARN("failed a request(%ld: %s)", responseCode, ossfscurl->url.c_str());
        }
      }else if(500 == responseCode){
        // case of all other result, do retry.(11/13/2013)
        // because it was found that ossfs got 500 error from OSS, but could success
        // to retry it.
        OSSFS_PRN_WARN("failed a request(%ld: %s)", responseCode, ossfscurl->url.c_str());
        isRetry = true;
      }else{
        // Retry in other case.
        OSSFS_PRN_WARN("failed a request(%ld: %s)", responseCode, ossfscurl->url.c_str());
        isRetry = true;
      }
    }else{
      OSSFS_PRN_ERR("failed a request(Unknown response code: %s)", ossfscurl->url.c_str());
    }

    if(!isRetry){
      ossfscurl->DestroyCurlHandle();
      delete ossfscurl;

    }else{
      OSSfsCurl* retrycurl = NULL;

      // For retry
      if(RetryCallback){
        retrycurl = RetryCallback(ossfscurl);
        if(NULL != retrycurl){
          clist_all.push_back(retrycurl);
        }else{
          // Could not set up callback.
          return -EIO;
        }
      }
      if(ossfscurl != retrycurl){
        ossfscurl->DestroyCurlHandle();
        delete ossfscurl;
      }
    }
  }
  clist_req.clear();

  return 0;
}

int OSSfsMultiCurl::Request()
{
  OSSFS_PRN_INFO3("[count=%zu]", clist_all.size());

  // Make request list.
  //
  // Send multi request loop( with retry )
  // (When many request is sends, sometimes gets "Couldn't connect to server")
  //
  while(!clist_all.empty()){
    // set curl handle to multi handle
    int                      result;
    ossfscurllist_t::iterator iter;
    for(iter = clist_all.begin(); iter != clist_all.end(); ++iter){
      OSSfsCurl* ossfscurl = *iter;
      clist_req.push_back(ossfscurl);
    }
    clist_all.clear();

    // Send multi request.
    if(0 != (result = MultiPerform())){
      Clear();
      return result;
    }

    // Read the result
    if(0 != (result = MultiRead())){
      Clear();
      return result;
    }

    // Cleanup curl handle in multi handle
    ClearEx(false);
  }
  return 0;
}

// thread function for performing an OSSfsCurl request
//
void* OSSfsMultiCurl::RequestPerformWrapper(void* arg)
{
  OSSfsCurl* ossfscurl= static_cast<OSSfsCurl*>(arg);
  void*     result  = NULL;
  if(ossfscurl && ossfscurl->fpLazySetup){
    if(!ossfscurl->fpLazySetup(ossfscurl)){
      OSSFS_PRN_ERR("Failed to lazy setup, then respond EIO.");
      result  = (void*)(intptr_t)(-EIO);
    }
  }

  if(!result){
    result = (void*)(intptr_t)(ossfscurl->RequestPerform());
    ossfscurl->DestroyCurlHandle(true, false);
  }

  AutoLock  lock(ossfscurl->completed_tids_lock);
  ossfscurl->completed_tids->push_back(pthread_self());
  ossfscurl->sem->post();

  return result;
}

//-------------------------------------------------------------------
// Utility functions
//-------------------------------------------------------------------
//
// curl_slist_sort_insert
// This function is like curl_slist_append function, but this adds data by a-sorting.
// Because OSS signature needs sorted header.
//
struct curl_slist* curl_slist_sort_insert(struct curl_slist* list, const char* data)
{
  if(!data){
    return list;
  }
  string strkey = data;
  string strval;

  string::size_type pos = strkey.find(':', 0);
  if(string::npos != pos){
    strval = strkey.substr(pos + 1);
    strkey = strkey.substr(0, pos);
  }

  return curl_slist_sort_insert(list, strkey.c_str(), strval.c_str());
}

struct curl_slist* curl_slist_sort_insert(struct curl_slist* list, const char* key, const char* value)
{
  struct curl_slist* curpos;
  struct curl_slist* lastpos;
  struct curl_slist* new_item;

  if(!key){
    return list;
  }
  if(NULL == (new_item = reinterpret_cast<struct curl_slist*>(malloc(sizeof(struct curl_slist))))){
    return list;
  }

  // key & value are trimmed and lower (only key)
  string strkey = trim(string(key));
  string strval = trim(string(value ? value : ""));
  string strnew = key + string(": ") + strval;
  if(NULL == (new_item->data = strdup(strnew.c_str()))){
    free(new_item);
    return list;
  }
  new_item->next = NULL;

  for(lastpos = NULL, curpos = list; curpos; lastpos = curpos, curpos = curpos->next){
    string strcur = curpos->data;
    size_t pos;
    if(string::npos != (pos = strcur.find(':', 0))){
      strcur = strcur.substr(0, pos);
    }

    int result = strcasecmp(strkey.c_str(), strcur.c_str());
    if(0 == result){
      // same data, so replace it.
      if(lastpos){
        lastpos->next = new_item;
      }else{
        list = new_item;
      }
      new_item->next = curpos->next;
      free(curpos->data);
      free(curpos);
      break;

    }else if(0 > result){
      // add data before curpos.
      if(lastpos){
        lastpos->next = new_item;
      }else{
        list = new_item;
      }
      new_item->next = curpos;
      break;
    }
  }

  if(!curpos){
    // append to last pos
    if(lastpos){
      lastpos->next = new_item;
    }else{
      // a case of list is null
      list = new_item;
    }
  }

  return list;
}

string get_sorted_header_keys(const struct curl_slist* list)
{
  string sorted_headers;

  if(!list){
    return sorted_headers;
  }

  for( ; list; list = list->next){
    string strkey = list->data;
    size_t pos;
    if(string::npos != (pos = strkey.find(':', 0))){
      if (trim(strkey.substr(pos + 1)).empty()) {
        // skip empty-value headers (as they are discarded by libcurl)
        continue;
      }
      strkey = strkey.substr(0, pos);
    }
    if(0 < sorted_headers.length()){
      sorted_headers += ";";
    }
    sorted_headers += lower(strkey);
  }

  return sorted_headers;
}

string get_header_value(const struct curl_slist* list, const string &key)
{
  if(!list){
    return "";
  }

  for( ; list; list = list->next){
    string strkey = list->data;
    size_t pos;
    if(string::npos != (pos = strkey.find(':', 0))){
      if(0 == strcasecmp(trim(strkey.substr(0, pos)).c_str(), key.c_str())){
        return trim(strkey.substr(pos+1));
      }
    }
  }

  return "";
}

string get_canonical_headers(const struct curl_slist* list)
{
  string canonical_headers;

  if(!list){
    canonical_headers = "\n";
    return canonical_headers;
  }

  for( ; list; list = list->next){
    string strhead = list->data;
    size_t pos;
    if(string::npos != (pos = strhead.find(':', 0))){
      string strkey = trim(lower(strhead.substr(0, pos)));
      string strval = trim(strhead.substr(pos + 1));
      if (strval.empty()) {
        // skip empty-value headers (as they are discarded by libcurl)
        continue;
      }
      strhead       = strkey.append(":").append(strval);
    }else{
      strhead       = trim(lower(strhead));
    }
    canonical_headers += strhead;
    canonical_headers += "\n";
  }
  return canonical_headers;
}

string get_canonical_headers(const struct curl_slist* list, bool only_oss)
{
  string canonical_headers;

  if(!list){
    canonical_headers = "\n";
    return canonical_headers;
  }

  for( ; list; list = list->next){
    string strhead = list->data;
    size_t pos;
    if(string::npos != (pos = strhead.find(':', 0))){
      string strkey = trim(lower(strhead.substr(0, pos)));
      string strval = trim(strhead.substr(pos + 1));
      if (strval.empty()) {
        // skip empty-value headers (as they are discarded by libcurl)
        continue;
      }
      strhead       = strkey.append(":").append(strval);
    }else{
      strhead       = trim(lower(strhead));
    }
    if(only_oss && strhead.substr(0, 5) != "x-oss"){
      continue;
    }
    canonical_headers += strhead;
    canonical_headers += "\n";
  }
  return canonical_headers;
}

// function for using global values
bool MakeUrlResource(const char* realpath, string& resourcepath, string& url)
{
  if(!realpath){
    return false;
  }
  resourcepath = urlEncode(service_path + bucket + realpath);
  url          = host + resourcepath;
  return true;
}

string prepare_url(const char* url)
{
  OSSFS_PRN_INFO3("URL is %s", url);

  string uri;
  string hostname;
  string path;
  string url_str = string(url);
  string token = string("/") + bucket;
  int bucket_pos = url_str.find(token);
  int bucket_length = token.size();
  int uri_length = 0;

  if(!strncasecmp(url_str.c_str(), "https://", 8)){
    uri_length = 8;
  } else if(!strncasecmp(url_str.c_str(), "http://", 7)) {
    uri_length = 7;
  }
  uri  = url_str.substr(0, uri_length);

  if(!pathrequeststyle){
    hostname = bucket + "." + url_str.substr(uri_length, bucket_pos - uri_length);
    path = url_str.substr((bucket_pos + bucket_length));
  }else{
    hostname = url_str.substr(uri_length, bucket_pos - uri_length);
    string part = url_str.substr((bucket_pos + bucket_length));
    if('/' != part[0]){
      part = "/" + part;
    }
    path = "/" + bucket + part;
  }

  url_str = uri + hostname + path;

  OSSFS_PRN_INFO3("URL changed is %s", url_str.c_str());

  return url_str;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
