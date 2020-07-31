/*
 * ossfs - FUSE-based file system backed by InspurCloud OSS
 *
 * Copyright(C) 2007 Takeshi Nakatani <ggtakec.com>
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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/types.h>
#include <dirent.h>

#include <string>
#include <sstream>
#include <map>
#include <list>

#include "common.h"
#include "ossfs_util.h"
#include "string_util.h"
#include "ossfs.h"
#include "ossfs_auth.h"

using namespace std;

//-------------------------------------------------------------------
// Global variables
//-------------------------------------------------------------------
std::string mount_prefix;

//-------------------------------------------------------------------
// Utility
//-------------------------------------------------------------------
string get_realpath(const char *path) {
  string realpath = mount_prefix;
  realpath += path;

  return realpath;
}

//-------------------------------------------------------------------
// Class OSSObjList
//-------------------------------------------------------------------
// New class OSSObjList is base on old oss_object struct.
// This class is for OSS compatible clients.
//
// If name is terminated by "/", it is forced dir type.
// If name is terminated by "_$folder$", it is forced dir type.
// If is_dir is true and name is not terminated by "/", the name is added "/".
//
bool OSSObjList::insert(const char* name, const char* etag, bool is_dir)
{
  if(!name || '\0' == name[0]){
    return false;
  }

  ossobj_t::iterator iter;
  string newname;
  string orgname = name;

  // Normalization
  string::size_type pos = orgname.find("_$folder$");
  if(string::npos != pos){
    newname = orgname.substr(0, pos);
    is_dir  = true;
  }else{
    newname = orgname;
  }
  if(is_dir){
    if('/' != newname[newname.length() - 1]){
      newname += "/";
    }
  }else{
    if('/' == newname[newname.length() - 1]){
      is_dir = true;
    }
  }

  // Check derived name object.
  if(is_dir){
    string chkname = newname.substr(0, newname.length() - 1);
    if(objects.end() != (iter = objects.find(chkname))){
      // found "dir" object --> remove it.
      objects.erase(iter);
    }
  }else{
    string chkname = newname + "/";
    if(objects.end() != (iter = objects.find(chkname))){
      // found "dir/" object --> not add new object.
      // and add normalization
      return insert_normalized(orgname.c_str(), chkname.c_str(), true);
    }
  }

  // Add object
  if(objects.end() != (iter = objects.find(newname))){
    // Found same object --> update information.
    (*iter).second.normalname.erase();
    (*iter).second.orgname = orgname;
    (*iter).second.is_dir  = is_dir;
    if(etag){
      (*iter).second.etag = string(etag);  // over write
    }
  }else{
    // add new object
    ossobj_entry newobject;
    newobject.orgname = orgname;
    newobject.is_dir  = is_dir;
    if(etag){
      newobject.etag = etag;
    }
    objects[newname] = newobject;
  }

  // add normalization
  return insert_normalized(orgname.c_str(), newname.c_str(), is_dir);
}

bool OSSObjList::insert_normalized(const char* name, const char* normalized, bool is_dir)
{
  if(!name || '\0' == name[0] || !normalized || '\0' == normalized[0]){
    return false;
  }
  if(0 == strcmp(name, normalized)){
    return true;
  }

  ossobj_t::iterator iter;
  if(objects.end() != (iter = objects.find(name))){
    // found name --> over write
    iter->second.orgname.erase();
    iter->second.etag.erase();
    iter->second.normalname = normalized;
    iter->second.is_dir     = is_dir;
  }else{
    // not found --> add new object
    ossobj_entry newobject;
    newobject.normalname = normalized;
    newobject.is_dir     = is_dir;
    objects[name]        = newobject;
  }
  return true;
}

const ossobj_entry* OSSObjList::GetOSSObj(const char* name) const
{
  ossobj_t::const_iterator iter;

  if(!name || '\0' == name[0]){
    return NULL;
  }
  if(objects.end() == (iter = objects.find(name))){
    return NULL;
  }
  return &((*iter).second);
}

string OSSObjList::GetOrgName(const char* name) const
{
  const ossobj_entry* possobj;

  if(!name || '\0' == name[0]){
    return string("");
  }
  if(NULL == (possobj = GetOSSObj(name))){
    return string("");
  }
  return possobj->orgname;
}

string OSSObjList::GetNormalizedName(const char* name) const
{
  const ossobj_entry* possobj;

  if(!name || '\0' == name[0]){
    return string("");
  }
  if(NULL == (possobj = GetOSSObj(name))){
    return string("");
  }
  if(0 == (possobj->normalname).length()){
    return string(name);
  }
  return possobj->normalname;
}

string OSSObjList::GetETag(const char* name) const
{
  const ossobj_entry* possobj;

  if(!name || '\0' == name[0]){
    return string("");
  }
  if(NULL == (possobj = GetOSSObj(name))){
    return string("");
  }
  return possobj->etag;
}

bool OSSObjList::IsDir(const char* name) const
{
  const ossobj_entry* possobj;

  if(NULL == (possobj = GetOSSObj(name))){
    return false;
  }
  return possobj->is_dir;
}

bool OSSObjList::GetLastName(std::string& lastname) const
{
  bool result = false;
  lastname = "";
  for(ossobj_t::const_iterator iter = objects.begin(); iter != objects.end(); ++iter){
    if((*iter).second.orgname.length()){
      if(0 > strcmp(lastname.c_str(), (*iter).second.orgname.c_str())){
        lastname = (*iter).second.orgname;
        result = true;
      }
    }else{
      if(0 > strcmp(lastname.c_str(), (*iter).second.normalname.c_str())){
        lastname = (*iter).second.normalname;
        result = true;
      }
    }
  }
  return result;
}

bool OSSObjList::GetNameList(ossobj_list_t& list, bool OnlyNormalized, bool CutSlash) const
{
  ossobj_t::const_iterator iter;

  for(iter = objects.begin(); objects.end() != iter; ++iter){
    if(OnlyNormalized && 0 != (*iter).second.normalname.length()){
      continue;
    }
    string name = (*iter).first;
    if(CutSlash && 1 < name.length() && '/' == name[name.length() - 1]){
      // only "/" string is skipped this.
      name = name.substr(0, name.length() - 1);
    }
    list.push_back(name);
  }
  return true;
}

typedef std::map<std::string, bool> ossobj_h_t;

bool OSSObjList::MakeHierarchizedList(ossobj_list_t& list, bool haveSlash)
{
  ossobj_h_t h_map;
  ossobj_h_t::iterator hiter;
  ossobj_list_t::const_iterator liter;

  for(liter = list.begin(); list.end() != liter; ++liter){
    string strtmp = (*liter);
    if(1 < strtmp.length() && '/' == strtmp[strtmp.length() - 1]){
      strtmp = strtmp.substr(0, strtmp.length() - 1);
    }
    h_map[strtmp] = true;

    // check hierarchized directory
    for(string::size_type pos = strtmp.find_last_of('/'); string::npos != pos; pos = strtmp.find_last_of('/')){
      strtmp = strtmp.substr(0, pos);
      if(0 == strtmp.length() || "/" == strtmp){
        break;
      }
      if(h_map.end() == h_map.find(strtmp)){
        // not found
        h_map[strtmp] = false;
      }
    }
  }

  // check map and add lost hierarchized directory.
  for(hiter = h_map.begin(); hiter != h_map.end(); ++hiter){
    if(false == (*hiter).second){
      // add hierarchized directory.
      string strtmp = (*hiter).first;
      if(haveSlash){
        strtmp += "/";
      }
      list.push_back(strtmp);
    }
  }
  return true;
}

//-------------------------------------------------------------------
// Utility functions for moving objects
//-------------------------------------------------------------------
MVNODE *create_mvnode(const char *old_path, const char *new_path, bool is_dir, bool normdir)
{
  MVNODE *p;
  char *p_old_path;
  char *p_new_path;

  p = (MVNODE *) malloc(sizeof(MVNODE));
  if (p == NULL) {
    printf("create_mvnode: could not allocation memory for p\n");
    OSSFS_FUSE_EXIT();
    return NULL;
  }

  if(NULL == (p_old_path = strdup(old_path))){
    free(p);
    printf("create_mvnode: could not allocation memory for p_old_path\n");
    OSSFS_FUSE_EXIT();
    return NULL;
  }

  if(NULL == (p_new_path = strdup(new_path))){
    free(p);
    free(p_old_path);
    printf("create_mvnode: could not allocation memory for p_new_path\n");
    OSSFS_FUSE_EXIT();
    return NULL;
  }

  p->old_path   = p_old_path;
  p->new_path   = p_new_path;
  p->is_dir     = is_dir;
  p->is_normdir = normdir;
  p->prev = NULL;
  p->next = NULL;
  return p;
}

//
// Add sorted MVNODE data(Ascending order)
//
MVNODE *add_mvnode(MVNODE** head, MVNODE** tail, const char *old_path, const char *new_path, bool is_dir, bool normdir)
{
  if(!head || !tail){
    return NULL;
  }

  MVNODE* cur;
  MVNODE* mvnew;
  for(cur = *head; cur; cur = cur->next){
    if(cur->is_dir == is_dir){
      int nResult = strcmp(cur->old_path, old_path);
      if(0 == nResult){
        // Found same old_path.
        return cur;

      }else if(0 > nResult){
        // next check.
        // ex: cur("abc"), mvnew("abcd")
        // ex: cur("abc"), mvnew("abd")
        continue;

      }else{
        // Add into before cur-pos.
        // ex: cur("abc"), mvnew("ab")
        // ex: cur("abc"), mvnew("abb")
        if(NULL == (mvnew = create_mvnode(old_path, new_path, is_dir, normdir))){
          return NULL;
        }
        if(cur->prev){
          (cur->prev)->next = mvnew;
        }else{
          *head = mvnew;
        }
        mvnew->prev = cur->prev;
        mvnew->next = cur;
        cur->prev = mvnew;

        return mvnew;
      }
    }
  }
  // Add into tail.
  if(NULL == (mvnew = create_mvnode(old_path, new_path, is_dir, normdir))){
    return NULL;
  }
  mvnew->prev = (*tail);
  if(*tail){
    (*tail)->next = mvnew;
  }
  (*tail) = mvnew;
  if(!(*head)){
    (*head) = mvnew;
  }
  return mvnew;
}

void free_mvnodes(MVNODE *head)
{
  MVNODE *my_head;
  MVNODE *next;

  for(my_head = head, next = NULL; my_head; my_head = next){
    next = my_head->next;
    free(my_head->old_path);
    free(my_head->new_path);
    free(my_head);
  }
}

//-------------------------------------------------------------------
// Class AutoLock
//-------------------------------------------------------------------
AutoLock::AutoLock(pthread_mutex_t* pmutex, bool no_wait) : auto_mutex(pmutex)
{
  if (no_wait) {
    is_lock_acquired = pthread_mutex_trylock(auto_mutex) == 0;
  } else {
    is_lock_acquired = pthread_mutex_lock(auto_mutex) == 0;
  }
}

bool AutoLock::isLockAcquired() const
{
  return is_lock_acquired;
}

AutoLock::~AutoLock()
{
  if (is_lock_acquired) {
    pthread_mutex_unlock(auto_mutex);
  }
}

//-------------------------------------------------------------------
// Utility for UID/GID
//-------------------------------------------------------------------
// get user name from uid
string get_username(uid_t uid)
{
  static size_t maxlen = 0;	// set once
  int result;
  char* pbuf;
  struct passwd pwinfo;
  struct passwd* ppwinfo = NULL;

  // make buffer
  if(0 == maxlen){
    long res = sysconf(_SC_GETPW_R_SIZE_MAX);
    if(0 > res){
      // SUSv4tc1 says the following about _SC_GETGR_R_SIZE_MAX and
      // _SC_GETPW_R_SIZE_MAX:
      // Note that sysconf(_SC_GETGR_R_SIZE_MAX) may return -1 if
      // there is no hard limit on the size of the buffer needed to
      // store all the groups returned.
      if (errno != 0){
        OSSFS_PRN_WARN("could not get max pw length.");
        maxlen = 0;
        return string("");
      }
      res = 1024; // default initial length
    }
    maxlen = res;
  }
  if(NULL == (pbuf = (char*)malloc(sizeof(char) * maxlen))){
    OSSFS_PRN_CRIT("failed to allocate memory.");
    return string("");
  }
  // get pw information
  while(ERANGE == (result = getpwuid_r(uid, &pwinfo, pbuf, maxlen, &ppwinfo))){
    free(pbuf);
    maxlen *= 2;
    if(NULL == (pbuf = (char*)malloc(sizeof(char) * maxlen))){
      OSSFS_PRN_CRIT("failed to allocate memory.");
      return string("");
    }
  }

  if(0 != result){
    OSSFS_PRN_ERR("could not get pw information(%d).", result);
    free(pbuf);
    return string("");
  }

  // check pw
  if(NULL == ppwinfo){
    free(pbuf);
    return string("");
  }
  string name = SAFESTRPTR(ppwinfo->pw_name);
  free(pbuf);
  return name;
}

int is_uid_include_group(uid_t uid, gid_t gid)
{
  static size_t maxlen = 0;	// set once
  int result;
  char* pbuf;
  struct group ginfo;
  struct group* pginfo = NULL;

  // make buffer
  if(0 == maxlen){
    long res = sysconf(_SC_GETGR_R_SIZE_MAX);
    if(0 > res) {
      // SUSv4tc1 says the following about _SC_GETGR_R_SIZE_MAX and
      // _SC_GETPW_R_SIZE_MAX:
      // Note that sysconf(_SC_GETGR_R_SIZE_MAX) may return -1 if
      // there is no hard limit on the size of the buffer needed to
      // store all the groups returned.
      if (errno != 0) {
        OSSFS_PRN_ERR("could not get max name length.");
        maxlen = 0;
        return -ERANGE;
      }
      res = 1024; // default initial length
    }
    maxlen = res;
  }
  if(NULL == (pbuf = (char*)malloc(sizeof(char) * maxlen))){
    OSSFS_PRN_CRIT("failed to allocate memory.");
    return -ENOMEM;
  }
  // get group information
  while(ERANGE == (result = getgrgid_r(gid, &ginfo, pbuf, maxlen, &pginfo))){
    free(pbuf);
    maxlen *= 2;
    if(NULL == (pbuf = (char*)malloc(sizeof(char) * maxlen))){
      OSSFS_PRN_CRIT("failed to allocate memory.");
      return -ENOMEM;
    }
  }

  if(0 != result){
    OSSFS_PRN_ERR("could not get group information(%d).", result);
    free(pbuf);
    return -result;
  }

  // check group
  if(NULL == pginfo){
    // there is not gid in group.
    free(pbuf);
    return -EINVAL;
  }

  string username = get_username(uid);

  char** ppgr_mem;
  for(ppgr_mem = pginfo->gr_mem; ppgr_mem && *ppgr_mem; ppgr_mem++){
    if(username == *ppgr_mem){
      // Found username in group.
      free(pbuf);
      return 1;
    }
  }
  free(pbuf);
  return 0;
}

//-------------------------------------------------------------------
// Utility for file and directory
//-------------------------------------------------------------------
// safe variant of dirname
// dirname clobbers path so let it operate on a tmp copy
string mydirname(const char* path)
{
  if(!path || '\0' == path[0]){
    return string("");
  }
  return mydirname(string(path));
}

string mydirname(const string& path)
{
  return string(dirname((char*)path.c_str()));
}

// safe variant of basename
// basename clobbers path so let it operate on a tmp copy
string mybasename(const char* path)
{
  if(!path || '\0' == path[0]){
    return string("");
  }
  return mybasename(string(path));
}

string mybasename(const string& path)
{
  return string(basename((char*)path.c_str()));
}

// mkdir --parents
int mkdirp(const string& path, mode_t mode)
{
  string        base;
  string        component;
  istringstream ss(path);
  while (getline(ss, component, '/')) {
    base += "/" + component;

    struct stat st;
    if(0 == stat(base.c_str(), &st)){
      if(!S_ISDIR(st.st_mode)){
        return EPERM;
      }
    }else{
      if(0 != mkdir(base.c_str(), mode) && errno != EEXIST){
        return errno;
     }
    }
  }
  return 0;
}

// get existed directory path
string get_exist_directory_path(const string& path)
{
  string        existed("/");    // "/" is existed.
  string        base;
  string        component;
  istringstream ss(path);
  while (getline(ss, component, '/')) {
    if(base != "/"){
      base += "/";
    }
    base += component;
    struct stat st;
    if(0 == stat(base.c_str(), &st) && S_ISDIR(st.st_mode)){
      existed = base;
    }else{
      break;
    }
  }
  return existed;
}

bool check_exist_dir_permission(const char* dirpath)
{
  if(!dirpath || '\0' == dirpath[0]){
    return false;
  }

  // exists
  struct stat st;
  if(0 != stat(dirpath, &st)){
    if(ENOENT == errno){
      // dir does not exist
      return true;
    }
    if(EACCES == errno){
      // could not access directory
      return false;
    }
    // something error occurred
    return false;
  }

  // check type
  if(!S_ISDIR(st.st_mode)){
    // path is not directory
    return false;
  }

  // check permission
  uid_t myuid = geteuid();
  if(myuid == st.st_uid){
    if(S_IRWXU != (st.st_mode & S_IRWXU)){
      return false;
    }
  }else{
    if(1 == is_uid_include_group(myuid, st.st_gid)){
      if(S_IRWXG != (st.st_mode & S_IRWXG)){
        return false;
      }
    }else{
      if(S_IRWXO != (st.st_mode & S_IRWXO)){
        return false;
      }
    }
  }
  return true;
}

bool delete_files_in_dir(const char* dir, bool is_remove_own)
{
  DIR*           dp;
  struct dirent* dent;

  if(NULL == (dp = opendir(dir))){
    OSSFS_PRN_ERR("could not open dir(%s) - errno(%d)", dir, errno);
    return false;
  }

  for(dent = readdir(dp); dent; dent = readdir(dp)){
    if(0 == strcmp(dent->d_name, "..") || 0 == strcmp(dent->d_name, ".")){
      continue;
    }
    string   fullpath = dir;
    fullpath         += "/";
    fullpath         += dent->d_name;
    struct stat st;
    if(0 != lstat(fullpath.c_str(), &st)){
      OSSFS_PRN_ERR("could not get stats of file(%s) - errno(%d)", fullpath.c_str(), errno);
      closedir(dp);
      return false;
    }
    if(S_ISDIR(st.st_mode)){
      // dir -> Reentrant
      if(!delete_files_in_dir(fullpath.c_str(), true)){
        OSSFS_PRN_ERR("could not remove sub dir(%s) - errno(%d)", fullpath.c_str(), errno);
        closedir(dp);
        return false;
      }
    }else{
      if(0 != unlink(fullpath.c_str())){
        OSSFS_PRN_ERR("could not remove file(%s) - errno(%d)", fullpath.c_str(), errno);
        closedir(dp);
        return false;
      }
    }
  }
  closedir(dp);

  if(is_remove_own && 0 != rmdir(dir)){
    OSSFS_PRN_ERR("could not remove dir(%s) - errno(%d)", dir, errno);
    return false;
  }
  return true;
}

//-------------------------------------------------------------------
// Utility functions for convert
//-------------------------------------------------------------------
time_t get_mtime(const char *str)
{
  // [NOTE]
  // In rclone, there are cases where ns is set to x-oss-meta-mtime
  // with floating point number. ossfs uses x-oss-meta-mtime by
  // truncating the floating point or less (in seconds or less) to
  // correspond to this.
  //
  string strmtime;
  if(str && '\0' != *str){
    strmtime = str;
    string::size_type pos = strmtime.find('.', 0);
    if(string::npos != pos){
      strmtime = strmtime.substr(0, pos);
    }
  }
  return static_cast<time_t>(ossfs_strtoofft(strmtime.c_str()));
}

static time_t get_time(headers_t& meta, bool overcheck, const char *header)
{
  headers_t::const_iterator iter;
  if(meta.end() == (iter = meta.find(header))){
    if(overcheck){
      return get_lastmodified(meta);
    }
    return 0;
  }
  return get_mtime((*iter).second.c_str());
}

time_t get_mtime(headers_t& meta, bool overcheck)
{
  return get_time(meta, overcheck, "x-oss-meta-mtime");
}

time_t get_ctime(headers_t& meta, bool overcheck)
{
  return get_time(meta, overcheck, "x-oss-meta-ctime");
}

off_t get_size(const char *s)
{
  return ossfs_strtoofft(s);
}

off_t get_size(headers_t& meta)
{
  headers_t::const_iterator iter = meta.find("Content-Length");
  if(meta.end() == iter){
    return 0;
  }
  return get_size((*iter).second.c_str());
}

mode_t get_mode(const char *s)
{
  return static_cast<mode_t>(ossfs_strtoofft(s));
}

mode_t get_mode(headers_t& meta, const char* path, bool checkdir, bool forcedir)
{
  mode_t mode = 0;
  bool isOSSsync = false;
  headers_t::const_iterator iter;

  if(meta.end() != (iter = meta.find("x-oss-meta-mode"))){
    mode = get_mode((*iter).second.c_str());
  }else if(meta.end() != (iter = meta.find("x-oss-meta-permissions"))){ // for osssync
    mode = get_mode((*iter).second.c_str());
    isOSSsync = true;
  }else{
    // If another tool creates an object without permissions, default to owner
    // read-write and group readable.
    mode = path[strlen(path) - 1] == '/' ? 0750 : 0640;
  }
  // Checking the bitmask, if the last 3 bits are all zero then process as a regular
  // file type (S_IFDIR or S_IFREG), otherwise return mode unmodified so that S_IFIFO,
  // S_IFSOCK, S_IFCHR, S_IFLNK and S_IFBLK devices can be processed properly by fuse.
  if(!(mode & S_IFMT)){
    if(!isOSSsync){
      if(checkdir){
        if(forcedir){
          mode |= S_IFDIR;
        }else{
          if(meta.end() != (iter = meta.find("Content-Type"))){
            string strConType = (*iter).second;
            // Leave just the mime type, remove any optional parameters (eg charset)
            string::size_type pos = strConType.find(';');
            if(string::npos != pos){
              strConType = strConType.substr(0, pos);
            }
            if(strConType == "application/x-directory" 
	       || strConType == "httpd/unix-directory"){ // Nextcloud uses this MIME type for directory objects when mounting bucket as external Storage
              mode |= S_IFDIR;
            }else if(path && 0 < strlen(path) && '/' == path[strlen(path) - 1]){
              if(strConType == "binary/octet-stream" || strConType == "application/octet-stream"){
                mode |= S_IFDIR;
              }else{
                if(complement_stat){
                  // If complement lack stat mode, when the object has '/' character at end of name
                  // and content type is text/plain and the object's size is 0 or 1, it should be
                  // directory.
                  off_t size = get_size(meta);
                  if(strConType == "text/plain" && (0 == size || 1 == size)){
                    mode |= S_IFDIR;
                  }else{
                    mode |= S_IFREG;
                  }
                }else{
                  mode |= S_IFREG;
                }
              }
            }else{
              mode |= S_IFREG;
            }
          }else{
            mode |= S_IFREG;
          }
        }
      }
      // If complement lack stat mode, when it's mode is not set any permission,
      // the object is added minimal mode only for read permission.
      if(complement_stat && 0 == (mode & (S_IRWXU | S_IRWXG | S_IRWXO))){
        mode |= (S_IRUSR | (0 == (mode & S_IFDIR) ? 0 : S_IXUSR));
      }
    }else{
      if(!checkdir){
        // cut dir/reg flag.
        mode &= ~S_IFDIR;
        mode &= ~S_IFREG;
      }
    }
  }
  return mode;
}

uid_t get_uid(const char *s)
{
  return static_cast<uid_t>(ossfs_strtoofft(s));
}

uid_t get_uid(headers_t& meta)
{
  headers_t::const_iterator iter;
  if(meta.end() != (iter = meta.find("x-oss-meta-uid"))){
    return get_uid((*iter).second.c_str());
  }else if(meta.end() != (iter = meta.find("x-oss-meta-owner"))){ // for osssync
    return get_uid((*iter).second.c_str());
  }else{
    return geteuid();
  }
}

gid_t get_gid(const char *s)
{
  return static_cast<gid_t>(ossfs_strtoofft(s));
}

gid_t get_gid(headers_t& meta)
{
  headers_t::const_iterator iter;
  if(meta.end() != (iter = meta.find("x-oss-meta-gid"))){
    return get_gid((*iter).second.c_str());
  }else if(meta.end() != (iter = meta.find("x-oss-meta-group"))){ // for osssync
    return get_gid((*iter).second.c_str());
  }else{
    return getegid();
  }
}

blkcnt_t get_blocks(off_t size)
{
  return size / 512 + 1;
}

time_t cvtIAMExpireStringToTime(const char* s)
{
  struct tm tm;
  if(!s){
    return 0L;
  }
  memset(&tm, 0, sizeof(struct tm));
  strptime(s, "%Y-%m-%dT%H:%M:%S", &tm);
  return timegm(&tm); // GMT
}

time_t get_lastmodified(const char* s)
{
  struct tm tm;
  if(!s){
    return 0L;
  }
  memset(&tm, 0, sizeof(struct tm));
  strptime(s, "%a, %d %b %Y %H:%M:%S %Z", &tm);
  return timegm(&tm); // GMT
}

time_t get_lastmodified(headers_t& meta)
{
  headers_t::const_iterator iter = meta.find("Last-Modified");
  if(meta.end() == iter){
    return 0;
  }
  return get_lastmodified((*iter).second.c_str());
}

//
// Returns it whether it is an object with need checking in detail.
// If this function returns true, the object is possible to be directory
// and is needed checking detail(searching sub object).
//
bool is_need_check_obj_detail(headers_t& meta)
{
  headers_t::const_iterator iter;

  // directory object is Content-Length as 0.
  if(0 != get_size(meta)){
    return false;
  }
  // if the object has x-oss-meta information, checking is no more.
  if(meta.end() != meta.find("x-oss-meta-mode")  ||
     meta.end() != meta.find("x-oss-meta-mtime") ||
     meta.end() != meta.find("x-oss-meta-uid")   ||
     meta.end() != meta.find("x-oss-meta-gid")   ||
     meta.end() != meta.find("x-oss-meta-owner") ||
     meta.end() != meta.find("x-oss-meta-group") ||
     meta.end() != meta.find("x-oss-meta-permissions") )
  {
    return false;
  }
  // if there is not Content-Type, or Content-Type is "x-directory",
  // checking is no more.
  if(meta.end() == (iter = meta.find("Content-Type"))){
    return false;
  }
  if("application/x-directory" == (*iter).second){
    return false;
  }
  return true;
}

//-------------------------------------------------------------------
// Help
//-------------------------------------------------------------------
void show_usage ()
{
  printf("Usage: %s BUCKET:[PATH] MOUNTPOINT [OPTION]...\n",
    program_name.c_str());
}

void show_help ()
{
  show_usage();
  printf(
    "\n"
    "Mount an InspurCloud OSS bucket as a file system.\n"
    "\n"
    "Usage:\n"
    "   mounting\n"
    "     ossfs bucket[:/path] mountpoint [options]\n"
    "     ossfs mountpoint [options(must specify bucket= option)]\n"
    "\n"
    "   umounting\n"
    "     umount mountpoint\n"
    "\n"
    "   General forms for ossfs and FUSE/mount options:\n"
    "      -o opt[,opt...]\n"
    "      -o opt [-o opt] ...\n"
    "\n"
    "   utility mode (remove interrupted multipart uploading objects)\n"
    "     ossfs --incomplete-mpu-list(-u) bucket\n"
    "     ossfs --incomplete-mpu-abort[=all | =<date format>] bucket\n"
    "\n"
    "ossfs Options:\n"
    "\n"
    "   Most ossfs options are given in the form where \"opt\" is:\n"
    "\n"
    "             <option_name>=<option_value>\n"
    "\n"
    "   bucket\n"
    "      - if it is not specified bucket name(and path) in command line,\n"
    "        must specify this option after -o option for bucket name.\n"
    "\n"
    "   default_acl (default=\"private\")\n"
    "      - the default canned acl to apply to all written oss objects,\n"
    "        e.g., private, public-read.  empty string means do not send\n"
    "        header.  see\n"
    "        https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#canned-acl\n"
    "        for the full list of canned acls\n"
    "\n"
    "   retries (default=\"5\")\n"
    "      - number of times to retry a failed oss transaction\n"
    "\n"
    "   use_cache (default=\"\" which means disabled)\n"
    "      - local folder to use for local file cache\n"
    "\n"
    "   check_cache_dir_exist (default is disable)\n"
    "      - if use_cache is set, check if the cache directory exists.\n"
    "        if this option is not specified, it will be created at runtime\n"
    "        when the cache directory does not exist.\n"
    "\n"
    "   del_cache (delete local file cache)\n"
    "      - delete local file cache when ossfs starts and exits.\n"
    "\n"
    // TODO: storage_class
    // "   storage_class (default=\"standard\")\n" 
    // "      - store object with specified storage class.  Possible values:\n"
    // "        standard, standard_ia, onezone_ia and reduced_redundancy.\n"
    // "\n"
    "   use_sse (default is disable)\n"
    "      - Specify three type InspurCloud's Server-Site Encryption: SSE-OSS,\n"
    "        SSE-C or SSE-KMS. SSE-OSS uses InspurCloud OSS-managed encryption\n"
    "        keys, SSE-C uses customer-provided encryption keys, and\n"
    "        SSE-KMS uses the master key which you manage in OSS KMS.\n"
    "        You can specify \"use_sse\" or \"use_sse=1\" enables SSE-OSS\n"
    "        type(use_sse=1 is old type parameter).\n"
    "        Case of setting SSE-C, you can specify \"use_sse=custom\",\n"
    "        \"use_sse=custom:<custom key file path>\" or\n"
    "        \"use_sse=<custom key file path>\"(only <custom key file path>\n"
    "        specified is old type parameter). You can use \"c\" for\n"
    "        short \"custom\".\n"
    "        The custom key file must be 600 permission. The file can\n"
    "        have some lines, each line is one SSE-C key. The first line\n"
    "        in file is used as Customer-Provided Encryption Keys for\n"
    "        uploading and changing headers etc. If there are some keys\n"
    "        after first line, those are used downloading object which\n"
    "        are encrypted by not first key. So that, you can keep all\n"
    "        SSE-C keys in file, that is SSE-C key history.\n"
    "        If you specify \"custom\"(\"c\") without file path, you\n"
    "        need to set custom key by load_sse_c option or OSSSSECKEYS\n"
    "        environment.(OSSSSECKEYS environment has some SSE-C keys\n"
    "        with \":\" separator.) This option is used to decide the\n"
    "        SSE type. So that if you do not want to encrypt a object\n"
    "        object at uploading, but you need to decrypt encrypted\n"
    "        object at downloading, you can use load_sse_c option instead\n"
    "        of this option.\n"
    "        For setting SSE-KMS, specify \"use_sse=kmsid\" or\n"
    "        \"use_sse=kmsid:<kms id>\". You can use \"k\" for short \"kmsid\".\n"
    "        If you san specify SSE-KMS type with your <kms id> in OSS\n"
    "        KMS, you can set it after \"kmsid:\"(or \"k:\"). If you\n"
    "        specify only \"kmsid\"(\"k\"), you need to set OSSSSEKMSID\n"
    "        environment which value is <kms id>. You must be careful\n"
    "        about that you can not use the KMS id which is not same EC2\n"
    "        region.\n"
    "\n"
    "   load_sse_c - specify SSE-C keys\n"
    "        Specify the custom-provided encryption keys file path for decrypting\n"
    "        at downloading.\n"
    "        If you use the custom-provided encryption key at uploading, you\n"
    "        specify with \"use_sse=custom\". The file has many lines, one line\n"
    "        means one custom key. So that you can keep all SSE-C keys in file,\n"
    "        that is SSE-C key history. OSSSSECKEYS environment is as same as this\n"
    "        file contents.\n"
    "\n"
    "   public_bucket (default=\"\" which means disabled)\n"
    "      - anonymously mount a public bucket when set to 1, ignores the \n"
    "        $HOME/.passwd-ossfs and /etc/passwd-ossfs files.\n"
    "        OSS does not allow copy object api for anonymous users, then\n"
    "        ossfs sets nocopyapi option automatically when public_bucket=1\n"
    "        option is specified.\n"
    "\n"
    "   passwd_file (default=\"\")\n"
    "      - specify which ossfs password file to use\n"
    "\n"
    "   ahbe_conf (default=\"\" which means disabled)\n"
    "      - This option specifies the configuration file path which\n"
    "      file is the additional HTTP header by file(object) extension.\n"
    "      The configuration file format is below:\n"
    "      -----------\n"
    "      line         = [file suffix or regex] HTTP-header [HTTP-values]\n"
    "      file suffix  = file(object) suffix, if this field is empty,\n"
    "                     it means \"reg:(.*)\".(=all object).\n"
    "      regex        = regular expression to match the file(object) path.\n"
    "                     this type starts with \"reg:\" prefix.\n"
    "      HTTP-header  = additional HTTP header name\n"
    "      HTTP-values  = additional HTTP header value\n"
    "      -----------\n"
    "      Sample:\n"
    "      -----------\n"
    "      .gz                    Content-Encoding  gzip\n"
    "      .Z                     Content-Encoding  compress\n"
    "      reg:^/MYDIR/(.*)[.]t2$ Content-Encoding  text2\n"
    "      -----------\n"
    "      A sample configuration file is uploaded in \"test\" directory.\n"
    "      If you specify this option for set \"Content-Encoding\" HTTP \n"
    "      header, please take care for RFC 2616.\n"
    "\n"
    "   profile (default=\"default\")\n"
    "      - Choose a profile from ${HOME}/.oss/credentials to authenticate\n"
    "        against OSS. Note that this format matches the OSS CLI format and\n"
    "        differs from the ossfs passwd format.\n"
    "\n"
    "   connect_timeout (default=\"300\" seconds)\n"
    "      - time to wait for connection before giving up\n"
    "\n"
    "   readwrite_timeout (default=\"60\" seconds)\n"
    "      - time to wait between read/write activity before giving up\n"
    "\n"
    "   list_object_max_keys (default=\"1000\")\n"
    "      - specify the maximum number of keys returned by OSS list object\n"
    "        API. The default is 1000. you can set this value to 1000 or more.\n"
    "\n"
    "   max_stat_cache_size (default=\"100,000\" entries (about 40MB))\n"
    "      - maximum number of entries in the stat cache\n"
    "\n"
    "   stat_cache_expire (default is no expire)\n"
    "      - specify expire time(seconds) for entries in the stat cache.\n"
    "        This expire time indicates the time since stat cached.\n"
    "\n"
    "   enable_noobj_cache (default is disable)\n"
    "      - enable cache entries for the object which does not exist.\n"
    "      ossfs always has to check whether file(or sub directory) exists \n"
    "      under object(path) when ossfs does some command, since ossfs has \n"
    "      recognized a directory which does not exist and has files or \n"
    "      sub directories under itself. It increases ListBucket request \n"
    "      and makes performance bad.\n"
    "      You can specify this option for performance, ossfs memorizes \n"
    "      in stat cache that the object(file or directory) does not exist.\n"
    "\n"
    "   no_check_certificate\n"
    "      - server certificate won't be checked against the available \n"
	"      certificate authorities.\n"
    "\n"
    "   nodnscache (disable dns cache)\n"
    "      - ossfs is always using dns cache, this option make dns cache disable.\n"
    "\n"
    "   nosscache (disable ssl session cache)\n"
    "      - ossfs is always using ssl session cache, this option make ssl \n"
    "      session cache disable.\n"
    "\n"
    "   multireq_max (default=\"20\")\n"
    "      - maximum number of parallel request for listing objects.\n"
    "\n"
    "   parallel_count (default=\"5\")\n"
    "      - number of parallel request for uploading big objects.\n"
    "      ossfs uploads large object(over 20MB) by multipart post request, \n"
    "      and sends parallel requests.\n"
    "      This option limits parallel request count which ossfs requests \n"
    "      at once. It is necessary to set this value depending on a CPU \n"
    "      and a network band.\n"
    "\n"
    "   multipart_size (default=\"10\")\n"
    "      - part size, in MB, for each multipart request.\n"
    "\n"
    "   ensure_diskfree (default 0)\n"
    "      - sets MB to ensure disk free space. ossfs makes file for\n"
    "        downloading, uploading and caching files. If the disk free\n"
    "        space is smaller than this value, ossfs do not use diskspace\n"
    "        as possible in exchange for the performance.\n"
    "\n"
    "   singlepart_copy_limit (default=\"512\")\n"
    "      - maximum size, in MB, of a single-part copy before trying \n"
    "      multipart copy.\n"
    "\n"
    "   url (default=\"https://oss.cn-north-3.inspurcloudoss.com\")\n"
    "      - sets the url to use to access InspurCloud OSS. If you want to use HTTP,\n"
    "        then you can set \"url=http://oss.cn-north-3.inspurcloudoss.com\".\n"
    "        If you do not use https, please specify the URL with the url\n"
    "        option.\n"
    "\n"
    "   endpoint (default=\"cn-north-3\")\n"
    "      - sets the endpoint to use on signature version 4\n"
    "      If this option is not specified, ossfs uses \"cn-north-3\" region as\n"
    "      the default. If the ossfs could not connect to the region specified\n"
    "      by this option, ossfs could not run. But if you do not specify this\n"
    "      option, and if you can not connect with the default region, ossfs\n"
    "      will retry to automatically connect to the other region. So ossfs\n"
    "      can know the correct region name, because ossfs can find it in an\n"
    "      error from the OSS server.\n"
    "\n"
    "   sigv4 (default is signature version 2)\n"
    "      - sets signing OSS requests by using Signature Version 4\n"
    "\n"
    "   mp_umask (default is \"0000\")\n"
    "      - sets umask for the mount point directory.\n"
    "      If allow_other option is not set, ossfs allows access to the mount\n"
    "      point only to the owner. In the opposite case ossfs allows access\n"
    "      to all users as the default. But if you set the allow_other with\n"
    "      this option, you can control the permissions of the\n"
    "      mount point by this option like umask.\n"
    "\n"
    "   nomultipart (disable multipart uploads)\n"
    "\n"
    "   enable_content_md5 (default is disable)\n"
    "      Allow OSS server to check data integrity of uploads via the\n"
    "      Content-MD5 header.  This can add CPU overhead to transfers.\n"
    "\n"
    // TODO:
    // "   ecs\n"
    // "      - This option instructs ossfs to query the ECS container credential\n"
    // "      metadata address instead of the instance metadata address.\n"
    // "\n"
    // "   iam_role (default is no IAM role)\n"
    // "      - This option requires the IAM role name or \"auto\". If you specify\n"
    // "      \"auto\", ossfs will automatically use the IAM role names that are set\n"
    // "      to an instance. If you specify this option without any argument, it\n"
    // "      is the same as that you have specified the \"auto\".\n"
    // "\n"
    // "   ibm_iam_auth\n"
    // "      - This option instructs ossfs to use IBM IAM authentication.\n"
    // "      In this mode, the OSSAccessKey and OSSSecretKey will be used as\n"
    // "      IBM's Service-Instance-ID and APIKey, respectively.\n"
    // "\n"
    // "   ibm_iam_endpoint (default is https://iam.bluemix.net)\n"
    // "      - sets the url to use for IBM IAM authentication.\n"
    // "\n"
    "   use_xattr (default is not handling the extended attribute)\n"
    "      Enable to handle the extended attribute(xattrs).\n"
    "      If you set this option, you can use the extended attribute.\n"
    "      For example, encfs and ecryptfs need to support the extended attribute.\n"
    "      Notice: if ossfs handles the extended attribute, ossfs can not work to\n"
    "      copy command with preserve=mode.\n"
    "\n"
    "   noxmlns (disable registering xml name space)\n"
    "        disable registering xml name space for response of \n"
    "        ListBucketResult and ListVersionsResult etc. Default name \n"
    "        space is looked up from \"http://oss.cn-north-3.inspurcloudoss.com/doc/2006-03-01\".\n"
    "        This option should not be specified now, because ossfs looks up\n"
    "        xmlns automatically after v1.66.\n"
    "\n"
    "   nocopyapi (for other incomplete compatibility object storage)\n"
    "        For a distributed object storage which is compatibility OSS\n"
    "        API without PUT(copy api).\n"
    "        If you set this option, ossfs do not use PUT with \n"
    "        \"x-oss-copy-source\"(copy api). Because traffic is increased\n"
    "        2-3 times by this option, we do not recommend this.\n"
    "\n"
    "   norenameapi (for other incomplete compatibility object storage)\n"
    "        For a distributed object storage which is compatibility OSS\n"
    "        API without PUT(copy api).\n"
    "        This option is a subset of nocopyapi option. The nocopyapi\n"
    "        option does not use copy-api for all command(ex. chmod, chown,\n"
    "        touch, mv, etc), but this option does not use copy-api for\n"
    "        only rename command(ex. mv). If this option is specified with\n"
    "        nocopyapi, then ossfs ignores it.\n"
    "\n"
    "   use_path_request_style (use legacy API calling style)\n"
    "        Enable compatibility with OSS-like APIs which do not support\n"
    "        the virtual-host request style, by using the older path request\n"
    "        style.\n"
    "\n"
    "   noua (suppress User-Agent header)\n"
    "        Usually ossfs outputs of the User-Agent in \"ossfs/<version> (commit\n"
    "        hash <hash>; <using ssl library name>)\" format.\n"
    "        If this option is specified, ossfs suppresses the output of the\n"
    "        User-Agent.\n"
    "\n"
    "   dbglevel (default=\"crit\")\n"
    "        Set the debug message level. set value as crit(critical), err\n"
    "        (error), warn(warning), info(information) to debug level.\n"
    "        default debug level is critical. If ossfs run with \"-d\" option,\n"
    "        the debug level is set information. When ossfs catch the signal\n"
    "        SIGUSR2, the debug level is bumpup.\n"
    "\n"
    "   curldbg - put curl debug message\n"
    "        Put the debug message from libcurl when this option is specified.\n"
    "\n"
    "   cipher_suites - customize TLS cipher suite list\n"
    "        Customize the list of TLS cipher suites.\n"
    "        Expects a colon separated list of cipher suite names.\n"
    "        A list of available cipher suites, depending on your TLS engine,\n"
    "        can be found on the CURL library documentation:\n"
    "        https://curl.haxx.se/docs/ssl-ciphers.html\n"
    "\n"
    "   instance_name - The instance name of the current ossfs mountpoint.\n"
    "        This name will be added to logging messages and user agent headers sent by ossfs.\n"
    "\n"
    "   complement_stat (complement lack of file/directory mode)\n"
    "        ossfs complements lack of information about file/directory mode\n"
    "        if a file or a directory object does not have x-oss-meta-mode\n"
    "        header. As default, ossfs does not complements stat information\n"
    "        for a object, then the object will not be able to be allowed to\n"
    "        list/modify.\n"
    "\n"
    "   notsup_compat_dir (not support compatibility directory types)\n"
    "        As a default, ossfs supports objects of the directory type as\n"
    "        much as possible and recognizes them as directories.\n"
    "        Objects that can be recognized as directory objects are \"dir/\",\n"
    "        \"dir\", \"dir_$folder$\", and there is a file object that does\n"
    "        not have a directory object but contains that directory path.\n"
    "        ossfs needs redundant communication to support all these\n"
    "        directory types. The object as the directory created by ossfs\n"
    "        is \"dir/\". By restricting ossfs to recognize only \"dir/\" as\n"
    "        a directory, communication traffic can be reduced. This option\n"
    "        is used to give this restriction to ossfs.\n"
    "        However, if there is a directory object other than \"dir/\" in\n"
    "        the bucket, specifying this option is not recommended. ossfs may\n"
    "        not be able to recognize the object correctly if an object\n"
    "        created by ossfs exists in the bucket.\n"
    "        Please use this option when the directory in the bucket is\n"
    "        only \"dir/\" object.\n"
    "\n"
    "   use_wtf8 - support arbitrary file system encoding.\n"
    "        OSS requires all object names to be valid utf-8. But some\n"
    "        clients, notably Windows NFS clients, use their own encoding.\n"
    "        This option re-encodes invalid utf-8 object names into valid\n"
    "        utf-8 by mapping offending codes into a 'private' codepage of the\n"
    "        Unicode set.\n"
    "        Useful on clients not using utf-8 as their file system encoding.\n"
    "\n"
    "FUSE/mount Options:\n"
    "\n"
    "   Most of the generic mount options described in 'man mount' are\n"
    "   supported (ro, rw, suid, nosuid, dev, nodev, exec, noexec, atime,\n"
    "   noatime, sync async, dirsync).  Filesystems are mounted with\n"
    "   '-onodev,nosuid' by default, which can only be overridden by a\n"
    "   privileged user.\n"
    "   \n"
    "   There are many FUSE specific mount options that can be specified.\n"
    "   e.g. allow_other  See the FUSE's README for the full set.\n"
    "\n"
    "Utility mode Options:\n"
    "\n"
    " -u, --incomplete-mpu-list\n"
    "        Lists multipart incomplete objects uploaded to the specified\n"
    "        bucket.\n"
    " --incomplete-mpu-abort(=all or =<date format>)\n"
    "        Delete the multipart incomplete object uploaded to the specified\n"
    "        bucket.\n"
    "        If \"all\" is specified for this option, all multipart incomplete\n"
    "        objects will be deleted. If you specify no argument as an option,\n"
    "        objects older than 24 hours(24H) will be deleted(This is the\n"
    "        default value). You can specify an optional date format. It can\n"
    "        be specified as year, month, day, hour, minute, second, and it is\n"
    "        expressed as \"Y\", \"M\", \"D\", \"h\", \"m\", \"s\" respectively.\n"
    "        For example, \"1Y6M10D12h30m30s\".\n"
    "\n"
    "Miscellaneous Options:\n"
    "\n"
    " -h, --help        Output this help.\n"
    "     --version     Output version info.\n"
    " -d  --debug       Turn on DEBUG messages to syslog. Specifying -d\n"
    "                   twice turns on FUSE debug messages to STDOUT.\n"
    " -f                FUSE foreground option - do not run as daemon.\n"
    " -s                FUSE singlethreaded option\n"
    "                   disable multi-threaded operation\n"
    "\n"
  );
}

void show_version()
{
  printf(
  "InspurCloud Object Storage Service File System V%s(commit:%s) with %s\n"
  "Copyright (C) 2010 Randy Rizun <rrizun@gmail.com>\n"
  "License GPL2: GNU GPL version 2 <https://gnu.org/licenses/gpl.html>\n"
  "This is free software: you are free to change and redistribute it.\n"
  "There is NO WARRANTY, to the extent permitted by law.\n",
  VERSION, COMMIT_HASH_VAL, ossfs_crypt_lib_name());
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: noet sw=4 ts=4 fdm=marker
* vim<600: noet sw=4 ts=4
*/
