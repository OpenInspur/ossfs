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

#ifndef OSSFS_SEMAPHORE_H_
#define OSSFS_SEMAPHORE_H_

// portability wrapper for sem_t since macOS does not implement it

#ifdef __APPLE__

#include <dispatch/dispatch.h>

class Semaphore
{
  public:
    explicit Semaphore(int value) : value(value), sem(dispatch_semaphore_create(value)) {}
    ~Semaphore() {
      // macOS cannot destroy a semaphore with posts less than the initializer
      for(int i = 0; i < get_value(); ++i){
        post();
      }
      dispatch_release(sem);
    }
    void wait() { dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER); }
    void post() { dispatch_semaphore_signal(sem); }
    int get_value() const { return value; }
  private:
    const int value;
    dispatch_semaphore_t sem;
};

#else

#include <errno.h>
#include <semaphore.h>

class Semaphore
{
  public:
    explicit Semaphore(int value) : value(value) { sem_init(&mutex, 0, value); }
    ~Semaphore() { sem_destroy(&mutex); }
    void wait()
    {
      int r;
      do {
        r = sem_wait(&mutex);
      } while (r == -1 && errno == EINTR);
    }
    void post() { sem_post(&mutex); }
    int get_value() const { return value; }
  private:
    const int value;
    sem_t mutex;
};

#endif

#endif // OSSFS_SEMAPHORE_H_
