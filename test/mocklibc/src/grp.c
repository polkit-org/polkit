/**
 * Copyright 2011 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author: Nikki VonHollen <vonhollen@gmail.com>
 */

#include <grp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define GROUP_CONFIG_KEY "MOCK_GROUP"

static FILE *global_stream = NULL;

void setgrent(void) {
  if (global_stream)
    endgrent();

  const char *path = getenv(GROUP_CONFIG_KEY);
  if (!path)
    return;

  global_stream = fopen(path, "r");
}

struct group *getgrent(void) {
  if (!global_stream)
    setgrent();

  if (!global_stream)
    return NULL;

  return fgetgrent(global_stream);
}

void endgrent(void) {
  if (!global_stream)
    return;

  fclose(global_stream);
  global_stream = NULL;
}

struct group *getgrnam(const char *name) {
  const char *path = getenv(GROUP_CONFIG_KEY);
  if (!path)
    return NULL;

  FILE *stream = fopen(path, "r");
  if (!stream)
    return NULL;

  struct group *entry;
  while ((entry = fgetgrent(stream))) {
    if (strcmp(entry->gr_name, name) == 0) {
      fclose(stream);
      return entry;
    }
  }

  fclose(stream);
  return NULL;
}

struct group *getgrgid(gid_t gid) {
  const char *path = getenv(GROUP_CONFIG_KEY);
  if (!path)
    return NULL;

  FILE *stream = fopen(path, "r");
  if (!stream)
    return NULL;

  struct group *entry;
  while ((entry = fgetgrent(stream))) {
    if (entry->gr_gid == gid) {
      fclose(stream);
      return entry;
    }
  }

  fclose(stream);
  return NULL;
}

int getgrouplist(const char *user, gid_t group, gid_t *groups, int *ngroups) {
  const char *path = getenv(GROUP_CONFIG_KEY);
  if (!path) {
    *ngroups = 0;
    return -1;
  }

  FILE *stream = fopen(path, "r");
  if (!stream) {
    *ngroups = 0;
    return -1;
  }

  int default_group_found = 0;
  int groups_found = 0;

  // Loop through all groups
  struct group *entry;
  while ((entry = fgetgrent(stream))) {
    // Loop through all users in group
    char **cur_user;
    for (cur_user = entry->gr_mem; *cur_user; cur_user++) {
      // Skip users who don't match arg 'user'
      if (strcmp(*cur_user, user))
        continue;

      // Is this the default group? if so, flag it
      if (entry->gr_gid == group)
        default_group_found = 1;

      // Only insert new entries if we have room
      if (groups_found < *ngroups) {
        groups[groups_found] = entry->gr_gid;
      }

      groups_found++;
    }
  }

  // Include the default group if it wasn't found
  if (!default_group_found) {
    if (groups_found < *ngroups) {
      groups[groups_found] = group;
    }
    groups_found++;
  }

  // Did we have to leave out some groups? If not, tell how many we found.
  int retval = (groups_found > *ngroups) ? -1 : groups_found;

  // Always tell the user how many groups we found via *ngroups
  *ngroups = groups_found;

  fclose(stream);
  return retval;
}
