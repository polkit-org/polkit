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

#include "netgroup.h"

#include <netdb.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define INNETGR_CHECK(match, value) if (match && value && strcmp(match, value)) continue;

/** Private static data. */

static struct netgroup *global_netgroup_head = NULL;
static struct netgroup_iter global_iter;

/** Public methods */

// REMEMBER: 1 means success, 0 means failure for netgroup methods

int setnetgrent(const char *netgroup) {
  if (!global_netgroup_head)
    global_netgroup_head = netgroup_parse_all();

  struct netgroup *group = netgroup_find(global_netgroup_head, netgroup);
  if (!group) {
     netgroup_free_all(global_netgroup_head);
    global_netgroup_head = NULL;
    return 0;
  }

  netgroup_iter_init(&global_iter, group);
  return 1;
}

void endnetgrent(void) {
  netgroup_free_all(global_netgroup_head);
  global_netgroup_head = NULL;
}

int getnetgrent(char **host, char **user, char **domain) {
  if (!global_netgroup_head)
    return 0;

  struct entry *result = netgroup_iter_next(&global_iter);
  if (!result)
    return 0;

  *host = result->data.triple.hostname;
  *user = result->data.triple.username;
  *domain = result->data.triple.domainname;
  return 1;
}

int innetgr(const char *netgroup, const char *host, const char *user,
    const char *domain) {
  int retval = 0;
  struct netgroup *head = netgroup_parse_all();
  struct netgroup *group = netgroup_find(head, netgroup);
  if (!group) {
    // Can't find group
    netgroup_free_all(head);
    return 0;
  }

  struct netgroup_iter iter;
  netgroup_iter_init(&iter, group);

  struct entry *cur;
  while ((cur = netgroup_iter_next(&iter))) {
    INNETGR_CHECK(host, cur->data.triple.hostname);
    INNETGR_CHECK(user, cur->data.triple.username);
    INNETGR_CHECK(domain, cur->data.triple.domainname);

    // No INNETGR_CHECK failed, so we matched!
    retval = 1;
    break;
  }

  netgroup_free_all(head);
  return retval;
}
