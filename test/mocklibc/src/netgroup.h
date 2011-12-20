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

#ifndef NETGROUP_H_
#define NETGROUP_H_

#define NETGROUP_MAX_DEPTH 32

/**
 * Netgroup with a name and list of entries.
 */
struct netgroup;

/**
 * Entry in a netgroup, either a triple or sub-group (child).
 */
struct entry;

struct netgroup {
  /* Next netgroup in list. */
  struct netgroup *next; // Next netgroup in list

  /* Netgroup name. */
  char *name;

  /* First entry in list of entries. */
  struct entry *head;
};

struct entry {
  /* Next entry in list of entries for the parent netgroup. */
  struct entry *next;

  /* Entry type is triple (host,user,domain) or child (netgroup name). */
  enum {CHILD_ENTRY, TRIPLE_ENTRY} type;

  union {
    /* Child data if entry is a netgroup name. */
    struct {
      /* Child netgroup name. */
      char *name;

      /* Pointer to first entry in child netgroup. */
      struct entry *head;
    } child;

    /* Triple data if entry type is triple. */
    struct {
      char *hostname;
      char *username;
      char *domainname;
    } triple;
  } data;
};

/* Recursive netgroup entry iterator. */
struct netgroup_iter {
  struct entry *stack [NETGROUP_MAX_DEPTH];
  int depth;
};


/**
 * Load full netgroup database into memory.
 * @return Head netgroup
 */
struct netgroup *netgroup_parse_all();

/**
 * Free a list of netgroups.
 * @param head Head of list of netgroups
 */
void netgroup_free_all(struct netgroup *head);

/**
 * Parse a single netgroup.
 * @param line Line for netgroup definition
 * @return Single netgroup with list of netgroup entries
 */
struct netgroup *netgroup_parse_line(char *line);

/**
 * Free single netgroup.
 * @param group Netgroup to free
 */
void netgroup_free(struct netgroup *group);

/**
 * Parse a single netgroup entry.
 * @param value Entry triple or name as string
 * @return Single netgroup entry
 */
struct entry *netgroup_parse_entry(const char *value);

/**
 * Free a list of netgroup entries.
 * @param head Head of list of entries
 */
void netgroup_entry_free_all(struct entry *head);

/**
 * Free a single netgroup entry.
 * @param entry Netgroup entry to free
 */
void netgroup_entry_free(struct entry *entry);

/**
 * Find netgroup with given name.
 * @param head Head of list of netgroups
 * @param name Name to find
 * @return Netgroup with name or NULL if not found
 */
struct netgroup *netgroup_find(struct netgroup *head, const char *name);

/**
 * Create recursive iterator over all entries in a netgroup.
 * @param iter Pointer to iterator struct
 * @param group Group to iterate over
 */
void netgroup_iter_init(struct netgroup_iter *iter, struct netgroup *group);

/**
 * Get the next entry in the netgroup iterator.
 * @param iter Pointer to iterator struct
 * @return Netgroup entry of type triple, or NULL if done iterating
 */
struct entry *netgroup_iter_next(struct netgroup_iter *iter);

#endif
