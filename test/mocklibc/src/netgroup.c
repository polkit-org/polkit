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

#include <ctype.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define NETGROUP_CONFIG_KEY "MOCK_NETGROUP"
#define NETGROUP_TRIPLE_REGEX "\\(([^,]*),([^,]*),([^\\)]*)\\)"
#define FREE_IF_NOT_NULL(ptr) if (ptr) free(ptr)

/** Private methods. */

/**
 * Move the given pointer past any whitespace.
 * @param cur Pointer to string (char *) to advance
 */
static void parser_skip_whitespace(char **cur) {
  for (; isspace(**cur); (*cur)++) {}
}

/**
 * Copy the next group of non-space characters and move the pointer past
 * consumed characters.
 * @param cur Pointer to string (char *) to search/advance
 * @return Copy of chars consumed. Must be free'd by user.
 */
static char *parser_copy_word(char **cur) {
  char *value = *cur;
  size_t i;

  // Find the next non-null non-space character
  for (i = 0; !isspace(value[i]) && value[i] != '\0'; i++) {}

  // Don't allocate zero-length strings, just die
  if (i == 0) {
    return NULL;
  }

  // Allocate the new string, with room for a null terminator
  char *result = malloc(i + 1);
  if (!result) {
    return NULL;
  }

  // Set the current pointer past the parsed region
  *cur += i;

  memcpy(result, value, i);
  result[i] = '\0';
  return result;
}

/**
 * Print a varaible indentation to the stream.
 * @param stream Stream to print to
 * @param indent Number of indents to use
 */
void print_indent(FILE *stream, unsigned int indent) {
  int i;
  for (i = 0; i < indent; i++)
    fprintf(stream, "  ");
}

/**
 * Connect entries with 'child' type to their child entries.
 * @param headentry Head of list of entries that need to be connected
 * @param headgroup Head of list of netgroups to connect child entries to
 */
static void netgroup_connect_children(struct entry *headentry, struct netgroup *headgroup) {
  struct entry *curentry;
  for (curentry = headentry; curentry; curentry = curentry->next) {
    // Skip entries that don't have children
    if (curentry->type != CHILD_ENTRY)
      continue;

    // Set the entry's children to the head of the netgroup with the same name
    struct netgroup *group = netgroup_find(headgroup, curentry->data.child.name);
    if (group)
      curentry->data.child.head = group->head;
  }
}


/* Public methods. */

struct netgroup *netgroup_parse_all() {
  const char *path = getenv(NETGROUP_CONFIG_KEY);
  if (!path)
    return NULL;

  FILE *stream = fopen(path, "r");
  if (!stream)
    return NULL;

  struct netgroup *headgroup = NULL;
  struct netgroup *lastgroup = NULL;

  // Parse netgroups but don't fill in child entry pointers
  for (;;) {
    size_t line_alloc = 0;
    char * line = NULL;
    ssize_t line_size = getline(&line, &line_alloc, stream);
    if (line_size == -1)
      {
	free(line);
	break;
      }

    struct netgroup *nextgroup = netgroup_parse_line(line);
    free(line);
    if (!nextgroup)
      continue;

    if (!headgroup) {
      headgroup = nextgroup;
      lastgroup = nextgroup;
    } else {
      lastgroup->next = nextgroup;
      lastgroup = nextgroup;
    }
  }

  fclose(stream);

  // Fill in child entry pointers
  struct netgroup *curgroup;
  for (curgroup = headgroup; curgroup; curgroup = curgroup->next) {
    netgroup_connect_children(curgroup->head, headgroup);
  }

  return headgroup;
}

void netgroup_free_all(struct netgroup *head) {
  struct netgroup *group = head;
  struct netgroup *nextgroup;
  while (group) {
    nextgroup = group->next;
    netgroup_free(group);
    group = nextgroup;
  }
}

struct netgroup *netgroup_parse_line(char *line) {
  char *cur = line;

  // Get the netgroup's name
  parser_skip_whitespace(&cur);
  char *group_name = parser_copy_word(&cur);
  if (!group_name)
    return NULL;

  // Create new netgroup object
  struct netgroup *result = malloc(sizeof(struct netgroup));
  if (!result)
    return NULL;
  result->next = NULL;
  result->name = group_name;
  result->head = NULL;

  // Fill in netgroup entries
  struct entry* lastentry = NULL;
  for (;;) {
    // Get the next word (anything non-space and non-null)
    parser_skip_whitespace(&cur);
    char *word = parser_copy_word(&cur);
    if (!word)
      break;

    // Parse the entry
    struct entry *entry = netgroup_parse_entry(word);
    free(word);
    if (!entry)
      continue;

    // Connect the entries together in a singly-linked list
    if (lastentry) {
      lastentry->next = entry;
    } else {
      result->head = entry;
    }

    lastentry = entry;
  }

  return result;
}

void netgroup_free(struct netgroup *group) {
  if (!group)
    return;

  free(group->name);
  netgroup_entry_free_all(group->head);
  free(group);
}

struct entry *netgroup_parse_entry(const char *value) {
  // Initialize the regex to match triples only on first call
  static int regex_needs_init = 1;
  static regex_t regex_triple;
  if (regex_needs_init) {
    if (regcomp(&regex_triple, NETGROUP_TRIPLE_REGEX, REG_EXTENDED))
      return NULL;
    regex_needs_init = 0;
  }

  struct entry *result = malloc(sizeof(struct entry));
  if (!result)
    return NULL;

  memset(result, 0, sizeof(struct entry));

  regmatch_t regex_triple_match [4];
  if (regexec(&regex_triple, value, 4, regex_triple_match, 0) == REG_NOMATCH) {
    // Match failed, assume entry is a netgroup name
    result->type = CHILD_ENTRY;
    result->data.child.name = strdup(value);
    if (!result->data.child.name) {
      netgroup_entry_free(result);
      return NULL;
    }
  } else {
    // Match success, entry is a triple
    result->type = TRIPLE_ENTRY;

    // Array of pointers to fields to set in triple
    char ** triple [3] = {
        &result->data.triple.hostname,
        &result->data.triple.username,
        &result->data.triple.domainname };
    int i;

    // Loop through each potential field in triple
    for (i = 0; i < 3; i++) {
      regoff_t start = regex_triple_match[i + 1].rm_so;
      regoff_t end = regex_triple_match[i + 1].rm_eo;
      regoff_t len = end - start;

      if (start == -1 || len == 0) {
        // This field is empty, so it matches anything
        *triple[i] = NULL;
      } else {
        // Allocate and copy new field for triple
        char *field = malloc(len + 1);
        if (!field) {
          netgroup_entry_free(result);
          return NULL;
        }
        memcpy(field, &value[start], len);
        field[len] = '\0';
        *triple[i] = field;
      }
    }
  }
  return result;
}

void netgroup_entry_free_all(struct entry *head) {
  struct entry *entry = head;
  struct entry *nextentry;
  while (entry) {
    nextentry = entry->next;
    netgroup_entry_free(entry);
    entry = nextentry;
  }
}

void netgroup_entry_free(struct entry *entry) {
  if (!entry)
    return;

  if (entry->type == TRIPLE_ENTRY) {
    FREE_IF_NOT_NULL(entry->data.triple.hostname);
    FREE_IF_NOT_NULL(entry->data.triple.username);
    FREE_IF_NOT_NULL(entry->data.triple.domainname);
  } else {
    FREE_IF_NOT_NULL(entry->data.child.name);
  }

  free(entry);
}

struct netgroup *netgroup_find(struct netgroup *head, const char *name) {
  struct netgroup *group;
  for (group = head; group && strcmp(group->name, name); group = group->next) {}
  return group;
}

void netgroup_iter_init(struct netgroup_iter *iter, struct netgroup *group) {
  iter->stack[0] = group->head;
  iter->depth = 0;
}

struct entry *netgroup_iter_next(struct netgroup_iter *iter) {
  while (iter->depth >= 0) {
    struct entry *cur = iter->stack[iter->depth];

    if (!cur) {
      // Pop current finished entry off stack
      iter->depth--;
    } else if (cur->type == CHILD_ENTRY) {
      // Replace the current location on the stack with the next sibling
      iter->stack[iter->depth] = cur->next;

      // Grow the stack
      iter->depth++;
      if (iter->depth >= NETGROUP_MAX_DEPTH) {
        iter->depth = -1;
        return NULL; // Too much recursion
      }

      // Put this entry's children on top of the stack
      struct entry *child = cur->data.child.head;
      iter->stack[iter->depth] = child;
    } else {
      // Replace the current location on the stack with the next sibling
      iter->stack[iter->depth] = cur->next;
      return cur;
    }
  }

  return NULL;
}
