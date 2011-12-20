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

#include "netgroup-debug.h"

#include <stdio.h>
#include <stdlib.h>

void netgroup_debug_print_entry(struct entry *entry, FILE *stream, unsigned int indent) {
  print_indent(stream, indent);

  if (entry->type == TRIPLE_ENTRY) {
    fprintf(stream, "triple (%s,%s,%s)\n",
        entry->data.triple.hostname,
        entry->data.triple.username,
        entry->data.triple.domainname);
  } else if (entry->type == CHILD_ENTRY) {
    fprintf(stream, "child '%s'\n", entry->data.child.name);
    struct entry *child;
    for (child = entry->data.child.head; child; child = child->next) {
      netgroup_debug_print_entry(child, stream, indent + 1);
    }
  } else {
    fprintf(stream, "UNKNOWN_TYPE");
  }
}

void netgroup_debug_print_group(struct netgroup *group, FILE *stream, unsigned int indent) {
  print_indent(stream, indent);
  fprintf(stream, "%s\n", group->name);
  struct entry *entry;
  for (entry = group->head; entry; entry = entry->next) {
    netgroup_debug_print_entry(entry, stream, indent + 1);
  }
}

void netgroup_debug_print_group_unrolled(struct netgroup *group, FILE *stream, unsigned int indent) {
  print_indent(stream, indent);
  fprintf(stream, "%s\n", group->name);

  struct netgroup_iter iter;
  netgroup_iter_init(&iter, group);

  struct entry *entry;
  while ((entry = netgroup_iter_next(&iter))) {
    netgroup_debug_print_entry(entry, stream, indent + 1);
  }
}

void netgroup_debug_print_all(struct netgroup *head, FILE *stream, unsigned int indent) {
  struct netgroup *group;
  for (group = head; group; group = group->next) {
    netgroup_debug_print_group(group, stream, indent);
  }
}

int main(int argc, char **argv) {
  struct netgroup *groups = netgroup_parse_all();
  if (argc == 1)
    netgroup_debug_print_all(groups, stdout, 0);
  else if (argc == 2) {
    struct netgroup *group = netgroup_find(groups, argv[1]);
    if (!group)
      return 1;
    netgroup_debug_print_group_unrolled(group, stdout, 0);
  }

  return 0;
}
