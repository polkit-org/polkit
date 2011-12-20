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

#ifndef NETGROUP_DEBUG_H_
#define NETGROUP_DEBUG_H_

#include "netgroup.h"

#include <stdio.h>

/**
 * Print entry and it's children to the given stream.
 * @param entry Netgroup entry to print
 * @param stream Stream to print to
 * @param indent Number of indents to use
 */
void netgroup_debug_print_entry(struct entry *entry, FILE *stream, unsigned int indent);

/**
 * Print a single netgroup to the given stream.
 * @param group Netgroup to print
 * @param stream Stream to print to
 * @param indent Number of indents to use
 */
void netgroup_debug_print_group(struct netgroup *group, FILE *stream, unsigned int indent);

/**
 * Print a single netgroup with all triples included recursively.
 * @param group Netgroup to print
 * @param stream Stream to print to
 * @param indent Number of indents to use
 */
void netgroup_debug_print_group_unrolled(struct netgroup *group, FILE *stream, unsigned int indent);

/**
 * Print all netgroups to the given stream.
 * @param head Head of list of netgroups
 * @param stream Stream to print to
 * @param indent Number of indents to use
 */
void netgroup_debug_print_all(struct netgroup *head, FILE *stream, unsigned int indent);

#endif
