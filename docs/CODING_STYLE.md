# Coding Style

The project uses the following formatting conventions (also specified in `.editorconfig`).

## Formatting Rules

- **Indentation:** 2 spaces (no tabs)
- **Line length:** Soft limit of 109 characters
- **Brace style:** Opening brace on the same line for `if`/`else`/`for`/`while`; opening brace on a new line for function bodies
- **Newlines:** LF only, with a final newline at end of file
- **Trailing whitespace:** Not allowed

## Function Definitions

Function return type and qualifiers go on a separate line from the function name.
Parameters are aligned vertically:

```c
static gboolean
load_key_from_config_file (const gchar *filename,
                           const gchar *section,
                           const gchar *key,
                           gchar **ret_value)
{
  ...
}
```

## Naming Conventions

- **Types:** `PascalCase` with project/module prefix — `PolkitAuthority`, `PolkitBackendSessionMonitor`
- **Functions:** `snake_case` with full module prefix — `polkit_authority_check_authorization()`, `polkit_backend_session_monitor_get_user_for_subject()`
- **Macros/Constants:** `UPPER_SNAKE_CASE` — `POLKIT_TYPE_AUTHORITY`, `POLKIT_IS_SUBJECT`
- **Private struct fields:** No prefix, plain `snake_case`
- **Enum values:** `UPPER_SNAKE_CASE` — `POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED`
- **Local variables:** Short `snake_case` — `ret`, `error`, `loop`
- **Output parameters:** Prefixed with `out_` or `ret_` — `gchar **ret_value`, `PolkitImplicitAuthorization *out_implicit_authorization`

## Header Guards

Double-underscore traditional style:

```c
#ifndef __POLKIT_IDENTITY_H
#define __POLKIT_IDENTITY_H
...
#endif /* __POLKIT_IDENTITY_H */
```

## Private Header Inclusion Guards

Public headers enforce single-entry-point inclusion:

```c
#if !defined (_POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_H)
#error "Only <polkit/polkit.h> can be included directly, this file may disappear or change contents."
#endif
```

## Section Separators

Visual section markers within source files:

```c
/* ---------------------------------------------------------------------------------------------------- */
```

## Error Handling

Follows the `GError` pattern with `goto out` cleanup:

```c
static gboolean
some_function (const gchar *input,
               GError     **error)
{
  gboolean ret = FALSE;
  gchar *value = NULL;

  value = do_something (input, error);
  if (value == NULL)
    goto out;

  /* success */
  ret = TRUE;

out:
  g_free (value);
  return ret;
}
```

## Control Flow

- Braces on the next line, indented from the block opener:
```c
  if (registration_id == NULL)
    {
      g_printerr ("Error registering authority: %s\n", error->message);
      g_error_free (error);
      g_main_loop_quit (loop);
    }
```
- Single-statement bodies may omit braces but must still use the next-line brace style for multi-line conditions

## Documentation

- gtk-doc format for all public API functions and types:
```c
/**
 * polkit_backend_authority_get_name:
 * @authority: A #PolkitBackendAuthority.
 *
 * Gets the name of the authority backend.
 *
 * Returns: The name of the backend.
 */
```

- `SECTION` documentation blocks at the top of source files:
```c
/**
 * SECTION:polkitauthority
 * @title: PolkitAuthority
 * @short_description: Authority
 * @stability: Stable
 */
```

## License Headers

Every source file begins with an LGPL-2.0+ license block:

```c
/*
 * Copyright (C) <year> <holder>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * ...
 *
 * Author: <name> <email>
 */
```
