## polkit 123

### Highlights:
- better safety with deeper resctiction of the configuration files
- better safety with restricting the daemon's owner under systemd
- better safety with the systemd unit sandboxing
- less thread races during upload of the configuration

### Build requirements
- glib, gobject, gio >= 2.32
- mozjs-102 OR duktape
- gobject-introspection >= 0.6.2 (optional)
- pam (optional)
- ConsoleKit OR systemd
- gettext
- meson

### Changes since polkit 122:

* Laurent Gauthier
    * prevent wrongful termination of runaway thread
* Luca Boccassi
    * Stop installing /usr/share/polkit-1/rules.d as 700/polkitd
    * set User/Group and don't change uid/gid if already set
* bboy_vi, liudun, Marco Trevisan, Marius Bakke, Matej Focko, Olivier Duchateau, Sam James, Val Packett
    * general and/or buildsystem fixes
* Topi Miettinen
    * systemd service hardening
* Vincent Mihalkovic
    * Packit service integration
    * pkcheck: manpage and help sync
    * general fixes
* Jan Rybar
    * Packit service integration
    * change of ownership of custom configs
    * general fixes
* Aleksandr Melman, Anders Jonsson, Jürgen Benvenuti, Piotr Drąg, Sabri Unal
    * localization


**Thanks to everyone involved for making this possible!**

The polkit team & polkit community
July 28, 2023
## polkit 122

### Highlights:
- new Georgian translation
- port to mozjs-102
- daemon-less build (support for e.g. flatpak deps)
- re-enable of (API) documentation build

### Build requirements
- glib, gobject, gio >= 2.32
- mozjs-102 OR duktape
- gobject-introspection >= 0.6.2 (optional)
- pam (optional)
- ConsoleKit OR systemd
- gettext
- meson

### Changes since polkit 121:

* Anders Jonsson
    * Swedish translation
* NorwayFun
    * Georgian translation
* Martin Kletzander
    * several pkttyagent fixes and improvements
* A. Wilcox
    * optional netgroup support
* Luca Boccassi
    * move 50-default.rules to /usr/share
* Michael Biebl
    * remove useless ifclause from meson.build
* Jordan Petridis
    * improve error message
* Luciano Santos
    * honour pam_prefix meson option
* Xi Ruoyao
    * meson: lfs autodetection
    * port to mozjs-102
* Peter Eisenmann
    * daemonless build option

Thanks to everyone involved for making this possible!

The polkit team & polkit community
October 26, 2022

## polkit 121

### Highlights:
- new versioning
- duktape added as backend JS engine
- autotools build system removed
- new translations

### Build requirements
- glib, gobject, gio >= 2.32
- mozjs-91 OR duktape
- gobject-introspection >= 0.6.2 (optional)
- pam (optional)
- ConsoleKit OR systemd
- gettext
- meson

### Changes since polkit 0.120:

* Simon McVittie
    * meson and testsuite fixes
* Bastien Nocera
    * add ability to create policyconfig-1.dtd file
* Xi Ruoyao
    * port to newer mozjs-91, jsauthority tweaks
* Wu Xiaotian and Gustavo Lima Chaves
    * Add duktape as javascript engine
* Nathan Follens
    * Dutch translation
* Daniel E
    * duktape fixup
* Fabrice Fontaine
    * fix build without C++
* Dan Nicholson
    * fixup in group permision checking (backend)
* Phaedrus Leeds
    * typo fix
* Adrian Vovk
    * add option (--keep-cwd) for pkexec
* Matt Turner
    * Allow --version and --help even if not setuid root
* Benedikt Ames
    * fixes in polkitagent
* Vincent Mihalkovic
    * development support

Thanks to everyone involved for making this possible!

Jan Rybar & polkit team
June 27, 2022

## polkit 0.120

**WARNING**: This is a prerelease on the road to polkit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

### NOTICE:
This is the LAST version to support AUTOTOOLS build system, as it has been obsoleted
by meson build system.
The next release of polkit will REQUIRE meson build system.

### Highlights:
- tarball fix-ups
- re-enabled documentation
- Intltool to gettext migration
- new translations

### Build requirements
- glib, gobject, gio >= 2.32
- mozjs-78
- gobject-introspection >= 0.6.2 (optional)
- pam (optional)
- ConsoleKit OR systemd
- gettext
- meson (optional)
- autotools (DEPRECATED)

### Changes since polkit 0.119:
- Inigo Martinez:
        transition from Intltool to gettext

- Simon McVittie:
        several tarball, meson and pipeline fixups

- Hugo Carvalho:
        Portuguese translation

- Sergiu Bivol:
        Romanian translation


Many thanks to all contributors!

Jan Rybar et al.,
September 30, 2021


## polkit 0.119
**WARNING**: This is a prerelease on the road to polkit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

This is polkit **0.119**.

### Highlights:
- meson build system added
- CVE-2021-3560 mitigation

### Build requirements
- glib, gobject, gio >= 2.32
- mozjs-78
- gobject-introspection >= 0.6.2 (optional)
- pam (optional)
- ConsoleKit OR systemd

### Changes since polkit 0.118:
- Inigo Martinez:
        meson build system added alongside autotools (many thanks!!)

- Matthias Classen:
        properties in text listener

- René Genz:
        typos fixups

- Balázs Úr:
        Update Hungarian translation

- Hendrik Werner:
        meson post-install script mod to avoid calling external processes

- Kevin Backhouse, Jan Rybar:
        CVE-2021-3560 mitigation

Many thanks to all contributors!

Jan Rybar et al.,
June 3, 2021

## polkit 0.118

**WARNING**: This is a prerelease on the road to polkit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

This is polkit **0.118**.

### Highlights:
- move to mozjs78
- tarball CI fix

### Build requirements
- glib, gobject, gio >= 2.32
- mozjs-78
- gobject-introspection >= 0.6.2 (optional)
- pam (optional)
- ConsoleKit OR systemd

### Changes since polkit 0.117:
- Xi Ruoyao:
    tarball fixup for distcheck

- Valentin David:
    updated dependency to mozjs78

Many thanks to all contributors!

Jan Rybar et al.,
September 8, 2020

## polkit 0.117

**WARNING**: This is a prerelease on the road to polkit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

This is polkit **0.117**.

### Highlights:
 Gitlab CI activation - all merge requests are tested before merged
 New Norwegian translation, several other language updates

### Build requirements
- glib, gobject, gio    >= 2.32
- mozjs-68
- gobject-introspection >= 0.6.2 (optional)
- pam (optional)
- ConsoleKit OR systemd

### Changes since polkit 0.116:
 - Bastien Nocera:
    Activated Gitlab CI

 - Xi Ruoyao:
    Updated dependency to mozjs68

 - Kalev Lember, Jan Rybar
    Memory management fixes

 - Anders Jonsson, Karl Ove Hufthammer, Andika Triwidada, Yuri Chornoivan:
    Language updates

Many thanks to all contributors!

Jan Rybar et al.,
July 24, 2020

polkit 0.116
------------

**WARNING**:
This is a prerelease on the road to polkit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

This is polkit **0.116**.

### Highlights:
 - Fix of CVE-2018-19788, high UIDs caused overflow in polkit;
 - Fix of CVE-2019-6133, kernel vulnerability (Slowfork) allowed local privilege escalation.

### Build requirements:
 - glib, gobject, gio    >= 2.32
 - mozjs-60
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)
 - ConsoleKit OR systemd

### Changes since polkit 0.115:
 - Kyle Walker:
    Leaking zombie child processes

 - Jan Rybar:
    Possible resource leak found by static analyzer
    Output messages tuneup
    Sanity fixes
    pkttyagent tty echo disabled on SIGINT

 - Ray Strode:
    HACKING: add link to Code of Conduct

 - Philip Withnall:
    polkitbackend: comment typos fix

 - Zbigniew Jędrzejewski-Szmek:
    `configure.ac`: fix detection of systemd with cgroups v2
    CVE-2018-19788 High UIDs overflow fix

 - Colin Walters:
    CVE-2019-6133 Slowfork vulnerability fix

 - Matthew Leeds:
    Allow unset process-uid

 - Emmanuele Bassi
    Port the JS authority to mozjs-60

 - Göran Uddeborg:
    Use JS_EncodeStringToUTF8

Many thanks to all contributors!

Jan Rybar et al.,
April 25, 2019

---------------
polkit 0.115
--------------

**WARNING:**
This is a prerelease on the road to polkit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

This is polkit **0.115**.

### Highlights:
 -  Fixes CVE-2018-1116, a local information disclosure and denial of service
 caused by trusting client-submitted UIDs when referencing processes.
 Thanks to Matthias Gerstner of the SUSE security team for reporting
 this issue.

### Build requirements:

 - glib, gobject, gio    >= 2.32
 - mozjs-52
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)
 - ConsoleKit OR systemd

### Changes since polkit 0.114:

 - Miloslav Trmač (1):
    Fix CVE-2018-1116: Trusting client-supplied UID

 - Ray Strode (3):
    Post-release version bump to 0.115
    jsauthority: pass "%s" format string to remaining report function
    NEWS: fix date from 2017 to 2018 for 0.114 entry

Thanks to our contributors.

Colin Walters and Miloslav Trmač,
July 10, 2018

--------------
polkit 0.114
--------------

**WARNING:**
This is a prerelease on the road to polkit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

This is polkit **0.114**.

### Highlights:
 Port to mozjs 52, the latest version of the firefox JavaScript engine.

 Add gettext support for policy files

 Fixes for various memory leaks

### Build requirements:

 - glib, gobject, gio    >= 2.32
 - mozjs-52
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)
 - ConsoleKit OR systemd

### Changes since polkit 0.113:

 - Anders Jonsson (2):
    pkcheck: fix man typos
    Add Swedish translation

 - Antoine Jacoutot (1):
    Add support for OpenBSD

 - Christian Kirbach (1):
    Add German translation

 - Colin Walters (3):
    build: Pull in GCC warning infra from ostree
    build: Use AC_USE_SYSTEM_EXTENSIONS
    tests: Correct boundary test for overflow

 - Dariusz Gadomski (2):
    Fix multi-line pam text info.
    Refactor send_to_helper usage

 - Gabor Kelemen (1):
    Add initial Hungarian translation, and add hu to LINGUAS

 - Jeremy Linton (5):
    change mozjs interface module to c++
    Switch to hard requiring mozjs24
    Fix warnings caused by building with C++
    Replace autocompartment
    test: Add a test case to handle actions without explicit rules

 - Jiří Klimeš (1):
    trivial: fix deprecated indication for polkit_agent_register_listener()

 - Matthias Clasen (1):
    Add gettext support for .policy files

 - Miloslav Trmač (21):
    Post-release version bump to 0.114
    Consistently use HAVE_NETGROUP_H instead of HAVE_OPENBSD
    Fix a memory leak of PolkitAgentListener's Server object
    Remove polkitbackendconfigsource.[ch]
    Add Slovak translation by Dusan Kazik <prescott66@gmail.com>
    Add Indonesian translation by Andika Triwidada
    Add Chinese (Taiwan) translation
    Fix a typo in polkit(8)
    Simplify GVariant reference counting
    Fix a memory leak on an error path of lookup_asv (twice)
    Fix a memory leak in server_handle_register_authentication_agent_with_options
    Fix a memory leak in server_handle_unregister_authentication_agent
    Fix a memory leak in server_handle_authentication_agent_response{,2}
    Fix memory leaks in server_handle_*_temporary_authorizations
    Fix error handling in polkit_authority_enumerate_temporary_authorizations_finish
    Fix a memory leak per agent authentication
    Fix a memory leak on agent authentication cancellation
    Audit and fix GVariant reference counting
    Fix help for (pkttyagent -s)
    Fix a race condition when terminating runaway_killer_thread
    Move to current GLib

 - Mingye Wang (Arthur2e5) (1):
    Add zh_CN translation

 - Muhammet Kara (1):
    Added Turkish translation

 - OBATA Akio (1):
    Add support for NetBSD

 - Peter Hutterer (1):
    gettext: switch to default-translate "no"

 - Philip Withnall (3):
    polkit: Add g_autoptr() support for GObject-derived polkit types
    data: Set GIO_USE_VFS=local in the environment
    polkitbackend: Fix typos in a couple of initialisation error messages

 - Piotr Drąg (1):
    Add Polish translation

 - Rafael Fontenelle (1):
    Add Brazilian Portuguese translation

 - Ray Strode (34):
    configure: bump mozjs requirement to 52
    jsauthority: fix how classes are defined
    jsauthority: use JS_FN instead of JS_FS
    jsauthority: get rid of JSRuntime
    jsauthority: change how setVersion is called
    jsauthority: call JS_Init
    jsauthority: call JS_InitSelfHostedCode
    jsauthority: change how JIT is disabled
    jsauthority: JS::SetWarningReporter instead of JS_SetErrorReporter
    jsauthority: add UTF8 suffix to renamed functions
    jsauthority: pass "%s" format string to report functions
    jsauthority: s/JSBool/bool/
    jsauthority: s/jsval/JS::Value/
    jsauthority: s/JSVAL_NULL/JS::NullValue()/
    jsauthority: s/JSVAL_VOID/JS::UndefinedValue()/
    jsauthority: s/OBJECT_TO_JSVAL/JS::ObjectValue/
    jsauthority: s/STRING_TO_JSVAL/JS::StringValue/
    jsauthority: s/BOOLEAN_TO_JSVAL/JS::BooleanValue/
    jsauthority: JSVAL_TO_OBJECT (o) to o.toObjectOrNull()
    jsauthority: JSVAL_TO_STRING (s) to s.toString()
    jsauthority: JSVAL_IS_STRING (s) to s.isString()
    jsauthority: JSVAL_IS_NULL (o) to o.isNull()
    jsauthority: Fix up JS_CallFunctionName invocations
    jsauthority: use InterruptCallback api instead of OperationCallback
    jsauthority: redo how global objects are set up
    jsauthority: root some locals to the context
    jsauthority: adapt arguments for new JS::Compile API
    jsauthority: adapt arguments for new JS_ExecuteScript API
    jsauthority: use JS::Evaluate instead of JS_EvaluateScript
    jsauthority: fix up set_property methods
    jsauthority: stop using JS_GetStringCharsZ
    jsauthority: switch from JS_ConvertArguments to JS::CallArgsFromVp
    jsauthority: re-enable JIT
    Port JavaScript authority to mozjs52

 - Rui Matos (1):
    polkitpermission: Fix a memory leak on authority changes

 - Sebastien Bacher (1):
    Support polkit session agent running outside user session

 - Stef Walter (2):
    polkitagent: Fix access after dereference on hashtable
    polkitagent: No double warnings in polkit_agent_listener_register()

 - Sven Eden (1):
    configure: enable elogind support in PolicyKit

 - Yuri Chornoivan (1):
    Add Ukrainian translation

 - enkore (1):
    Fix abnomal formatting of authentication header lines

 - muzena (1):
    Add hr.po

Thanks to our contributors.

Colin Walters and Miloslav Trmač,
April 2, 2018

--------------
polkit 0.113
--------------

NOTE: This release is an important security update, see below.

**WARNING:**
This is a prerelease on the road to polkit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

This is polkit **0.113**.

### Highlights:
 Fixes CVE-2015-4625, a local privilege escalation due to predictable
 authentication session cookie values. Thanks to Tavis Ormandy, Google Project
 Zero for reporting this issue. For the future, authentication agents are
 encouraged to use PolkitAgentSession instead of using the D-Bus agent response
 API directly.

 Fixes CVE-2015-3256, various memory corruption vulnerabilities in use of the
 JavaScript interpreter, possibly leading to local privilege escalation.

 Fixes CVE-2015-3255, a memory corruption vulnerability in handling duplicate
 action IDs, possibly leading to local privilege escalation. Thanks to
 Laurent Bigonville for reporting this issue.

 Fixes CVE-2015-3218, which allowed any local user to crash polkitd. Thanks to
 Tavis Ormandy, Google Project Zero, for reporting this issue.

 On systemd-213 and later, the “active” state is shared across all sessions of
 an user, instead of being tracked separately.

 (pkexec), when not given a program to execute, runs the users’ shell by
 default.

### Build requirements:

 - glib, gobject, gio    >= 2.30
 - mozjs185 or mozjs-17.0
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)
 - ConsoleKit OR systemd

### Changes since polkit 0.112:

 - Colin Walters (17):
    PolkitSystemBusName: Add public API to retrieve Unix user
    examples/cancel: Fix to securely lookup subject
    sessionmonitor-systemd: Deduplicate code paths
    PolkitSystemBusName: Retrieve both pid and uid
    Port internals non-deprecated PolkitProcess API where possible
    Use G_GNUC_BEGIN_IGNORE_DEPRECATIONS to avoid warning spam
    pkexec: Work around systemd injecting broken XDG_RUNTIME_DIR
    pkexec: Support just plain "pkexec" to run shell
    .dir-locals: Style for Emacs - we don't use tabs
    authority: Avoid cookie wrapping by using u64 counter
    CVE-2015-3218: backend: Handle invalid object paths in RegisterAuthenticationAgent
    build: Start using git.mk
    Revert "authority: Avoid cookie wrapping by using u64 counter"
    authority: Add a helper method for checking whether an identity is root
    CVE-2015-4625: Use unpredictable cookie values, keep them secret
    CVE-2015-4625: Bind use of cookies to specific uids
    README: Note to send security reports via DBus's mechanism

 - Kay Sievers (1):
    sessionmonitor-systemd: prepare for D-Bus "user bus" model

 - Lukasz Skalski (1):
    polkitd: Fix problem with removing non-existent source

 - Max A. Dednev (1):
    authority: Fix memory leak in EnumerateActions call results handler

 - Miloslav Trmač (24):
    Post-release version bump to 0.113
    Don't discard error data returned by polkit_system_bus_name_get_user_sync
    Fix a memory leak
    Refuse duplicate --user arguments to pkexec
    Fix a possible NULL dereference.
    Remove a redundant assignment.
    Simplify forced error domain registration
    Fix a typo, s/Evaluting/Evaluating/g
    s/INCLUDES/AM_CPPFLAGS/g
    Fix duplicate GError use when "uid" is missing
    Fix a crash when two authentication requests are in flight.
    docs: Update for changes to uid binding/AuthenticationAgentResponse2
    Don't pass an uninitialized JS parameter
    Don't add extra NULL group to subject.groups
    Don't store unrooted jsvals on heap
    Fix a per-authorization memory leak
    Fix a memory leak when registering an authentication agent
    Wrap all JS usage within “requests”
    Register heap-based JSObject pointers to GC
    Prevent builds against SpiderMonkey with exact stack rooting
    Clear the JS operation callback before invoking JS in the callback
    Fix spurious timeout exceptions on GC
    Fix GHashTable usage.
    Fix use-after-free in polkitagentsession.c

 - Philip Withnall (1):
    sessionmonitor-systemd: Use sd_uid_get_state() to check session activity

 - Rui Matos (1):
    PolkitAgentSession: fix race between child and io watches

 - Simon McVittie (1):
    Use libsystemd instead of older libsystemd-login if possible

 - Ting-Wei Lan (1):
    build: Fix several issues on FreeBSD

 - Xabier Rodriguez Calvar (1):
    Fixed compilation problem in the backend

Thanks to our contributors.

Colin Walters and Miloslav Trmač,
July 2, 2015

--------------
polkit 0.112
--------------

NOTE: This release is an important security update, see below.

**WARNING:**
This is a prerelease on the road to polkit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

This is polkit **0.112**.

### Highlights:
 This release fixes CVE-2013-4288: Race condition with process subjects that do
 not have securely determined uid.

 pkcheck(1) now supports a new format for the --process argument; all
 applications need to use the new format to avoid a race condition (or use
 --system-bus-name to identify the process instead).

 Similarly, applications using the API should always use
 polkit_unix_process_new_for_owner().  polkit_unix_process_new() and
 polkit_unix_process_new_full() are unsafe and have been deprecated.

 Thanks to Sebastian Krahmer of the SUSE Security Team for reporting this issue.

### Build requirements:

 - glib, gobject, gio    >= 2.30
 - mozjs185 or mozjs-17.0
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)
 - ConsoleKit OR systemd

### Changes since polkit 0.111:

 - Colin Walters (2):
    polkitunixprocess: Deprecate racy APIs
    pkcheck: Support --process=pid,start-time,uid syntax too

 - Miloslav Trmač (1):
    Post-release version bump to 0.112

 - Tomas Bzatek (1):
    Use GOnce for interface type registration

 - Tomas Chvatal (2):
    Add czech translation po file to distribution.
    Update the czech once more with newest pot file.

Thanks to our contributors.

Colin Walters and Miloslav Trmač,
September 18, 2013

--------------
polkit 0.111
--------------

**WARNING:**
This is a prerelease on the road to polkit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

This is polkit **0.111**.

### Highlights:
 The JavaScript interpreter is now mandatory.
 Both js185 and mozjs17 versions of SpiderMonkey are supported.

### Build requirements:

 - glib, gobject, gio    >= 2.30
 - mozjs185 or mozjs-17.0
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)
 - ConsoleKit OR systemd

### Changes since polkit 0.110:

 - Colin Walters (6):
    mocklibc: Only require autoconf 2.63
    configure: Specify GLib min/max version
    jsauthority: We can really only handle a string
    jsauthority: Use JSVAL_NULL rather than {0} struct initialization
    Revert "Dynamically load libmozjs185.so and cope with it not being available"
    jsauthority: Work with mozjs-17.0 too

 - David Zeuthen (1):
    Post-release version bump to 0.111

 - Giovanni Campagna (1):
    build: try harder to avoid systemd/consolekit misconfiguration

 - Michael Biebl (1):
    man: Fix pkaction man page wrt to --action-id option

 - Miloslav Trmač (28):
    Clean (git status) after autogen.sh
    Fix build with srcdir!=builddir
    Fix DOC_SOURCE_DIR for builddir != srcdir
    Fix various memory leaks.
    Add annotation glossary
    Leave out backend from gtk-doc generation
    Fix most "undocumented symbol" warnings
    Move polkit_temporary_authorization_new to private header file.
    Include documentation of polkit_action_description_get_annotation_keys
    Document deprecated functions.
    Fold enum documentation into relevant classes
    Fix an obvious docstring typo.
    Add annotations for element types of returned lists
    Add a FIXME to polkitprivate.h
    Use auth_admin* instead of auth_self* in examples
    More warnings about using auth_self*
    Fix a TypeError when no admin rules are registered
    Fix handling of null returned from _runRules
    Refuse non-string parameters to Polkit.spawn()
    Drop unused variable
    Fix a memory leak
    Remove an unused va_start
    Don't spawn man for --help
    Fix package version / bug report address mixing
    Add bug reporting address and home page to --help output
    Refuse unrecognized command-line operands
    Exit pkaction with status 0 on success
    Fix inclusion of COPYING into documentation with srcdir != builddir

 - Nuno Araujo (1):
    Fix the build with automake 1.13

 - Samuli Suominen (1):
    Add missing #include <sys/wait.h>

 - Steve Langasek (1):
    pkexec: Set process environment from pam_getenvlist()

 - Vincent Untz (1):
    polkitagent, pkexec: Respect SUID_CFLAGS and SUID_LDFLAGS

 - darkxst (1):
    update types for js188

Thanks to our contributors.

Miloslav Trmač,
May 15, 2013

--------------
polkit 0.110
--------------

**WARNING:**
This is a prerelease on the road to polkit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

This is polkit **0.110**.

### Build requirements:

 - glib, gobject, gio    >= 2.30
 - mozjs185
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)
 - ConsoleKit OR systemd

### Changes since polkit 0.109:

 - David Zeuthen (5):
    Post-release version bump to 0.110
    Set XAUTHORITY environment variable if is unset
    Use mutex and condition variables properly
    Remove AM_PROG_CC_STDC
    Update NEWS for release

 - Emilio Pozuelo Monfort (1):
    Fix build on GNU Hurd

 - Michael Biebl (1):
    build: Remove generated introspection files on "make clean"

Thanks to our contributors.

David Zeuthen,
Jan 9, 2013

--------------
polkit 0.109
--------------

**WARNING:**
This is a prerelease on the road to polkit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

This is polkit **0.109**.

### Build requirements:

 - glib, gobject, gio    >= 2.30
 - mozjs185
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)
 - ConsoleKit OR systemd

### Changes since polkit 0.108:

 - David Zeuthen (4):
    Post-release version bump to 0.109
    Include gmodule-2.0 to avoid linker errors
    Don't require libmozjs185 devel packages for polkit rules to work
    Update NEWS for release

Thanks to our contributors.

David Zeuthen,
December 19, 2012

--------------
polkit 0.108
--------------

**WARNING:**
This is a prerelease on the road to polkit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

This is polkit **0.108**.

### Build requirements:

 - glib, gobject, gio    >= 2.30
 - mozjs185
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)
 - ConsoleKit OR systemd

### Changes since polkit 0.107:

 - Adam Jackson (1):
    PolkitAgent: Avoid crashing if initializing the server object fails

 - David Zeuthen (5):
    Post-release version bump to 0.108
    Fall back to authenticating as uid 0 if the list of admin identities is empty
    Dynamically load libmozjs185.so and cope with it not being available
    docs: mention the audience for authorization rules
    Update NEWS for release

 - Ryan Lortie (1):
    build: Fix .gir generation for parallel make

Thanks to our contributors.

David Zeuthen,
November 14, 2012

--------------
polkit 0.107
--------------

**WARNING:**
This is a prerelease on the road to polkit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

This is polkit **0.10**.

### Build requirements:

 - glib, gobject, gio    >= 2.30
 - mozjs185
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)
 - ConsoleKit OR systemd

### Changes since polkit 0.106:

 - David Zeuthen (7):
    Post-release version bump to 0.107
    Update guidance on situations where there is no polkit authority
    Nuke leftover polkit-backend-1.pc file
    Nuke --enable-verbose flag
    Introduce a polkit.Result enumeration for authorization rules
    pkexec: add support for argv1 annotation and mention shebang-wrappers
    Update NEWS for release

 - Matthias Clasen (1):
    Try harder to look up the right localization

Thanks to our contributors.

David Zeuthen,
July 11, 2012

--------------
polkit 0.106
--------------

**WARNING:**
This is a prerelease on the road to polkit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

This is polkit **0.106. There's a major change in this release which i**.
a switch from .pkla files (keyfile-format) to .rules files
(JavaScript), see

 http://davidz25.blogspot.com/2012/06/authorization-rules-in-polkit.html

for more information.

### Build requirements:

 - glib, gobject, gio    >= 2.30
 - mozjs185
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)
 - ConsoleKit OR systemd

### Changes since polkit 0.105:

 - Colin Walters (3):
    build: Check for mozjs185, not libjs
    autogen.sh: Fix check for libtool (we only need libtoolize)
    agenthelper-pam: Fix newline-trimming code

 - David Zeuthen (65):
    Post-release version bump to 0.106
    Add experimental authority backend using JavaScript rule files
    Include seat and session in Subject object
    Pass details to JS functions and simplify how Subject instances are constructed
    Clean up code a bit
    Add a couple of more error checks
    Collect garbage
    Emit ::Changed signal after reloading rules
    Reformat init.js and also avoid quoting non-string properties in toString()
    Make it possible for JS code to change details
    Add polkit.spawn() to spawn external programs
    Make polkit.spawn() take an array of arguments instead of a command-line
    Don't include command-line in spawning error messages
    docs: add AUTHORIZATION RULES section to the polkit(8) man page
    Also add an example of polkit.spawn() to polkit(8) man page
    docs: clarify how rules files work
    Also load rules from /usr/share/polkit/rules.d
    Use addRule() and addAdminRule()
    docs: emphasize that registered functions may actually never be called
    Add test cases for evaluation order
    Test that subject.isInGroup() works
    Add netgroup support
    Minor doc fixes
    Mention unix-netgroup:xyz as a valid return value in addAdminRule() functions
    Add test-cases and 10 second timeout for polkit.spawn()
    Create rules.d directories
    Update docs
    docs: enclose local <citerefentry> in <link> to make links work
    docs: update SEE ALSO to make each man page point to all other man pages
    Clarify docs a bit
    polkitd: add reference to polkit(8) from its man page
    Fix speling
    Fix a couple typos in the docs
    Mention details["polkit.message"] and add an example using details
    Use <variablelist> instead of <informaltable> for Subject attributes
    Make polkit_details_insert() remove the key if passed value is NULL
    Add real-world example featuring udisks2 and the drive.* variables it passes
    Rename --enable-systemd to --enable-libsystemd-login
    Fix distcheck
    Add a systemd .service file
    Nuke polkitbackend library, localauthority backend and extension system
    Mention systemd(1) in the polkitd(8) man page
    Store private binaries in /usr/lib/polkit-1 instead of /usr/libexec
    Add default rules
    Pass expanded identity list to the AuthenticationSession
    Use "rules", not "scripts" to refer to files in rules.d
    Terminate runaway scripts
    Use a condition variable to signal that runaway killer thread is ready
    Combine action and details parameters
    Clarify pkexec(1) variables
    Use g_unix_signal_add() from GLib 2.30
    Move polkitd into src/polkitbackend
    Ensure polkitd is rebuilt if libpolkit-backend-1.la changes
    Remove unused DBUS_GLIB_* and GIO_* variables
    Run polkitd as an unprivileged user
    Log when the name org.fd.PolicyKit1 has been acquired
    Rewrite the "Writing polkit applications" chapter
    Update links to udisks docs
    Update pkexec(1) man page with example
    Small updates to the "Writing polkit applications" chapter
    State that authorization rules must not rely on SpiderMonkey features
    Make it work when using ConsoleKit instead of libsystemd-login
    Mention the implications of returning *_keep in an authorization rule
    docs: add a "make sure your app works when there's no polkitd(8)" note
    Update NEWS for release

Thanks to our contributors.

David Zeuthen,
June 7, 2012

--------------
polkit 0.105
--------------

This is polkit **0.10**.

**WARNING:**
This is a prerelease on the road to polkit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

### Build requirements:

 - glib, gobject, gio    >= 2.28
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)
 - ConsoleKit OR systemd

### Changes since polkit 0.104:

 - David Zeuthen (11):
    Post-release version bump
    PolkitUnixSession: Set error if we cannot find a session for the given pid
    PolkitUnixSession: Actually return TRUE if a session exists
    PolkitAgentSession: Don't leak file descriptors
    Add pkttyagent(1) helper
    Make it possible to influence agent registration with an a{sv} parameter
    Fix type in docs
    Mention pkttyagent(1) in "Writing PolicyKit applications" chapter
    Update the docs to use 'polkit' (instead of 'PolicyKit') as the name
    Add Makefile rules for signing and publishing releases and docs
    Update NEWS for release

 - Ryan Lortie (1):
    Various builddir != srcdir fixes

Thanks to our contributors.

David Zeuthen,
April 24, 2012

--------------
PolicyKit 0.104
--------------

This is polkit **0.104**

**WARNING:**
This is a prerelease on the road to PolicyKit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

### Build requirements:

 - glib, gobject, gio    >= 2.28
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)
 - ConsoleKit OR systemd

### Changes since PolicyKit 0.103:

 - David Zeuthen (3):
    Post-release version bump to 0.104
    Detect whether systemd is available and default to use if so
    Update NEWS for release

 - Matthias Clasen (1):
    Add optional systemd support

 - Nikki VonHollen (2):
    Bug 43608 – Add unit tests
    Bug 43610 - Add netgroup support

Thanks to our contributors.

David Zeuthen,
January 3, 2012

--------------
PolicyKit 0.103
--------------

This is polkit **0.103**

**WARNING:**
This is a prerelease on the road to PolicyKit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

### Build requirements:

 - glib, gobject, gio    >= 2.28
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)

 - IMPORTANT: As of release 0.103, the default Authority backend now
 - defaults to allowing members of the 'wheel' group to authenticate as
 - an administator since this is common usage in popular Linux
 - distributions. Distributors can change this by patching the
 - 50-localauthority.conf file in /etc/polkit-1/localauthority.conf.d as
 - needed.

### Changes since PolicyKit 0.102:

 - Alan Near (1):
    Mistype in DBus object: PoliycKit1 -> PolicyKit1

 - David Zeuthen (7):
    Post-release version bump to 0.103
    Add support for the org.freedesktop.policykit.imply annotation
    Add --no-debug option and use this for D-Bus activation
    Bug 41025 – Add org.freedesktop.policykit.owner annotation
    Default to AdminIdentities=unix-group:wheel for local authority
    Update NEWS for release
    Fix typo

Thanks to our contributors.

David Zeuthen,
December 6, 2011

--------------
PolicyKit 0.102
--------------

This is polkit **0.102**

**WARNING:**
This is a prerelease on the road to PolicyKit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

### Build requirements:

 - glib, gobject, gio    >= 2.28
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)

### Changes since PolicyKit 0.101:

 - Benjamin Otte (1):
    introspection: Add --c-include to the gir files

 - David Zeuthen (7):
    Post-release version bump to 0.102
    Don't show diagnostic messages intended for the administrator to the end u
    PolkitUnixProcess: Clarify that the real uid is returned, not the effectiv
    Make PolkitUnixProcess also record the uid of the process
    Use polkit_unix_process_get_uid() to get the owner of a process
    pkexec: Avoid TOCTTOU problems with parent process
    Update NEWS for release

 - Evan Nemerson (1):
    Specify exported pkg-config files in GIRs

 - Marc Deslauriers (1):
    Fix multi-line pam prompt handling

 - Martin Pitt (3):
    Ignore .po/ for intltool
    Fix backend crash if a .policy file does not specify <message>
    Bug 38769 — pkexec: Support running X11 apps

Thanks to our contributors.

David Zeuthen,
August 1, 2011

--------------
PolicyKit 0.101
--------------

This is polkit **0.101**

**WARNING:**
This is a prerelease on the road to PolicyKit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

### Build requirements:

 - glib, gobject, gio    >= 2.28
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)

### Changes since PolicyKit 0.100:

 - Adrian Bunk (1):
    Bug 27253 – Use GOBJECT_INTROSPECTION_CHECK from gobject-introspection

 - David Zeuthen (16):
    Post-release version bump to 0.101
    Bug 30653 – No way to detect cancellation in pkexec
    Bug 27081 – pkexec fails to build on non glibc systems
    Bug 30438 – PolicyKit fails to build on AIX
    Bug 32334 – Always set polkit.retains_authorization_after_challenge
    Fix a memory leak
    Be more specific about what info we want when enumerating files
    Make pkcheck(1) report if the authentication dialog was dismissed
    pkcheck: Make it possible to list and revoke temporary authorizations
    Be a bit more careful parsing the command-line
    Bug 29712 – Use monotonic for temporary authorizations
    Allow overriding message shown in authentication dialog
    Deprecated PolkitBackendActionLookup
    Fix a couple of warnings triggered by gcc 4.6
    Build examples by default and fix compiler warnings
    Update NEWS for release

 - Michael Biebl (1):
    Bug 29871 – Fix build failures with binutils-gold

Thanks to our contributors.

David Zeuthen,
March 3, 2011

--------------
PolicyKit 0.100
--------------

This is polkit **0.100**

**WARNING:**
This is a prerelease on the road to PolicyKit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

### Build requirements:

 - glib, gobject, gio    >= 2.25.12
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)

### Changes since PolicyKit 0.99:

 - David Zeuthen (12):
    Post-release version bump to 0.100
    Add missing GObject Introspection annotations
    Build gir/typelib for PolkitAgent-1.0
    Fix-up PolkitAgentSession to use GObject properties
    Improve error reporting for authentication sessions
    Add some debug info that can be shown with the env var POLKIT_DEBUG
    Fix up debug and timeouts in agent helper
    Always pass non-zero value to g_once_init_leave()
    Add a note about POLKIT_DEBUG
    Pass caller and subject pid to authentication agent
    Update NEWS for release
    Fix 'make distcheck'

Thanks to our contributors.

David Zeuthen,
February 21, 2011

--------------
PolicyKit 0.99
--------------

This is polkit **0.99**

**WARNING:**
This is a prerelease on the road to PolicyKit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

### Build requirements:

 - glib, gobject, gio    >= 2.25.12
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)

### Changes since PolicyKit 0.98:

 - Colin Walters (3):
    Remove duplicate definitions of enumeration types
    Fix (correct) GCC warning about possibly-uninitialized variable
    Fix another GCC uninitialized variable warning

 - David Zeuthen (2):
    Post-release version bump to 0.99
    Update NEWS for release

 - Vincent Untz (1):
    Bug 29816 – Install polkitagentenumtypes.h

Thanks to our contributors.

David Zeuthen,
September 15, 2010

--------------
PolicyKit 0.98
--------------

This is polkit **0.98**.

**WARNING:**
This is a prerelease on the road to PolicyKit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

### Build requirements:

 - glib, gobject, gio    >= 2.25.12
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)

### Changes since PolicyKit 0.97:

 - David Zeuthen (11):
    Post-release version bump to 0.98
    Require GLib 2.25.12
    Fix scanning of unix-process subjects
    Add textual authentication agent and use it in pkexec(1)
    Fix ConsoleKit interaction bug
    pkexec: add --disable-internal-agent option
    pkcheck: add --enable-internal-agent option
    Fix wording in pkexec(1) man page
    Various doc cleanups
    Fix dist-check
    Update NEWS for release

Thanks to our contributors.

David Zeuthen,
August 20, 2010

--------------
PolicyKit 0.97
--------------

This is polkit **0.97**.

**WARNING:**
This is a prerelease on the road to PolicyKit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

The main change since the previous version is a port from eggdbus to
GLib's new D-Bus implementation. Other changes includes various bug
fixes and support for shadow authentication. Support for the
AddLockdown() and RemoveLockdown() methods has been removed. You will
need an updated version of PolicyKit-gnome to go with this release.

### Build requirements:

 - glib, gobject, gio    >= 2.25.11
 - gobject-introspection >= 0.6.2 (optional)
 - pam (optional)

### Changes since PolicyKit 0.96:

 - Andrew Psaltis (1):
    Add shadow support

 - Dan Rosenberg (1):
    Bug 26982 – pkexec information disclosure vulnerability

 - David Zeuthen (23):
    Post-release version bump to 0.97
    Port core bits to gdbus
    Port CK class to gdbus
    Port PolkitBackendInteractiveAuthority to gdbus
    Port PolkitAgent to gdbus
    Add generated docbook D-Bus API docs to git
    Nuke eggdbus usage
    Make polkitd accept --replace and gracefully handle SIGINT
    Implement polkit_temporary_authorization_new_for_gvariant()
    Remove Lock Down functionality
    Make NameOwnerChanged a private impl detail of the interactive authority
    Update README
    Merge remote branch 'origin/gdbus'
    Add a GPermission implementation
    PolkitAuthority: Implement failable initialization
    PolkitAuthority: Add g_return_if_fail() checks
    Add g_return_if_fail() to all public API entry points
    Use polkit_authority_get_sync() instead of deprecated polkit_authority_get
    PolkitBackend: Don't export unneeded convenience API
    Update GI annotations
    Don't dist org.freedesktop.ConsoleKit.xml; It's dead, Jim
    Properly reference headers
    Update NEWS for release

 - Petr Mrázek (1):
    Bug 29051 – Configuration reload on every query

Thanks to our contributors.

David Zeuthen,
August 9, 2010

--------------
PolicyKit 0.96
--------------

This is polkit **0.96**. This is supposed to be the last release until 1.0.

**WARNING:**
This is a prerelease on the road to PolicyKit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

### Build requirements:

 - glib, gobject, gio    >= 2.21.4
 - eggdbus-1             >= 0.6
 - gobject-introspection >= 0.6.2 (optional)
 - pam

### Changes since PolicyKit 0.95:

 - David Zeuthen (15):
    Bug 25367 — Also read local authority configuration data from /etc
    Fix logic error in pk-example-frobnicate
    Run the open_session part of the PAM stack in pkexec(1)
    Fix up last comment
    Bug 25594 – System logging
    Remove trailing whitespace from log messages
    Properly handle return value from getpwnam_r()
    Fix error message when no authentication agent is available
    Make pkexec(1) validate environment variables
    Make pkexec(1) use the syslogging facilities
    Save original cwd in pkexec(1) since it will change during the life-time
    Complain on stderr, not stdout
    Post-release version bump to 0.96
    Don't log authorization checks
    Update NEWS for release

David Zeuthen,
January 15, 2010

--------------
PolicyKit 0.95
--------------

This is polkit **0.95**. This is supposed to be the last release until 1.0.

**WARNING:**
This is a prerelease on the road to PolicyKit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

### Build requirements:

 - glib, gobject, gio    >= 2.21.4
 - eggdbus-1             >= 0.6
 - gobject-introspection >= 0.6.2 (optional)
 - pam

### Changes since PolicyKit 0.94:

 - Alexander Sack (1):
    Bug 24566 – Properly _ref authority in singleton constructor

 - Andreas Sandberg (1):
    Bug 24235 – polkit-agent-helper may call pam_end with a stale pam handle

 - Bastien Nocera (1):
    Fix process start time when using polkit_unix_process_new_full()

 - David Zeuthen (20):
    Post-release version bump to 0.95
    Use correct program name when complaining about not being setuid root
    Sort by action id in pkaction(1) output
    Bug 23867 – UnixProcess vs. SystemBusName aliasing
    Implement lockdown for the Local Authority implementation
    Remove POLKIT_USER from configuration summary
    Add missing comma so we're save both LANG and LANGUAGE, not only LANGLANGUAGE
    Pass --libtool to g-ir-scanner
    Clarify comment on where to find process start-time on Linux
    Add properties with information about the currently used authority
    Clarify when AllowUserInteraction should and shouldn't be used
    Add methods AddLockdownForAction() and RemoveLockdownForAction()
    Port lockdown from pklalockdown(1) to D-Bus methods
    Drop ununsed policykit actions
    Remove TODO about symbol visibility as this has been fixed for a while
    Clarify pklocalauthority(8) man page
    Properly validate all arguments passed via D-Bus
    Add Python example
    Fix make distcheck
    Update NEWS for release

 - Matthias Clasen (1):
    Bug 24640 – Typos in pklocalauthority(8)

 - Michael Biebl (8):
    Trim the list of exported symbols
    Use _polkit_agent_marshal prefix
    Make private symbols accessible to libpolkitagent and libpolkitbackend
    Make examples optional
    Enable silent rules
    Remove POLKIT_USER option
    Don't include Polkit-1.0.gir in the dist tarball
    Bug 24176 – Current git master fails to build, GLIB_LDADD -> GLIB_LIBS

 - Samuel Thibault (1):
    Bug 24495 – Fails to build on platforms without PATH_MAX (like hurd)

David Zeuthen,
November 13, 2009

--------------
PolicyKit 0.94
--------------

This is polkit **0.94**.

**WARNING:**
This is a prerelease on the road to PolicyKit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

### Build requirements:

 - glib, gobject, gio    >= 2.21.4
 - eggdbus-1             >= 0.5
 - gobject-introspection >= 0.6.2 (optional)
 - pam

### Changes since PolicyKit 0.93:

 - David Zeuthen (13):
    Post-release version bump to 0.94
    Require correct versions of glib and eggdbus
    Ignore .pkla files starting with dot and don't segfault on error path
    Allow unprivileged callers to check authorizations
    Don't spawn man(1) from a setuid program
    Add polkit.retains_authorization_after_challenge to authz result
    Ensure all fds except stdin/stdout/stderr are closed after exec(2)
    Be more careful when determining process start time
    Pass the right struct offset for the ::changed class signal handler
    Don't set the GError if the process doesn't exist
    Remove temporary authorization when the subject it applies to vanishes
    Generate GI gir and typelibs for libpolkit-gobject-1
    Update NEWS for release

 - Joe Marcus Clarke (1):
    Bug 23093 – FreeBSD portability fixes

David Zeuthen,
August 12, 2009

--------------
PolicyKit 0.93
--------------

This is polkit **0.93**.

**WARNING:**
This is a prerelease on the road to PolicyKit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

### Build requirements:

 - glib, gobject, gio >= 2.21.4
 - eggdbus-1          >= 0.5
 - pam

### Changes since PolicyKit 0.92:

 - David Zeuthen (16):
    Post-release version bump to 0.93
    GIO modules need to be prefix with lib
    Cancel an authentication if the unique name for the subject vanishes
    Plug a couple of memory leaks
    Move local authority management to a separate library
    Rip out polkit-local and refactor local authority to only use tmp authz
    Move authentication agent bits to separate authority subclass
    Also pass the identity of the subject we are checking for
    Actually make the local authority look up authorization files
    In .pkla files, use Result{Any,Inactive,Active} instead of just Result
    Rename some man pages and the daemon binary
    Add docs detailing how the Local Authority works
    Add support for querying and revoking temporary authorizations
    Fix make distcheck
    Update TODO
    Update NEWS for release

 - Yanko Kaneti (2):
    Use unique ids for sections to prevent them being autogenerated
    More unique ids to get the docs build fully predictable

David Zeuthen,
July 20th, 2009

--------------
PolicyKit 0.92
--------------

This is polkit **0.92**.

**WARNING:**
This is a prerelease on the road to PolicyKit
1.0. Public API might change and certain parts of the code still needs
some security review. Use at your own risk.

### Build requirements:

 - glib, gobject, gio >= 2.14
 - eggdbus-1          >= 0.4
 - pam

### Changes since PolicyKit 0.91:

 - David Zeuthen (36):
    post-release version bump to 0.92
    install gtkdoc HTML in the proper location
    Fix D-Bus policy to work with non-permissive D-Bus
    Only allow privileged apps to check authz and add ActionLookup interface
    Change the PolkitAuthorizationResult enumeration into an object
    Port examples and command-line tools to new API
    Move docs to proper location
    Add a pkexec(1) command
    Mention /usr/bin/pkexec in the configure blurb
    Fix a bug where details were not shown for normal pkexec usage
    Use an object, not a GHashTable when passing details around
    Forgot to add source for PolkitDetails
    Change the defaults for .run-frobnicate to auth_self_keep
    Require eggdbus-1 >= 0.4
    Only free hash table if it's not NULL
    Avoid returning an error if no authentication agent is available
    Clarify docs for is_challenge member of the AuthorizationResult struct
    Add pkcheck(1) command to check for authorizations
    nullbackend: Catch up with latest API changes
    Return the icon name instead of a GIcon in PolkitActionDescription
    Add pkaction(1) and nuke polkit-1(1) commands
    Update SEE ALSO sections in man pages
    Add a man page for polkit-1(8)
    First cut at some high-level docs
    Improve pkexec(1) man page by adding screenshots of authentication dialogs
    Add some more API docs
    Add a "PolicyKit Overview" section to the docs
    Consolidate all gtk-doc stuff in docs/polkit
    Expand on the D-Bus docs
    Use .../extensions instead of ../backends for loading extensions
    Minor doc fixes
    Move the doc chapters around a bit
    Change GNOME to freedesktop.org in the docs
    Fix make distcheck
    Update NEWS
    Also dist polkitd-1.xml

 - Richard Hughes (2):
    fix up gtk-doc API markup for a couple of functions
    add a draft version of the porting guide -- WIP

David Zeuthen,
June 8, 2009
