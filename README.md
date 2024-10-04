OVERVIEW
========

polkit is a toolkit for defining and handling authorizations.  It is
used for allowing unprivileged processes to speak to privileged
processes.


DOCUMENTATION
=============

Latest documentation, reference manual and API description of polkit can be still found  
on project's previous instance of Gitlab Pages  
https://polkit.pages.freedesktop.org/polkit


Older reference can be found at  
 https://www.freedesktop.org/software/polkit/docs/latest/


RELEASES
========

Latest releases are available at [the Release page](https://github.com/polkit-org/polkit/releases).

Older releases are still available as tarballs at  
 https://www.freedesktop.org/software/polkit/releases/

To verify the authenticity of the compressed tarball, use this command

``` bash
$ gpg --verify polkit-$(VERSION).tar.gz.sign polkit-$(VERSION).tar.gz
$ gpg: Signature made Tue 23 Apr 2019 04:19:29 PM CEST using RSA key ID FFDCE258
$ gpg: Good signature from "Jan Rybar (Red Hat) <jrybar@redhat.com>"
```

Public key available at

 https://keys.openpgp.org/vks/v1/by-fingerprint/7FFB7D6BD83147D74284E3178CEB3030FFDCE258


BUGS and DEVELOPMENT
====================

Please report non-security bugs via the polkit's GitHub issues at
https://github.com/polkit-org/polkit/issues

The other way, in case of **non**-security issues, is to contact developers via official polkit's FreeDesktop.org mailing list at

polkit-devel@lists.freedesktop.org  

SECURITY ISSUES
===============

Please report any security issues not yet known to public by sending mail to polkit-security@redhat.com or use GitHub's button for reporting a vulnerability when creating an issue.  
Thank you.


BUILD INSTRUCTIONS
==================

**polkit** uses [meson build system](https://mesonbuild.com/) for configuration with *ninja* as backend and *gcc* as compiler.  
To configure and compile your copy of polkit tarball, simply follow meson build instructions in the following manner:
```
$ meson setup [[-D option]...] target_directory
$ meson compile -C target_directory
...
# meson install -C target_directory
```

List of available configuration options can be obtained with `meson configure` command.

I WANT TO CONTRIBUTE
====================
Your pull requests and patch suggestions are welcome! If you want to contribute, a pull request on this GitHub project is a preferred way, yet not the only one. Please consult other options with this upsteam's maintainers.

Thank you in advance.
