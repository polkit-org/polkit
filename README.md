OVERVIEW
========

polkit is a toolkit for defining and handling authorizations.  It is
used for allowing unprivileged processes to speak to privileged
processes.


DOCUMENTATION
=============

Latest documentation, reference manual and API description of polkit can be found  
on project's Gitlab Pages  
 https://polkit.pages.freedesktop.org/polkit


Old reference can be found at  
 https://www.freedesktop.org/software/polkit/docs/latest/


RELEASES
========

Latest releases are available at polkit's Gitlab Releases page:  
 https://gitlab.freedesktop.org/polkit/polkit/-/releases


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

Please report non-security bugs via the polkit's freedesktop.org GitLab at

 https://gitlab.freedesktop.org/polkit/polkit/issues

The other way, in case of **non**-security issues, is to contact developers via official polkit's FreeDesktop.org mailing list at

polkit-devel@lists.freedesktop.org  

SECURITY ISSUES
===============

Please report any security issues not yet known to public
by creating new issue and checking the ***This issue is confidential*** checkbox.

 https://gitlab.freedesktop.org/polkit/polkit/issues


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
Your merge requests and patch suggestions are welcome! If you want to contribute, a merge request on this Gitlab instance is a preferred way, yet not the only one. Please consult other options with this upsteam's maintainers.

Should you already have a freedesktop.org Gitlab account, please file your merge request. In this case, please **don't force-push any further changes** into the merge request and add a new commit into the MR instead.

Thank you in advance.
