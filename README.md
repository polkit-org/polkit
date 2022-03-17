OVERVIEW
========

polkit is a toolkit for defining and handling authorizations.  It is
used for allowing unprivileged processes to speak to privileged
processes.


DOCUMENTATION
=============

Latest documentation, reference manual and API description of polkit can be found at

 https://www.freedesktop.org/software/polkit/docs/latest/


RELEASES
========

Latest releases are available in compressed tarballs from

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


SECURITY ISSUES
===============

Please report any security issues not yet known to public
by creating new issue and checking the ***This issue is confidential*** checkbox.

 https://gitlab.freedesktop.org/polkit/polkit/issues

