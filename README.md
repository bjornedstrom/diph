# diph - diffable ciphertext
version 0.0.1beta

Björn Edström 2010-2012 <be@bjrn.se>
See LICENSE for copyright

## WARNING

Not only does this system have some security weaknesses **by design**
(see further below), this implementation is beta-quality and has
bugs. You should **NOT** use diph unless you fully understand the
security implications of doing so.

## Introduction

`diph` is a cryptographic system for encrypting source code, TODO
lists, and other "plain text" files. Lines of text are encrypted
individually and the system has the special property that diffs
between two revisions of a file are preserved in the cipher text. This
means that the output of the system can be operated on by a revision
control system, such as git.

## Overview of Design

The heart of diph is a diff algorithm combined with the CTR block
cipher mode.

Consider a file `P_1` and a subsequent change of the file `P_2`

    $ diff -u P_1 P_2
    --- P_1
    +++ P_2
    @@ -1,3 +1,3 @@
     TODO list
    -* TODO do something
    +* DONE do something
     * TODO do something else

On the first usage of diph, `P_1` is encrypted to `C_1`:

    $ diph encrypt P_1 | tee C_1
    ?? diph1
    ?k yeC+cBzWI20smp3xgQttP/hLjo2V/HcDvlx3t/+suyc70zwLz2GbX1n6yyopl+R7jIF/ZAUnlmIeu4Tw7tjemQ==
    ?c 0 WRd1hwIo2y/fpA==
    ?c 1000 wHIvxLDTRA2pot/4w5R/T+k2NS0=
    ?c 2000 sLHxgz3AaMZu8Q+2QQZc/DkyKeaSyX3sJw==

To preserve the diff in P, `C_1` is used as input when doing encryption
of `P_2`:

    $ diph encrypt P_2 C_1 > C_2 && diff -u C_1 C_2
    --- C_1
    +++ C_2
    @@ -1,4 +1,4 @@
     ?k yeC+cBzWI20smp3xgQttP/hLjo2V/HcDvlx3t/+suyc70zwLz2GbX1n6yyopl+R7jIF/ZAUnlmIeu4Tw7tjemQ==
     ?c 0 WRd1hwIo2y/fpA==
    -?c 1000 wHIvxLDTRA2pot/4w5R/T+k2NS0=
    +?c 3000 r/+xa7JU8TDe0Yv5XnXIHOQlKtg=
     ?c 2000 sLHxgz3AaMZu8Q+2QQZc/DkyKeaSyX3sJw==

When decrypting, diph will preserve merge conflict markers, so you can
resolve them in the plain text.

## Inner Workings

Each line of plain text is mapped to a (counter, line) tuple where
counter is used to encrypt line using AES-CTR. The counter is
increased in large steps (default 1000) allowing sufficient length of
the line.

To encrypt a file:

1. The previous version of the file is decrypted to (counter, line) tuples.
2. The current version of the file is diff'ed with the previous, and (counter, line) pairs are inserted or removed as appropriate, increasing the counter past the maximum in the old version.

The file is encrypted with a random key that is PBKDF2-protected in
the top of the cipher text.

### Specification

It is recommended that you read the specification. See the `doc`
directory.

## Weaknesses

diph has the following weaknesses, that may or may not be acceptable
to you:

* MAJOR ISSUE: The system makes it very easy to accidentally re-use
  counters, for example after a merge conflict is resolved. If you do
  not know what that means, you should not use diph.
* MAJOR ISSUE: The system does not use any kind of authentication
  (such as a HMAC), because I haven't implemented that yet. If you do
  not know what that means, you should not use diph.
* An attacker can guess from the structure of the file what the
  content is.
* diph does not currently make any attempt to encrypt the file name.

### Managing Counters

The main issue when dealing with diph is to make sure that counters
(as in the CTR block cipher mode) are not reused. diph handles the
case where lines from the end of file are removed from the plain text,
and subsequently added.

To give control to the user (you) diph also supports a counter pragma
that can be added anywhere in your plain text file, like so
(case-sensitive but can appear anywhere on a line):

    #diph ctr 53000

This means that when the file is encrypted, diph will start all new
modifications in the file (compared to the previous version) at
minimum counter 53000.

## History / Rationale

diph is written by Björn Edström. I have written several
implementations since I got the idea 2010, and this is the one that
I'm going to try to use in the wild.

The problem I'm trying to solve is store my org-mode TODO files on
github, with "good enough" security.
