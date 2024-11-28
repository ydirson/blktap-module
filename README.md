# Reconstructed history of the blktap2 kernel-module

The `blktap2` kernel module used by several projects (known to me:
XenServer, XCP-ng, OpenXT) had a number of versions over the years and
it is not trivial to see how they relate.  This is a an attempt at
getting the big picture.

This repo consists of branches of the `blktap2` module source,
imported from various available sources.  Some of those sources
shipped the module source as kernel patches, some shipped the source
code directly.

Note this is a work in progress, and the current import are partial,
and histories will be rewritten

* `xenserver` [2012-09..]: collected from SPRMs in source ISOs from
  https://www.citrix.com/downloads/citrix-hypervisor/
* `openxt` [2014-06..]: collected from patches in
  https://github.com/OpenXT/xenclient-oe.git
* `linux-3.x.pg` [2013-07..2015-09]: collected from patches in old XS repo
  https://github.com/xenserver/linux-3.x.pg
* `blktap-dkms` [2011-11..2013-03]: direct commits from
  https://github.com/xapi-project/blktap-dkms

Not yet imported:
* `xcpng`: patches in successive SRPMs in
  https://github.com/xcp-ng-rpms/kernel

Note that the initial commit in `xenclient-oe.git` was populated from
OpenXT old patch queue at
https://github.com/OpenXT-Extras/linux-3.11-pq.git but in that repo
`blktap2` was never modified after its import, so we'll disregard it
here.

## linking timelines together

Those per-project timelines are not independant, and merges can be
identified.  Those get recorded as git "graft" [replace
references](https://git-scm.com/docs/git-replace).

Consider adding the following line to your remote definition in
`.git/config`, to get advantage of them (and them use
`--no-replace-objects` to see the imported history lines without those
connections):

```
        fetch = +refs/replace/*:refs/replace/*
```
