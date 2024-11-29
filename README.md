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
* `xenclient-4.1` [2012-06]: collected from
  https://www.citrix.com/downloads/xenclient/source.html, based off
  `dstodden` (4.5.1 having same patches as 4.1, and 2.0/2.1 apparently
  not sporting kernel source?)
* `dstodden` [2011-03..2011-05]: collected from
  git://xenbits.xensource.com/people/dstodden/linux.git branches
  next-2.6.3[23679]
* `jfitzhardinge-from-dmeyer` [2009-03..2010-07],
  `dstodden-from-jfitzhardinge` [2010-08..2011-03] filtered commit
  history from upstream/xen/dom0/backend/blktap2, from import of
  03-blktap2-patch by Ian Campbell and Jeremy Fitzhardinge, which
  seems to come from Dutch Meyer's
  https://xen-devel.narkive.com/KPJivIz4/5-patches-synchronize-blktap-with-citrix-blktap2
  but has `BLKTAP2_IOCTL_`
* `xenserver-2.6.27` [2009-04] base import of XenServer 2.6.27 in
  git://xenbits.xen.org/xenclient/linux-2.6.27-pq.git (forking
  off `dstodden-from-dmeyer`)
*  `xenclient-2.6.27` [2009-04..2010-01]
   git://xenbits.xen.org/xenclient/linux-2.6.27-pq.git (just a pair of
   patches)

Not yet imported:
* `xcpng`: patches in successive SRPMs in
  https://github.com/xcp-ng-rpms/kernel
* small gap between `xenclient-4.1` and `openxt`

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

## disjoint partial timelines

### `drivers/xen/blktap` / `drivers/xen/blktap2` timeline

* the original(?) blktap2 timeline, for which we only have Daniel
Stodden's `upstream/xen/dom0/backend/blktap2` branch, which (starting
2009-03) could derive directly from Dutch Meyer's 2009-02, which seem
to be the birth of blktap2.

* `xenserver-2.6.27` (which uses the name `drivers/xen/blktap2`,
  likely because of `blktap1` in `drivers/xen/blktap`) and
  `xenclient-2.6.27`

Notably has `BLKTAP2_IOCTL_*` which no other timeline has.

### `drivers/block/blktap` timeline

The OpenXT timeline can be traced through XenClient back to Daniel
Stodden's `next-2.6.*` branches.

Continuation of `drivers/xen/blktap`?

### `drivers/block/blktap2` timeline

This is the XenServer/XCP-ng one, since XenServer 6.1 at least.

Continuation of `drivers/xen/blktap2`?
