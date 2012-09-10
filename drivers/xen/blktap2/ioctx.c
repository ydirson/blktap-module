/*
 * Copyright (c) 2010 Citrix Systems, Inc.
 */

#include <linux/bio.h>
#include <linux/iocontext.h>

#include "blktap.h"

void
blktap_ioctx_detach(struct blktap *tap)
{
	struct special_io_context *sioc;
	struct io_context *ioc;

	ioc  = tap->ioc;
	if (!ioc)
		return;

	sioc = ioc->special;
	if (sioc && atomic_dec_and_test(&sioc->refs)) {
		bioset_free(sioc->bs);
		kfree(sioc);
		ioc->special = NULL;
	}

	put_io_context(ioc);
	tap->ioc = NULL;
}

int
blktap_ioctx_attach(struct blktap *tap, int node)
{
	struct special_io_context *sioc;
	struct io_context *ioc;
	int err;

	err = -ENOMEM;

	ioc = tap->ioc = get_io_context(GFP_KERNEL, node);
	if (!ioc)
		goto fail;

	sioc = ioc->special;
	if (sioc)
		goto out;

	sioc = kzalloc_node(sizeof(*sioc), GFP_KERNEL, node);
	if (!sioc)
		goto fail;

	ioc->special = sioc;

	/* NB. multi-vbd count. */
	atomic_set(&sioc->refs, 0);

	/* NB. one warning per task and minute. */
	sioc->rs.interval = 60 * HZ;
	sioc->rs.burst    = 1;

	sioc->bs = bioset_create(BLKTAP_BIO_POOL_SIZE, 0);
	if (!sioc->bs)
		goto fail;

out:
	atomic_inc(&sioc->refs);
	return 0;

fail:
	blktap_ioctx_detach(tap);
	return err;
}
