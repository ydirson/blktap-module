#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/cdrom.h>
#include <linux/hdreg.h>
#include <linux/log2.h>
#include <linux/export.h>
#include <scsi/scsi.h>
#include <scsi/scsi_ioctl.h>

#include "blktap.h"

int blktap_device_major;

#define dev_to_blktap(_dev) container_of(_dev, struct blktap, device)

struct blktap_req {
        blk_status_t    error;
};

static inline struct blktap_req *blktap_req(struct request *rq)
{
        return blk_mq_rq_to_pdu(rq);
}

static int
blktap_device_open(struct block_device *bdev, fmode_t mode)
{
	struct gendisk *disk = bdev->bd_disk;
	struct blktap_device *tapdev = disk->private_data;

	if (!tapdev)
		return -ENXIO;

	/* NB. we might have bounced a bd trylock by tapdisk. when
	 * failing for reasons not !tapdev, make sure to kick tapdisk
	 * out of destroy wait state again. */

	return 0;
}

static void
blktap_device_release(struct gendisk *disk, fmode_t mode)
{
	struct blktap_device *tapdev = disk->private_data;
	struct block_device *bdev = bdget_disk(disk, 0);
	struct blktap *tap = dev_to_blktap(tapdev);

	bdput(bdev);

	if (!bdev->bd_openers) {
		set_bit(BLKTAP_DEVICE_CLOSED, &tap->dev_inuse);
		blktap_ring_kick_user(tap);
	}
}

static int
blktap_device_getgeo(struct block_device *bd, struct hd_geometry *hg)
{
	/* We don't have real geometry info, but let's at least return
	   values consistent with the size of the device */
	sector_t nsect = get_capacity(bd->bd_disk);
	sector_t cylinders = nsect;

	hg->heads = 0xff;
	hg->sectors = 0x3f;
	sector_div(cylinders, hg->heads * hg->sectors);
	hg->cylinders = cylinders;
	if ((sector_t)(hg->cylinders + 1) * hg->heads * hg->sectors < nsect)
		hg->cylinders = 0xffff;
	return 0;
}

static int
blktap_device_ioctl(struct block_device *bd, fmode_t mode,
		    unsigned command, unsigned long argument)
{
	int i;

	switch (command) {
	case CDROMMULTISESSION:
		BTDBG("FIXME: support multisession CDs later\n");
		for (i = 0; i < sizeof(struct cdrom_multisession); i++)
			if (put_user(0, (char __user *)(argument + i)))
				return -EFAULT;
		return 0;

	case SCSI_IOCTL_GET_IDLUN:
		if (!access_ok(argument, sizeof(struct scsi_idlun)))
			return -EFAULT;

		/* return 0 for now. */
		__put_user(0, &((struct scsi_idlun __user *)argument)->dev_id);
		__put_user(0,
			&((struct scsi_idlun __user *)argument)->host_unique_id);
		return 0;

	default:
		/*printk(KERN_ALERT "ioctl %08x not supported by Xen blkdev\n",
		  command);*/
		return -EINVAL; /* same return as native Linux */
	}

	return 0;
}

static struct block_device_operations blktap_device_file_operations = {
	.owner     = THIS_MODULE,
	.open      = blktap_device_open,
	.release   = blktap_device_release,
	.ioctl     = blktap_device_ioctl,
	.getgeo    = blktap_device_getgeo
};

void
blktap_device_end_request(struct blktap *tap,
			  struct blktap_request *request,
			  blk_status_t error)
{
	struct blktap_device *tapdev = &tap->device;
	struct request *rq = request->rq;

	blktap_ring_unmap_request(tap, request);

	blktap_ring_free_request(tap, request);

	dev_dbg(disk_to_dev(tapdev->gd),
		"end_request: op=%d error=%d bytes=%d\n",
		rq_data_dir(rq), error, blk_rq_bytes(rq));

	// XXX Maybe this lock is unneeded
	spin_lock_irq(&rq->q->queue_lock);
	blk_mq_end_request(rq, error);
	spin_unlock_irq(&rq->q->queue_lock);
}

int
blktap_device_make_request(struct blktap *tap, struct request *rq)
{
	struct blktap_device *tapdev = &tap->device;
	struct blktap_request *request;
	int nsegs;
	int err;

	request = blktap_ring_make_request(tap);
	if (IS_ERR(request)) {
		err = PTR_ERR(request);
		request = NULL;

		if (err == -ENOSPC || err == -ENOMEM)
			goto stop;

		goto fail;
	}

	if (blk_rq_is_passthrough(rq)) {
		err = -EOPNOTSUPP;
		goto fail;
	}

	switch (req_op(rq)) {
		case REQ_OP_DISCARD:
			request->operation = BLKTAP_OP_TRIM;
			request->nr_pages  = 0;
			goto submit;
		case REQ_OP_FLUSH:
			request->operation = BLKTAP_OP_FLUSH;
			request->nr_pages  = 0;
			goto submit;
		case REQ_OP_READ:
			request->operation = BLKTAP_OP_READ;
			break;
		case REQ_OP_WRITE:
			request->operation = BLKTAP_OP_WRITE;
			break;
		default:
			err = -EOPNOTSUPP;
			goto fail;
	}

	nsegs = blk_rq_map_sg(rq->q, rq, request->sg_table);

	err = blktap_request_get_pages(tap, request, nsegs);
	if (err)
		goto stop;

	err = blktap_ring_map_request(tap, request);
	if (err)
		goto fail;

submit:
	request->rq = rq;
	blktap_ring_submit_request(tap, request);

	return 0;

stop:
	tap->stats.st_oo_req++;
	err = -EBUSY;

_out:
	if (request)
		blktap_ring_free_request(tap, request);

	return err;
fail:
	if (printk_ratelimit())
		dev_warn(disk_to_dev(tapdev->gd),
			 "make request: %d, failing\n", err);
	goto _out;
}

static void cleanup_queue(struct request_queue *rq)
{
	struct blktap *tap = rq->queuedata;

	blk_cleanup_queue(rq);
	blk_mq_free_tag_set(&tap->tag_set);
}

static void
blktap_device_do_request(struct request_queue *rq)
{
	struct blktap *tap = rq->queuedata;

	blktap_ring_kick_user(tap);
}

static void
blktap_device_restart(struct blktap *tap)
{
        struct blktap_device *dev;

        dev = &tap->device;

        spin_lock_irq(&dev->lock);

        /* Re-enable calldowns. */
        if (dev->gd) {
                struct request_queue *rq = dev->gd->queue;

                if (blk_queue_stopped(rq))
                        blk_mq_start_hw_queues(rq);

                /* Kick things off immediately. */
                blktap_device_do_request(rq);
        }

        spin_unlock_irq(&dev->lock);
}

void
blktap_device_configure(struct blktap *tap,
			struct blktap_device_info *info)
{
	struct blktap_device *tapdev = &tap->device;
	struct gendisk *gd = tapdev->gd;
	struct request_queue *rq = gd->queue;
	struct queue_limits *limits = &rq->limits;

	set_capacity(gd, info->capacity);
	set_disk_ro(gd, !!(info->flags & BLKTAP_DEVICE_FLAG_RO));

	blk_queue_flag_set(QUEUE_FLAG_VIRT, rq);
	blk_queue_logical_block_size(rq, info->sector_size);

	/* Hard sector size and alignment in hardware */
	blk_queue_physical_block_size(rq, info->phys_block_size);
	blk_queue_alignment_offset(rq, info->phys_block_offset);

	/* Each segment in a request is up to an aligned page in size. */
	blk_queue_segment_boundary(rq, PAGE_SIZE - 1);
	blk_queue_max_segment_size(rq, PAGE_SIZE);

	/* Ensure a merged request will fit in a single I/O ring slot. */
	blk_queue_max_segments(rq, BLKTAP_SEGMENT_MAX);
	blk_queue_max_segment_size(rq, PAGE_SIZE);

	/* Make sure buffer addresses are sector-aligned. */
	blk_queue_dma_alignment(rq, 511);

	/* Make sure there is buffer control on high memory pages */
	blk_queue_bounce_limit(rq, BLK_BOUNCE_HIGH);

	/* Enable cache control */
	if (info->flags & BLKTAP_DEVICE_FLAG_FLUSH)
		blk_queue_write_cache(rq, true, false);

	/* Block discards */
	if (info->flags & BLKTAP_DEVICE_FLAG_TRIM) {
		blk_queue_max_discard_sectors(rq, UINT_MAX);

		limits->discard_granularity = info->trim_block_size;
		limits->discard_alignment   = info->trim_block_offset;

		blk_queue_flag_set(QUEUE_FLAG_DISCARD, rq);
	}
}

static int
blktap_device_validate_info(struct blktap *tap,
			    struct blktap_device_info *info)
{
	struct device *dev = tap->ring.dev;

	/* sector size is is 2^(n >= 9) */
	if (info->sector_size < 512 ||
	    !is_power_of_2(info->sector_size))
		goto fail;

	/* make sure capacity won't overflow */
	if (!info->capacity ||
	    info->capacity > ULLONG_MAX >> ilog2(info->sector_size))
		goto fail;

	/* physical blocks default to logical ones */
	if (!(info->flags & BLKTAP_DEVICE_FLAG_PSZ)) {
		info->phys_block_size   = info->sector_size;
		info->phys_block_offset = 0;
	}

	/* phys block size is 2^n and >= logical */
	if (info->phys_block_size < info->sector_size ||
	    !is_power_of_2(info->phys_block_size))
		goto fail;

	/* alignment offset < physical/logical */
	if (info->phys_block_offset % info->sector_size ||
	    info->phys_block_offset >= info->phys_block_size)
		goto fail;

	/* trim info vs logical addressing */
	if (info->flags & BLKTAP_DEVICE_FLAG_TRIM) {

		if (info->trim_block_size < info->sector_size ||
		    !is_power_of_2(info->trim_block_size))
			goto fail;

		if (info->trim_block_offset % info->sector_size ||
		    info->trim_block_offset >= info->trim_block_size)
			goto fail;
	}

	return 0;

fail:
	dev_err(dev,
		"capacity: %llu, sector-size: %u/%u+%u, "
		"trim: %u+%u flags: %#lx\n",
		info->capacity, info->sector_size,
		info->phys_block_size, info->phys_block_offset,
		info->trim_block_size, info->trim_block_offset,
		info->flags);
	return -EINVAL;
}

int
blktap_device_resume(struct blktap *tap)
{
	int err;

	if (!test_bit(BLKTAP_DEVICE, &tap->dev_inuse))
		return -ENODEV;

	if (!test_bit(BLKTAP_PAUSED, &tap->dev_inuse))
		return 0;

	err = blktap_ring_resume(tap);
	if (err)
		return err;

	BTDBG("restarting device\n");
	blktap_device_restart(tap);

        return 0;
}

int
blktap_device_pause(struct blktap *tap)
{
	unsigned long flags;
	struct blktap_device *dev = &tap->device;

	if (!test_bit(BLKTAP_DEVICE, &tap->dev_inuse))
		return -ENODEV;

	if (test_bit(BLKTAP_PAUSED, &tap->dev_inuse))
		return 0;

	spin_lock_irqsave(&dev->lock, flags);

	blk_mq_stop_hw_queues(dev->gd->queue);
	set_bit(BLKTAP_PAUSE_REQUESTED, &tap->dev_inuse);

	spin_unlock_irqrestore(&dev->lock, flags);

	return blktap_ring_pause(tap);
}

int
blktap_device_destroy(struct blktap *tap)
{
	struct blktap_device *tapdev = &tap->device;
	struct block_device *bdev;
	struct gendisk *gd;
	int err;

	gd = tapdev->gd;
	if (!gd)
		return 0;

	bdev = bdget_disk(gd, 0);

	err = !mutex_trylock(&bdev->bd_mutex);
	if (err) {
		/* NB. avoid a deadlock. the last opener syncs the
		 * bdev holding bd_mutex. */
		err = -EBUSY;
		goto out_nolock;
	}

	if (bdev->bd_openers) {
		err = -EBUSY;
		goto out;
	}

	blk_mq_stop_hw_queues(tap->rq);

	del_gendisk(gd);
	gd->private_data = NULL;

	cleanup_queue(gd->queue);

	put_disk(gd);
	tapdev->gd = NULL;

	clear_bit(BLKTAP_DEVICE, &tap->dev_inuse);

	if (test_bit(BLKTAP_SHUTDOWN_REQUESTED, &tap->dev_inuse))
		blktap_control_destroy_tap(tap);

	err = 0;
out:
	mutex_unlock(&bdev->bd_mutex);
out_nolock:
	bdput(bdev);

	return err;
}

static void
blktap_device_fail_queue(struct blktap *tap)
{
	struct blktap_device *tapdev = &tap->device;
	struct request_queue *q = tapdev->gd->queue;

	spin_lock_irq(&tapdev->lock);
	// Moved inside lock like it was in 4.14
	blk_queue_flag_clear(QUEUE_FLAG_STOPPED, q);
	cleanup_queue(tapdev->gd->queue);

	spin_unlock_irq(&tapdev->lock);
}

int
blktap_device_try_destroy(struct blktap *tap)
{
	int err;

	err = blktap_device_destroy(tap);
	if (err)
		blktap_device_fail_queue(tap);

	return err;
}

static inline void flush_requests(struct blktap_ring *rinfo)
{
	int notify;

	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&rinfo->ring, notify);
}

static blk_status_t blktap_queue_rq(struct blk_mq_hw_ctx *hctx,
				    const struct blk_mq_queue_data *qd)
{
	unsigned long flags;
	struct blktap *tap = hctx->queue->queuedata;
	struct blktap_device *tapdev = &tap->device;
	struct blktap_ring *rinfo = &tap->ring;

	blk_mq_start_request(qd->rq);
	spin_lock_irqsave(&tapdev->lock, flags);
	if (RING_FULL(&rinfo->ring))
		goto out_busy;

	switch (blktap_device_make_request(tap, qd->rq)) {
	case -EBUSY:
		goto out_busy;
		break;
	case -EOPNOTSUPP:
		goto out_err;
		break;
	case 0:
		break;
	}

	if (qd->last)
		blktap_device_do_request(tapdev->gd->queue);

	spin_unlock_irqrestore(&tapdev->lock, flags);
	return BLK_STS_OK;

// EOPNOTSUPP
out_err:
	spin_unlock_irqrestore(&tapdev->lock, flags);
	return BLK_STS_IOERR;

out_busy:
	blk_mq_stop_hw_queue(hctx);
	spin_unlock_irqrestore(&tapdev->lock, flags);
	return BLK_STS_DEV_RESOURCE;
}

static void blktap_complete_rq(struct request *rq)
{
	blk_mq_end_request(rq, blktap_req(rq)->error);
}

static void blktap_commit_rqs(struct blk_mq_hw_ctx *hctx)
{
	struct blktap *tap = hctx->queue->queuedata;
	struct blktap_device *tapdev = &tap->device;

	blktap_device_do_request(tapdev->gd->queue);
}

static const struct blk_mq_ops blktap_mq_ops = {
	.queue_rq       = blktap_queue_rq,
	.complete	= blktap_complete_rq,
	.commit_rqs	= blktap_commit_rqs,
};

static struct request_queue *init_queue(struct blktap *tap)
{
	struct request_queue *rq;

	memset(&tap->tag_set, 0, sizeof(tap->tag_set));
	tap->tag_set.ops = &blktap_mq_ops;
	tap->tag_set.nr_hw_queues = 1;
	tap->tag_set.queue_depth = BLKTAP_RING_SIZE / 2;
	tap->tag_set.numa_node = NUMA_NO_NODE;
	tap->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	tap->tag_set.cmd_size = 0;
	tap->tag_set.driver_data = tap;

	if (blk_mq_alloc_tag_set(&tap->tag_set))
		return NULL;

	rq = blk_mq_init_queue(&tap->tag_set);
	if (IS_ERR(rq)) {
		blk_mq_free_tag_set(&tap->tag_set);
		return rq;
	}

	rq->queuedata = tap;

	tap->rq = rq;

	return rq;
}

int
blktap_device_create(struct blktap *tap, struct blktap_device_info *info)
{
	int minor, err;
	struct gendisk *gd;
	struct request_queue *rq;
	struct blktap_device *tapdev;

	gd     = NULL;
	rq     = NULL;
	tapdev = &tap->device;
	minor  = tap->minor;

	if (test_bit(BLKTAP_DEVICE, &tap->dev_inuse))
		return -EEXIST;

	if (blktap_device_validate_info(tap, info))
		return -EINVAL;

	gd = alloc_disk(1);
	if (!gd) {
		err = -ENOMEM;
		goto fail;
	}

	if (minor < 26) {
		sprintf(gd->disk_name, "td%c", 'a' + minor % 26);
	} else if (minor < (26 + 1) * 26) {
		sprintf(gd->disk_name, "td%c%c",
			'a' + minor / 26 - 1,'a' + minor % 26);
	} else {
		const unsigned int m1 = (minor / 26 - 1) / 26 - 1;
		const unsigned int m2 = (minor / 26 - 1) % 26;
		const unsigned int m3 =  minor % 26;
		sprintf(gd->disk_name, "td%c%c%c",
			'a' + m1, 'a' + m2, 'a' + m3);
	}

	gd->major = blktap_device_major;
	gd->first_minor = minor;
	gd->fops = &blktap_device_file_operations;
	gd->private_data = tapdev;

	spin_lock_init(&tapdev->lock);
	rq = init_queue(tap);
	if (!rq) {
		err = -ENOMEM;
		goto fail;
	}

	gd->queue     = rq;
	tapdev->gd    = gd;

	blktap_device_configure(tap, info);
	add_disk(gd);

	set_bit(BLKTAP_DEVICE, &tap->dev_inuse);

	dev_info(disk_to_dev(gd),
		 "sector-size: %u/%u+%u capacity: %llu"
		 " discard: %u+%u flush: %#lx\n",
		 queue_logical_block_size(rq),
		 queue_physical_block_size(rq),
		 queue_alignment_offset(rq),
		 (unsigned long long)get_capacity(gd),
		 rq->limits.discard_granularity,
		 queue_discard_alignment(rq),
		 rq->queue_flags);

	return 0;

fail:
	if (gd)
		del_gendisk(gd);
	if (rq)
		cleanup_queue(rq);

	return err;
}

size_t
blktap_device_debug(struct blktap *tap, char *buf, size_t size)
{
	struct gendisk *disk = tap->device.gd;
	struct request_queue *q;
	struct block_device *bdev;
	char *s = buf, *end = buf + size;

	if (!disk)
		return 0;

	q = disk->queue;

	s += snprintf(s, end - s,
		      "disk capacity:%llu sector size:%u\n",
		      (unsigned long long)get_capacity(disk),
		      queue_logical_block_size(q));

	s += snprintf(s, end - s,
		      "queue flags:%#lx stopped:%d\n",
		      q->queue_flags, blk_queue_stopped(q));

	bdev = bdget_disk(disk, 0);
	if (bdev) {
		s += snprintf(s, end - s,
			      "bdev openers:%d closed:%d\n",
			      bdev->bd_openers,
			      test_bit(BLKTAP_DEVICE_CLOSED, &tap->dev_inuse));
		bdput(bdev);
	}

	return s - buf;
}

int __init
blktap_device_init()
{
	int major;

	/* Dynamically allocate a major for this device */
	major = register_blkdev(0, "tapdev");
	if (major < 0) {
		BTERR("Couldn't register blktap device\n");
		return -ENOMEM;
	}

	blktap_device_major = major;
	BTINFO("blktap device major %d\n", major);

	return 0;
}

void
blktap_device_exit(void)
{
	if (blktap_device_major)
		unregister_blkdev(blktap_device_major, "tapdev");
}
