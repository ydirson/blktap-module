#include <linux/types.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>

#include "blktap.h"

int blktap_debug_level = 1;

static struct class *class;

static ssize_t
blktap_sysfs_set_name(struct device *dev, struct device_attribute *attr, const char *buf, size_t size)
{
	struct blktap *tap;

	tap = dev_get_drvdata(dev);
	if (!tap)
		return 0;

	if (size >= BLKTAP2_MAX_MESSAGE_LEN)
		return -ENAMETOOLONG;

	if (strnlen(buf, size) != size)
		return -EINVAL;

	strcpy(tap->name, buf);

	return size;
}

static ssize_t
blktap_sysfs_get_name(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct blktap *tap;
	ssize_t size;

	tap = dev_get_drvdata(dev);
	if (!tap)
		return 0;

	if (tap->name[0])
		size = sprintf(buf, "%s\n", tap->name);
	else
		size = sprintf(buf, "%d\n", tap->minor);

	return size;
}
static DEVICE_ATTR(name, S_IRUGO|S_IWUSR,
		   blktap_sysfs_get_name, blktap_sysfs_set_name);

static void
blktap_sysfs_remove_work(struct work_struct *work)
{
	struct blktap *tap
		= container_of(work, struct blktap, remove_work);
	blktap_control_destroy_tap(tap);
}

static ssize_t
blktap_sysfs_remove_device(struct device *dev,
			   struct device_attribute *attr,
			   const char *buf, size_t size)
{
	struct blktap *tap;
	int err;

	tap = dev_get_drvdata(dev);
	if (!tap)
		return size;

	if (test_and_set_bit(BLKTAP_SHUTDOWN_REQUESTED, &tap->dev_inuse))
		goto wait;

	if (tap->ring.vma) {
		blkif_sring_t *sring = tap->ring.ring.sring;
		sring->private.tapif_user.msg = BLKTAP2_RING_MESSAGE_CLOSE;
		blktap_ring_kick_user(tap);
	} else {
		INIT_WORK(&tap->remove_work, blktap_sysfs_remove_work);
		schedule_work(&tap->remove_work);
	}
wait:
	err = wait_event_interruptible(tap->remove_wait,
				       !dev_get_drvdata(dev));
	if (err)
		return err;

	return size;
}
static DEVICE_ATTR(remove, S_IWUSR, NULL, blktap_sysfs_remove_device);

static ssize_t
blktap_sysfs_debug_device(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct blktap *tap;
	char *tmp = buf;
	int i;

	tap = dev_get_drvdata(dev);
	if (!tap)
		return 0;

	tmp += sprintf(tmp, "%s (%u:%u), refcnt: %d, dev_inuse: 0x%08lx\n",
		       tap->name, MAJOR(tap->ring.devno),
		       MINOR(tap->ring.devno), atomic_read(&tap->refcnt),
		       tap->dev_inuse);

	if (tap->device.gd) {
		struct gendisk *gd = tap->device.gd;
		struct block_device *bdev = bdget_disk(gd, 0);
		tmp += sprintf(tmp, "capacity: 0x%llx, sector size: %#x, "
			       "device users: %d\n", get_capacity(gd),
			       gd->queue->hardsect_size, bdev->bd_openers);
		bdput(bdev);
	}

	tmp += sprintf(tmp, "pending requests: %d\n", tap->pending_cnt);

	for (i = 0; i < MAX_PENDING_REQS; i++) {
		struct blktap_request *req = tap->pending_requests[i];
		if (!req)
			continue;

		tmp += sprintf(tmp, "req %d: id: %llu, usr_idx: %d, "
			       "status: 0x%02x, pendcnt: %d, "
			       "nr_pages: %u, op: %d, time: %lu:%lu\n",
			       i, (unsigned long long)req->id, req->usr_idx,
			       req->status, atomic_read(&req->pendcnt),
			       req->nr_pages, req->operation, req->time.tv_sec,
			       req->time.tv_usec);
	}

	return (tmp - buf) + 1;
}
static DEVICE_ATTR(debug, S_IRUGO, blktap_sysfs_debug_device, NULL);

static ssize_t
blktap_sysfs_show_task(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct blktap *tap;
	ssize_t rv = 0;

	tap = dev_get_drvdata(dev);
	if (!tap)
		return 0;

	if (tap->ring.task)
		rv = sprintf(buf, "%d\n", tap->ring.task->pid);

	return rv;
}
static DEVICE_ATTR(task, S_IRUGO, blktap_sysfs_show_task, NULL);

int
blktap_sysfs_create(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;
	struct device *dev;
	int err = 0;

	init_waitqueue_head(&tap->remove_wait);

	dev = device_create(class, NULL, ring->devno,
			    tap, "blktap%d", tap->minor);
	if (IS_ERR(dev))
		err = PTR_ERR(dev);
	if (!err)
		err = device_create_file(dev, &dev_attr_name);
	if (!err)
		err = device_create_file(dev, &dev_attr_remove);
	if (!err)
		err = device_create_file(dev, &dev_attr_debug);
	if (!err)
		err = device_create_file(dev, &dev_attr_task);
	if (!err)
		ring->dev = dev;
	else
		device_unregister(dev);

	return err;
}

void
blktap_sysfs_destroy(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;
	struct device *dev;

	dev = ring->dev;

	if (!dev)
		return;

	dev_set_drvdata(dev, NULL);
	wake_up(&tap->remove_wait);

	device_unregister(dev);
	ring->dev = NULL;
}

static ssize_t
blktap_sysfs_show_verbosity(struct class *class, char *buf)
{
	return sprintf(buf, "%d\n", blktap_debug_level);
}

static ssize_t
blktap_sysfs_set_verbosity(struct class *class, const char *buf, size_t size)
{
	int level;

	if (sscanf(buf, "%d", &level) == 1) {
		blktap_debug_level = level;
		return size;
	}

	return -EINVAL;
}
static CLASS_ATTR(verbosity, S_IRUGO|S_IWUSR,
		  blktap_sysfs_show_verbosity, blktap_sysfs_set_verbosity);

static ssize_t
blktap_sysfs_show_devices(struct class *class, char *buf)
{
	int i, ret;
	struct blktap *tap;

	mutex_lock(&blktap_lock);

	ret = 0;
	for (i = 0; i < blktap_max_minor; i++) {
		tap = blktaps[i];
		if (!tap)
			continue;

		if (!test_bit(BLKTAP_DEVICE, &tap->dev_inuse))
			continue;

		ret += sprintf(buf + ret, "%d %s\n", tap->minor, tap->name);
	}

	mutex_unlock(&blktap_lock);

	return ret;
}
static CLASS_ATTR(devices, S_IRUGO, blktap_sysfs_show_devices, NULL);

void
blktap_sysfs_exit(void)
{
	if (class)
		class_destroy(class);
}

int __init
blktap_sysfs_init(void)
{
	struct class *cls;
	int err = 0;

	cls = class_create(THIS_MODULE, "blktap2");
	if (IS_ERR(cls))
		err = PTR_ERR(cls);
	if (!err)
		err = class_create_file(cls, &class_attr_verbosity);
	if (!err)
		err = class_create_file(cls, &class_attr_devices);
	if (!err)
		class = cls;
	else
		class_destroy(cls);

	return err;
}
