#ifndef _BLKTAP_H_
#define _BLKTAP_H_

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/init.h>
#include <linux/scatterlist.h>
#include <linux/blktap.h>

extern int blktap_debug_level;
extern int blktap_ring_major;
extern int blktap_device_major;

#define BTPRINTK(level, tag, force, _f, _a...)				\
	do {								\
		if (blktap_debug_level > level &&			\
		    (force || printk_ratelimit()))			\
			printk(tag "%s: " _f, __func__, ##_a);		\
	} while (0)

#define BTDBG(_f, _a...)             BTPRINTK(8, KERN_DEBUG, 1, _f, ##_a)
#define BTINFO(_f, _a...)            BTPRINTK(0, KERN_INFO, 0, _f, ##_a)
#define BTWARN(_f, _a...)            BTPRINTK(0, KERN_WARNING, 0, _f, ##_a)
#define BTERR(_f, _a...)             BTPRINTK(0, KERN_ERR, 0, _f, ##_a)

#define MAX_BLKTAP_DEVICE            16384
#define BLKTAP_DEVICE                4
#define BLKTAP_DEVICE_CLOSED         5
#define BLKTAP_SHUTDOWN_REQUESTED    8

#define BLKTAP_REQUEST_FREE          0
#define BLKTAP_REQUEST_PENDING       1

#define BLKTAP_BIO_POOL_SIZE         2

struct blktap_device {
	spinlock_t                     lock;
	struct gendisk                *gd;
};

struct blktap_request;

struct blktap_ring {
	struct task_struct            *task;

	struct vm_area_struct         *vma;
	struct blktap_front_ring       ring;
	unsigned long                  ring_vstart;
	unsigned long                  user_vstart;

	int                            n_pending;
	struct blktap_request         *pending[BLKTAP_RING_SIZE];

	wait_queue_head_t              poll_wait;

	dev_t                          devno;
	struct device                 *dev;
};

struct blktap_statistics {
	unsigned long                  st_print;
	int                            st_rd_req;
	int                            st_wr_req;
	int                            st_oo_req;
	int                            st_rd_sect;
	int                            st_wr_sect;
	s64                            st_rd_cnt;
	s64                            st_rd_sum_usecs;
	s64                            st_rd_max_usecs;
	s64                            st_wr_cnt;
	s64                            st_wr_sum_usecs;
	s64                            st_wr_max_usecs;	
};

struct blktap_request {
	struct blktap                 *tap;
	struct request                *rq;
	int                            usr_idx;

	int                            operation;
	struct timeval                 time;

	struct scatterlist             sg_table[BLKTAP_SEGMENT_MAX];
	struct page                   *pages[BLKTAP_SEGMENT_MAX];
	int                            nr_pages;
};

#define blktap_for_each_sg(_sg, _req, _i)	\
	for (_sg = (_req)->sg_table, _i = 0;	\
	     _i < (_req)->nr_pages;		\
	     (_sg)++, (_i)++)

struct blktap {
	int                            minor;
	unsigned long                  dev_inuse;

	struct blktap_ring             ring;
	struct blktap_device           device;
	struct blktap_page_pool       *pool;
	struct io_context             *ioc;

	/* device_mutex protects the block device create/destroy. */
	struct mutex                   device_mutex;

	struct list_head               node;

	wait_queue_head_t              remove_wait;
	struct work_struct             remove_work;
	char                           name[BLKTAP_NAME_MAX];

	struct blktap_statistics       stats;
};

struct blktap_page_pool {
	/*
	 * Use a pool-specific reference count for the current pool
	 * users, rather than the kobject reference count. We can then
	 * delete the kobject immediately (and safely) when there are
	 * no users.
	 *
	 * See blktap_page_pool_get() and blktap_page_pool_put().
	 */
	atomic_t                       users;
	struct mempool_s              *bufs;
	spinlock_t                     lock;
	struct kobject                 kobj;
	struct list_head               waiters;
};

extern struct mutex blktap_lock;
extern struct blktap **blktaps;
extern int blktap_max_minor;

int blktap_control_destroy_tap(struct blktap *);
size_t blktap_control_debug(struct blktap *, char *, size_t);

int blktap_ring_init(void);
void blktap_ring_exit(void);
size_t blktap_ring_debug(struct blktap *, char *, size_t);
int blktap_ring_create(struct blktap *);
int blktap_ring_destroy(struct blktap *);
struct blktap_request *blktap_ring_make_request(struct blktap *);
void blktap_ring_free_request(struct blktap *,struct blktap_request *);
void blktap_ring_submit_request(struct blktap *, struct blktap_request *);
int blktap_ring_map_request_segment(struct blktap *, struct blktap_request *, int);
int blktap_ring_map_request(struct blktap *, struct blktap_request *);
void blktap_ring_unmap_request(struct blktap *, struct blktap_request *);
void blktap_ring_set_message(struct blktap *, int);
void blktap_ring_kick_user(struct blktap *);

int blktap_sysfs_init(void);
void blktap_sysfs_exit(void);
int blktap_sysfs_create(struct blktap *);
void blktap_sysfs_destroy(struct blktap *);

int blktap_device_init(void);
void blktap_device_exit(void);
size_t blktap_device_debug(struct blktap *, char *, size_t);
int blktap_device_create(struct blktap *, struct blktap_device_info *);
int blktap_device_destroy(struct blktap *);
void blktap_device_destroy_sync(struct blktap *);
void blktap_device_run_queue(struct blktap *);
void blktap_device_end_request(struct blktap *, struct blktap_request *, int);
void blktap_device_start_queue(struct blktap *tap);

int blktap_page_pool_init(struct kobject *);
void blktap_page_pool_exit(void);
void blktap_page_pool_get(struct blktap_page_pool *pool);
void blktap_page_pool_put(struct blktap_page_pool *pool);
struct blktap_page_pool *blktap_page_pool_get_by_name(const char *);

size_t blktap_request_debug(struct blktap *, char *, size_t);
struct blktap_request *blktap_request_alloc(struct blktap *);
int blktap_request_get_pages(struct blktap *, struct blktap_request *, int);
void blktap_request_free(struct blktap *, struct blktap_request *);
void blktap_request_bounce(struct blktap *, struct blktap_request *, int, int);
void __page_pool_wake(struct blktap_page_pool *pool);

int blktap_ioctx_attach(struct blktap *, int);
void blktap_ioctx_detach(struct blktap *);

#endif
