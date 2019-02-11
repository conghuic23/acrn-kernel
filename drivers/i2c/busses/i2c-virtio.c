#include <linux/clk.h>
#include <linux/completion.h>
#include <linux/jiffies.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/platform_device.h>
#include <linux/i2c.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/log2.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/acpi.h>

#define VIRTIO_I2C_TIMEOUT	msecs_to_jiffies(4 * 1000)

struct virtio_i2c_outhdr {
	__virtio16 addr;	/* slave address */
	__virtio16 flags;
	__virtio16 len;		/*msg length*/
};

struct virtio_i2c_msg {
	struct virtio_i2c_outhdr out_hdr;
	char *buf;
	u8 status;
#define VIRTIO_I2C_MSG_OK	0
#define VIRTIO_I2C_MSG_ERR	1
	struct i2c_msg *msg;
};

#define VQ_NAME_LEN  256
struct virtio_i2c_vq {
	spinlock_t vq_lock;
	struct virtqueue *vq;
	char name[VQ_NAME_LEN];
}____cacheline_aligned_in_smp;

struct virtio_i2c {
	struct virtio_device *vdev;
	u32 num_queues;
	struct completion completion;
	struct i2c_adapter adap;
	struct i2c_msg *msg;
	int pos;
	int nmsgs;
	int state; /* see STATE_ */
	struct clk *clk;
	int ip_clock_khz;
	int bus_clock_khz;
	struct virtio_i2c_vq msg_vqs[];
};

static inline struct virtio_i2c *virtio_i2c_adapter(struct virtio_device *vdev)
{
	return vdev->priv;
}

static void virti2c_msg_done(struct virtqueue *vq)
{
	struct virtio_i2c *i2c = virtio_i2c_adapter(vq->vdev);

	printk(KERN_ERR "virti2c_msg_done receive \n");
	complete(&i2c->completion);

	return;
}

static int virtio_queue_add_msg(struct virtqueue *vq,
			struct virtio_i2c_msg *vmsg,
			struct i2c_msg *msg)
{
	struct scatterlist *sgs[3], hdr, bout, bin, status;
	int outcnt = 0, incnt = 0;
	
	vmsg->out_hdr.addr = msg->addr;
	vmsg->out_hdr.flags = msg->flags;
	vmsg->out_hdr.len = msg->len;

	printk(KERN_ERR "add msg: addr=%x, flags=%d len=%d\n", msg->addr, msg->flags, msg->len);

	if (vmsg->out_hdr.len)
		vmsg->buf = kzalloc(vmsg->out_hdr.len, GFP_ATOMIC);

	sg_init_one(&hdr, &vmsg->out_hdr, sizeof(struct virtio_i2c_msg *));
	sgs[outcnt++] = &hdr;

	if (vmsg->buf) {
		if (vmsg->out_hdr.flags & I2C_M_RD) {
			sg_init_one(&bin, vmsg->buf, msg->len);
			sgs[outcnt + incnt++] = &bin;
		} else {
			memcpy(vmsg->buf, msg->buf, msg->len);

			sg_init_one(&bout, vmsg->buf, msg->len);
			sgs[outcnt++] = &bout;
		}
	}

	sg_init_one(&status, &vmsg->status, 1);
	sgs[outcnt + incnt++] = &status;

	return virtqueue_add_sgs(vq, sgs, outcnt, incnt, vmsg, GFP_ATOMIC);
}


static int virtio_xfer(struct i2c_adapter *adap, struct i2c_msg *msgs, int num)
{
	struct virtio_i2c *i2c = i2c_get_adapdata(adap);
	struct virtqueue *vq = i2c->msg_vqs[0].vq;
	struct virtio_i2c_msg *vmsg, *msg_r;
	unsigned long flags;
	int len, i, ret;
	unsigned long time_left;


	printk(KERN_ERR " virtio_xfer vq=%p\n", vq);
	ret = 0;
	if (unlikely(!vq))
		return ret;

	vmsg = kzalloc(sizeof(*vmsg), GFP_ATOMIC);
	vmsg->buf = NULL;

	for (i = 0; i < num; i++) {
		printk(KERN_ERR "start to add msg for  %d  vq=%p\n",i,vq);
		spin_lock_irqsave(&i2c->msg_vqs[0].vq_lock, flags);
		ret = virtio_queue_add_msg(vq, vmsg, &msgs[i]);
		spin_unlock_irqrestore(&i2c->msg_vqs[0].vq_lock, flags);

		printk(KERN_ERR "after add msg for %d \n",i);
		virtqueue_notify(vq);
		printk(KERN_ERR "wait for complete\n");
		/*wait for complete*/
		time_left = wait_for_completion_timeout(&i2c->completion,
						adap->timeout);
		if (!time_left) {
			printk(KERN_ERR "error for msg%d\n", i);
			ret = i ? (i - 1) : 0;
			goto err; 	
		}
		
		printk(KERN_ERR "and continue on get buf \n");
		if ((msg_r = (struct virtio_i2c_msg *)virtqueue_get_buf(vq, &len)) != NULL) {
			if (msg_r->status != VIRTIO_I2C_MSG_OK) {
				ret = i - 1;
				goto err;
			}
			if ((msg_r->out_hdr.flags & I2C_M_RD) && msg_r->out_hdr.len)
				memcpy(msgs[i].buf, msg_r->buf, msg_r->out_hdr.len);
			if (msg_r->buf)
				kfree(msg_r->buf);
		}
		reinit_completion(&i2c->completion);
		printk(KERN_ERR "reinit completion \n");

	}
	if (i == num)
		ret = num;

err:
	kfree(vmsg);
	return ret;
}


static void virtio_i2c_init_vq(struct virtio_i2c_vq *virtio_i2c_vq, struct virtqueue *vq)
{
	spin_lock_init(&virtio_i2c_vq->vq_lock);
	virtio_i2c_vq->vq = vq;
}

static void virtio_i2c_remove_vqs(struct virtio_device *vdev)
{
	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);
}

static int virtio_i2c_init(struct virtio_device *vdev, struct virtio_i2c *virtio_i2c)
{
	int err;
	u32 i;
	u32 num_vqs;
	vq_callback_t **callbacks;
	const char **names;
	struct virtqueue **vqs;

	num_vqs = virtio_i2c->num_queues;

	vqs = kmalloc_array(num_vqs, sizeof(struct virtqueue *), GFP_KERNEL);
	callbacks = kmalloc_array(num_vqs, sizeof(vq_callback_t *),
				  GFP_KERNEL);
	names = kmalloc_array(num_vqs, sizeof(char *), GFP_KERNEL);

	if (!callbacks || !vqs || !names) {
		err = -ENOMEM;
	}
	for (i = 0; i < num_vqs; i++) {
		callbacks[i] = virti2c_msg_done;
		snprintf(virtio_i2c->msg_vqs[i].name, VQ_NAME_LEN, "msg.%d", i);
		names[i] = virtio_i2c->msg_vqs[i].name;
	}

	err = virtio_find_vqs(vdev, num_vqs, vqs, callbacks, names, NULL);
	if (err)
		return err;
	for (i = 0; i < num_vqs; i++) {
		virtio_i2c_init_vq(&virtio_i2c->msg_vqs[i], vqs[i]);
	}
	return 0;
}


static u32 virtio_func(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL;
}

static struct i2c_algorithm virtio_algorithm = {
	.master_xfer = virtio_xfer,
	.functionality = virtio_func,
};

static struct i2c_adapter virtio_adapter = {
	.owner = THIS_MODULE,
	.name = "i2c-virtio",
	.class = I2C_CLASS_DEPRECATED,
	.algo = &virtio_algorithm,
};

static int virtio_i2c_probe(struct virtio_device *vdev)
{
	struct virtio_i2c *virtio_i2c;
	int ret;
	struct device *pdev;

	pdev = vdev->dev.parent;

	if (!ACPI_COMPANION(pdev))
		printk(KERN_ERR "virtio i2c adap does not have acpi node\n");

	virtio_i2c = devm_kzalloc(&vdev->dev, sizeof(*virtio_i2c), GFP_KERNEL);
	if (!virtio_i2c)
		return -ENOMEM;
	/*get config data from FE*/
	virtio_i2c->num_queues = 1;

	init_completion(&virtio_i2c->completion);
	ret = virtio_i2c_init(vdev, virtio_i2c);
	if (ret)
		return ret;

	virtio_i2c->adap = virtio_adapter;
	i2c_set_adapdata(&virtio_i2c->adap, virtio_i2c);
	
	virtio_i2c->adap.dev.parent = &vdev->dev;
	vdev->priv = virtio_i2c;

	ACPI_COMPANION_SET(&virtio_i2c->adap.dev, ACPI_COMPANION(pdev));
	virtio_i2c->adap.timeout = VIRTIO_I2C_TIMEOUT;

	/* add i2c adapter to i2c tree */
	ret = i2c_add_adapter(&virtio_i2c->adap);
	if (ret)
		return ret;

	return ret;
}

static void virtio_i2c_remove(struct virtio_device *vdev)
{
	struct virtio_i2c *i2c = virtio_i2c_adapter(vdev);

	i2c_del_adapter(&i2c->adap);
	virtio_i2c_remove_vqs(vdev);
}
static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_I2CADAP, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

#define VIRTIO_I2C_F_8_BIT 1
#define VIRTIO_I2C_F_10_BIT 2

static unsigned int features[] = {
	VIRTIO_I2C_F_8_BIT,
	VIRTIO_I2C_F_10_BIT,
};

static struct virtio_driver virtio_i2c_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.probe = virtio_i2c_probe,
	.remove = virtio_i2c_remove,
};

static int __init init(void)
{
	int ret = -ENOMEM;

	ret = register_virtio_driver(&virtio_i2c_driver);
	if (ret < 0)
		goto error;

	return 0;

error:
	return ret;

}

static void __exit fini(void)
{

	unregister_virtio_driver(&virtio_i2c_driver);
}

module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio i2c adpater driver");
MODULE_LICENSE("GPL");
