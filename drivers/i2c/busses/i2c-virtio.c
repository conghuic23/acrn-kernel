#include <linux/clk.h>
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

	u32 reg_shift;
	u32 reg_io_width;
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

static inline struct i2c_adapter *virtio_i2c_adapter(struct virtio_device *vdev)
{
	return vdev->priv;
}

static void virti2c_vq_done(struct virtio_i2c *vi2c,
			struct virtio_i2c_vq *virti2c_vq)
{
	struct virtqueue *vq=virti2c_vq->vq;
	unsigned int len;
	unsigned long flags;

	spin_lock_irqsave(&virti2c_vq->vq_lock, flags);
	virtqueue_get_buf(vq, &len);
	spin_unlock_irqrestore(&virti2c_vq->vq_lock, flags);
}


static void virti2c_msg_done(struct virtqueue *vq)
{
#if 0
	struct i2c_adapter *adap = virtio_i2c_adapter(vq->vdev);
	struct virtio_i2c *vi2c = i2c_get_adapdata(adap);

	virti2c_vq_done(vi2c, vi2c->msg_vqs);
#endif

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
	bool notify;
	ret = 0;
	notify = false;
	vmsg = kzalloc(sizeof(*vmsg), GFP_ATOMIC);
	vmsg->buf = NULL;

	for (i = 0; i < num; i++) {
		spin_lock_irqsave(&i2c->msg_vqs[0].vq_lock, flags);
		ret = virtio_queue_add_msg(vq, vmsg, &msgs[i]);
		if (virtqueue_kick_prepare(vq))
			notify = true;
		spin_unlock_irqrestore(&i2c->msg_vqs[0].vq_lock, flags);
		if (notify)
			virtqueue_notify(vq);
		
		if ((msg_r = (struct virtio_i2c_msg *)virtqueue_get_buf(vq, &len)) != NULL) {
			if (msg_r->status != VIRTIO_I2C_MSG_OK) {
				ret = i - 1;
				goto err;
			}
			if ((msg_r->out_hdr.flags & I2C_M_RD) &&  msg_r->out_hdr.len)
				memcpy(msgs[i].buf, msg_r->buf, msg_r->out_hdr.len);
			if (msg_r->buf)
				kfree(msg_r->buf);
		}

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
		names[i] = "msg";
	}

	err = virtio_find_vqs(vdev, num_vqs, vqs, callbacks, names, NULL);
	if (err)
		return err;
	for (i=0; i < num_vqs; i++)
		virtio_i2c_init_vq(&virtio_i2c->msg_vqs[i], vqs[i]);

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
	virtio_i2c->reg_shift = 0;
	virtio_i2c->reg_io_width = 0;
	virtio_i2c->ip_clock_khz = 0;
	virtio_i2c->bus_clock_khz = 100;
	virtio_i2c->num_queues = 1;

	if (virtio_i2c->reg_io_width == 0)
		virtio_i2c->reg_io_width = 1; /* Set to default value */
	ret = virtio_i2c_init(vdev, virtio_i2c);
	if (ret)
		return ret;

	virtio_i2c->adap = virtio_adapter;
	i2c_set_adapdata(&virtio_i2c->adap, virtio_i2c);
	
	virtio_i2c->adap.dev.parent = &vdev->dev;
	vdev->priv = &virtio_adapter;

	ACPI_COMPANION_SET(&virtio_i2c->adap.dev, ACPI_COMPANION(pdev));

	/* add i2c adapter to i2c tree */
	ret = i2c_add_adapter(&virtio_i2c->adap);
	if (ret)
		return ret;
	/* add in known devices to the bus */

	return ret;
}

static void virtio_i2c_remove(struct virtio_device *vdev)
{
	struct i2c_adapter *i2c = virtio_i2c_adapter(vdev);

	i2c_del_adapter(i2c);

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
