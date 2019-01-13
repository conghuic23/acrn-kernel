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


struct virtio_i2c_vq {
	spinlock_t vq_lock;
	struct virtqueue *vq;
};

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
	struct i2c_adapter *adap = virtio_i2c_adapter(vq->vdev);
	struct virtio_i2c *vi2c = i2c_get_adapdata(adap);

	virti2c_vq_done(vi2c, vi2c->msg_vqs);
}

static int virtio_xfer(struct i2c_adapter *adap, struct i2c_msg *msgs, int num)
{
	struct virtio_i2c *i2c = i2c_get_adapdata(adap);

	i2c->msg = msgs;
	i2c->pos = 0;
	i2c->nmsgs = num;
	i2c->state = 0;
	/* add vq send function*/
	return num;
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

	trace_printk(" virtio_i2c_init done !!! \n");
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

//shost->can_queue = virtqueue_get_vring_size(vscsi->req_vqs[0].vq);
	virtio_i2c->adap = virtio_adapter;
	i2c_set_adapdata(&virtio_i2c->adap, virtio_i2c);
	virtio_i2c->adap.dev.parent = &vdev->dev;
	vdev->priv = &virtio_adapter;

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
