#include <common.h>
#include <asm/arch/imx8mq_pins.h>
#include <asm/mach-imx/iomux-v3.h>
#include <asm-generic/gpio.h>
#include <asm/mach-imx/gpio.h>
#include <asm/io.h>
#include "sku_id.h"

#define SKU_ID_0_GPIO	IMX_GPIO_NR(4, 29)
#define SKU_ID_1_GPIO	IMX_GPIO_NR(4, 30)
#define SKU_ID_2_GPIO	IMX_GPIO_NR(4, 31)

/* GPIO port description */
static unsigned long imx8m_gpio_ports[] = {
	[0] = GPIO1_BASE_ADDR,
	[1] = GPIO2_BASE_ADDR,
	[2] = GPIO3_BASE_ADDR,
	[3] = GPIO4_BASE_ADDR,
	[4] = GPIO5_BASE_ADDR,
};

/* use legacy gpio operations before device model is ready. */
static int gpio_direction_input_legacy(unsigned int gpio)
{
	unsigned int port;
	struct gpio_regs *regs;
	u32 l;

	port = gpio/32;
	gpio &= 0x1f;
	regs = (struct gpio_regs *)imx8m_gpio_ports[port];

	l = readl(&regs->gpio_dir);
	/* set direction as input. */
	l &= ~(1 << gpio);
	writel(l, &regs->gpio_dir);

	return 0;
}

static int gpio_get_value_legacy(unsigned gpio)
{
	unsigned int port;
	struct gpio_regs *regs;
	u32 val;

	port = gpio/32;
	gpio &= 0x1f;
	regs = (struct gpio_regs *)imx8m_gpio_ports[port];
	val = (readl(&regs->gpio_dr) >> gpio) & 0x01;

	return val;
}

int get_sku_id() {
	int sku_id = 0, i = 0, value = 0, pin[3];

	pin[0] = SKU_ID_0_GPIO;
	pin[1] = SKU_ID_1_GPIO;
	pin[2] = SKU_ID_2_GPIO;

	for (i = 0; i < 3; i++) {
		gpio_direction_input_legacy(pin[i]);
		if ((value = gpio_get_value_legacy(pin[i])) < 0) {
			printf("Error! Read gpio port: %d failed!\n", pin[i]);
			return -1;
		} else {
			sku_id |= ((value & 0x01) << i);
		}
	}

	return sku_id;
}
