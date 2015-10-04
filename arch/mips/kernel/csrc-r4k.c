/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2007 by Ralf Baechle
 */
#include <linux/clocksource.h>
#include <linux/init.h>

#include <asm/time.h>

#ifdef CONFIG_RALINK_CPUSLEEP_AND_SYSTICK_COUNTER
#include <asm/mach-ralink/rt_mmap.h>
#endif

static cycle_t c0_hpt_read(struct clocksource *cs)
{
#ifdef CONFIG_RALINK_CPUSLEEP_AND_SYSTICK_COUNTER
	return (*((volatile u32 *)(RALINK_COUNT)));
#else
	return read_c0_count();
#endif
}

static struct clocksource clocksource_mips = {

#ifdef CONFIG_RALINK_CPUSLEEP_AND_SYSTICK_COUNTER
	.name		= "Ralink external timer",
	.mask		= 0xffff,
#else
	.name		= "MIPS",
	.mask		= CLOCKSOURCE_MASK(32),
#endif
	.read		= c0_hpt_read,
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};

int __init init_r4k_clocksource(void)
{
	if (!cpu_has_counter || !mips_hpt_frequency)
		return -ENXIO;

	/* Calculate a somewhat reasonable rating value */
	clocksource_mips.rating = 200 + mips_hpt_frequency / 10000000;

#ifdef CONFIG_RALINK_CPUSLEEP_AND_SYSTICK_COUNTER
	clocksource_set_clock(&clocksource_mips, 50000);
#else
	clocksource_set_clock(&clocksource_mips, mips_hpt_frequency);
#endif
	clocksource_register(&clocksource_mips);

	return 0;
}
