.set project_name qsconsole
.set project_type windows
.set project_platforms \
	std500armv4i \
	std500x86 \
	std500sh4 \
	std500mipsii \
	std500mipsii_fp \
	std500mipsiv \
	std500mipsiv_fp \
	ppc50armv4i \
	sp50armv4i \
	wm6std \
	wm6pro
.set project_guid 207AD59E-8DD9-3794-9C00-A40997C07907
.set project_dir apps\\winceutils
.set project_dir_inverse ..\\..
.set project_incdirs \
	apps\\winceutils \
	.
.set project_defs \
	QS_SETUP_EXPORTS \
	HAVE_CONFIG_H
.set project_cflags
.set project_rcflags
.set project_libdirs
.set project_ldflags
.set project_libs
.set project_dependencies
.set outdir .
.set srcs \
	qsconsole.c
.set dir_qsconsole.c apps\\winceutils 
.set custom_tags
.set rsrcs \
	qsconsole.rc
.set dir_qsconsole.rc apps\\winceutils 
.set hdrs \
	qsconsole.h
.set dir_qsconsole.h apps\\winceutils 
