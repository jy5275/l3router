## Process this file with automake to produce Makefile.in


bin_PROGRAMS =  \
	l3router

l3router_SOURCES =  \
	l3router.h \
	main_l3router.c \
	utils.c \
	fib.c \
	fib6.c

l3router_LDADD = -L../../lib/libua \
	-L../../lib/libreg \
	-lua \
	-lreg \
	-lpthread 
