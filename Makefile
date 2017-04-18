# Makefile for filter2xdp
#
# Copyright (C) 2017 Tobias Klauser <tklauser@distanz.ch>

PROG = filter2xdp
OBJS = bpf_convert.o bpf_load.o cbpf.o ebpf.o filter_comp.o utils.o filter2xdp.o

LIBS = -lpcap
INCS =

CC	= $(CROSS_COMPILE)gcc
INSTALL	= install
GZIP	= gzip -9 -c

CPPFLAGS ?=
LDFLAGS	?=

CFLAGS_MIN := -W -Wall
ifeq ($(DEBUG), 1)
  CFLAGS_MIN += -g -DDEBUG
endif

CFLAGS ?= -O2 $(INCS) -Wextra
override CFLAGS := $(CFLAGS_MIN) $(CFLAGS)

Q	?= @
ifeq ($(Q),)
  CCQ	= $(CC)
  LDQ	= $(CC)
else
  CCQ	= $(Q)echo "  CC $<" && $(CC)
  LDQ	= $(Q)echo "  LD $@" && $(CC)
endif

all: $(PROG)

$(PROG): $(OBJS)
	$(LDQ) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.c %.h
	$(CCQ) $(CFLAGS) $(CPPFLAGS) -o $@ -c $<

%.o: %.c
	$(CCQ) $(CFLAGS) $(CPPFLAGS) -o $@ -c $<

clean:
	@echo "  CLEAN"
	$(Q)rm -f $(OBJS) $(PROG)
