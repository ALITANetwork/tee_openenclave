# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

CFLAGS += $(EXTRA_CFLAGS)

CFLAGS +=       \
	-I$(O)      \
	-I$(NP_INC) \
	-I$(OE_INC)

CFLAGS += -DLINUX -DOE_USE_OPTEE

libdirs += $(AR_O)

libnames += oeenclave
libnames += oestdio_enc

srcs-y += ../enc.c

srcs-y += $(GEN)
