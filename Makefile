# Makefile for libtdsuv

# Tools
CC = gcc
AR = ar
RANLIB = ranlib
CFLAGS = -Wall -g -O2
LDFLAGS = -L/usr/local/lib -L.

CC += -pthread -I. -I/usr/local/include

LIBTDSUV := libtdsuv.a

TEST1 := test1

# Object files for libtdsuv.a
OBJS = sqlrp.o tds_buf.o tds_log.o tds_prelogin.o tds_tokens.o tds_types.o \
    tds_uv.o utils.o

# test1 objects
TEST_OBJS = test1.o conf.o

LIBS = -ltdsuv -luv

all: $(TEST1)

$(TEST1): $(LIBTDSUV) $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJS) $(LDFLAGS) $(LIBS)

$(LIBTDSUV): $(OBJS)
	$(AR) cr $@ $(OBJS)
	$(RANLIB) $@

$(OBJS): Makefile

clean:
	rm -f $(TEST1) $(LIBTDSUV) $(OBJS) $(TEST_OBJS)

#.c.o:
#	$(CC) $(INTERNAL_CFLAGS) $(CPPFLAGS) -o $@ -c $<

