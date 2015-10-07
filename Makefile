OBJS = lldd.o lldp.o cdp.o lldp_pdu.o list.o lldp_obj.o lldp_str.o lldp_timer.o
SRCS = $(OBJS:%.o=%.c)

CFLAGS = -xsb -g -mt
LDLIBS += -lscf -ldlpi -lsocket -lnsl -lumem

BIN = lldd

CPPFLAGS += -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS -D__EXTENSIONS__ -DDEBUG

$(BIN): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)

lldp.o: lldd.h lldp.h lldp_int.h
lldp_pdu.o: lldp.h lldd.h lldp_int.h
lldp_obj.o: lldp.h lldp_int.h
lldd.o: lldd.h lldp.h cdp.h

%.o: %.c
	$(COMPILE.c) $<

clean:
	rm -f $(BIN) $(OBJS)
