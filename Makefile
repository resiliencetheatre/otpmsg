CC=gcc

EXTRA_WARNINGS=-Wall 
CFLAGS=$(EXTRA_WARNINGS)
BINS=otpmsg

otpmsg:	otpmsg.c log.c ini.c binn.c base64.c
	 $(CC) $+ $(CFLAGS) $(GST_CFLAGS) $(GST_LIBS) -o $@ -I.

clean:
	rm -rf $(BINS)

