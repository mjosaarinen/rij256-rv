#	Makefile
#	2025-01-11	Markku-Juhani O. Saarinen <mjos@iki.fi>

#	set USE_ZVKNED_INTRIN to use the intrinsics versions
#CCONFIG	=	-DUSE_ZVKNED_INTRIN

#	adjust paths if need be
XBIN	=	xtest
XCROSS	=	riscv64-unknown-linux-gnu-
CC		=	$(XCROSS)gcc
SPIKE	=	spike

#	ISA string, including target VLEN
RVKISA	=	rv64gcv_zvkned_zvl256b
SPIKEFL	=	--isa=$(RVKISA)_zicntr_zihpm
CFLAGS	=	-Wall -Wextra -O3 $(CCONFIG) -march=$(RVKISA)
ASFLAGS	=	-Wall $(CCONFIG) -march=$(RVKISA)
LDFLAGS	=	-static -march=$(RVKISA)
LDLIBS	=

#	grab all sources
CSRC	= 	$(wildcard *.c)
SSRC	= 	$(wildcard *.S)
OBJS	=	$(CSRC:.c=.o) $(SSRC:.S=.o)

run:	$(XBIN)
	$(SPIKE) $(SPIKEFL)  pk $(XBIN)

$(XBIN): $(OBJS) Makefile
	$(CC) $(LDFLAGS) -o $(XBIN) $(OBJS) $(LDLIBS)

%.o:	%.c
	$(CC) $(CFLAGS) -c $^ -o $@

%.o:	%.[sS]
	$(CC) $(ASFLAGS) -c $^ -o $@

clean:
	$(RM) -f $(XBIN) $(OBJS) *.tmp

