BPF_SRC := telescope_bpf.c
BPF_OBJ := out/telescope_bpf.o
USR_SRC := telescope_user.c
USR_OUT := out/telescope_user

build:
	@$(MAKE) build_bpf
	@$(MAKE) skeleton
	@$(MAKE) build_usr

skeleton:
	@mkdir -p out
	$(MAKE) build_bpf
	bpftool gen skeleton $(BPF_OBJ) > telescope_skeleton.h

build_bpf: 
	@mkdir -p out
	@clang -O2 \
		-g \
		-Wall \
		-target bpf \
		-c $(BPF_SRC) \
		-o $(BPF_OBJ)

build_usr:
	@mkdir -p out
	@clang -O2\
		-g \
		-Wall \
		$(USR_SRC) \
		xpcapng.c \
		-lelf \
		-lbpf \
		-lz \
		-o $(USR_OUT) 