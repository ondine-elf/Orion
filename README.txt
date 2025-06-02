For quick experimentation, run the following commands:
    sudo make run
    sudo watch -n1 cat /sys/fs/bpf/flow_map
Then, open a browser and visit some sites to see the flow map entries
go up in live-time.

If you then want to generate a csv file from this
flow map, please run:
    gcc -Wall -Wextra -O2 src/xdp_user_csv.c -o dump -lbpf
    sudo ./dump

Please note that you may have to have libbpf among other dependencies
installed. Generally, they are:
    clang
    llvm
    libbpf
    bpftool
    xdp-tools
    gcc
    linux-headers-$(uname -r)
    make
    libbpf-dev

    