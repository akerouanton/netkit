FROM alpine AS bpf

RUN apk add linux-headers clang clang-dev libbpf libbpf-dev llvm

COPY bpf/ ./

RUN clang -O2 -Wall -mcpu=v1 -g -target bpfel -c bpf.c -o netkit.bpf.o

####################

FROM golang:1.22.5 AS loader

COPY go.mod .
COPY go.sum .
COPY loader/ /go/loader
RUN CGO_ENABLED=0 go build -o bin/loader -gcflags="all=-N -l" ./loader

####################

FROM alpine AS final

RUN apk add --no-cache bpftool curl iperf3 iproute2 iptables tshark

WORKDIR /app
COPY --link --from=bpf /netkit.bpf.o netkit.bpf.o
COPY --link --from=loader /go/bin/loader loader
COPY hack/ ./hack

COPY hack/entrypoint /app/entrypoint
ENTRYPOINT ["/app/entrypoint"]
