.PHONY: build
build:
	docker build -t netkit-loader --target final .

.PHONY: run
run: build
	docker run --rm --name netkit-test -it --pid=host --network=host --privileged netkit-loader /bin/sh -s
