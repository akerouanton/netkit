package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

var (
	flagIface      string
	flagAttachType string
	flagBPF        string
	flagProgram    string
	flagFIBIface   string
)

func main() {
	flag.StringVar(&flagIface, "iface", "", "Interface to attach the BPF program to")
	flag.StringVar(&flagAttachType, "attach-type", "", "Either: netkit_primary, netkit_peer, or ")
	flag.StringVar(&flagBPF, "bpf", "", "Path to the BPF object")
	flag.StringVar(&flagProgram, "prog", "", "Name of the BPF program to attach to the interface")
	flag.StringVar(&flagFIBIface, "fib-iface", "", "Interface that should be used as the output iface for fib lookups")
	flag.Parse()

	ifIndex, err := net.InterfaceByName(flagIface)
	if err != nil {
		panic(err)
	}

	collSpec, err := ebpf.LoadCollectionSpec(flagBPF)
	if err != nil {
		panic(fmt.Errorf("could not load collection spec from %s: %w", flagBPF, err))
	}

	if flagFIBIface == "" {
		flagFIBIface = flagIface
	}

	fibIfIndex, err := net.InterfaceByName(flagFIBIface)
	if err != nil {
		panic(err)
	}

	// fib_iif is the input interface used for FIB lookups:
	//  - When a packet comes out of the child netns, we want to make a FIB
	//    lookup in the parent netns, hence fib_iif should be the primary
	//    interface.
	//  - When a packet comes in from the host iface (eg. eth0), we want to
	//    resolve the route in the host netns, hence fib_iif should be that
	//    interface.
	if err := collSpec.RewriteConstants(map[string]any{
		"fib_iif": uint32(fibIfIndex.Index),
	}); err != nil {
		panic(fmt.Errorf("could not rewrite constants: %v", err))
	}

	coll, err := ebpf.NewCollectionWithOptions(collSpec, ebpf.CollectionOptions{})
	if err != nil {
		panic(fmt.Errorf("could not load BPF objects from collection spec: %w", err))
	}

	prog, ok := coll.Programs[flagProgram]
	if !ok {
		panic(fmt.Errorf("program %s not found in bpf collection", flagProgram))
	}

	var l link.Link
	if strings.HasPrefix(flagAttachType, "netkit") {
		// Even for netkit_peer, we attach to the primary interface. The kernel
		// expects that interface as it will automatically pick the peer.
		// See https://github.com/torvalds/linux/blob/d3d1556696c1a993eec54ac585fe5bf677e07474/drivers/net/netkit.c#L510-L516
		l, err = attachNetkit(prog, ifIndex.Index, flagAttachType)
	} else if strings.HasPrefix(flagAttachType, "tcx") {
		l, err = attachTCX(prog, ifIndex.Index, flagAttachType)
	} else {
		err = fmt.Errorf("invalid attach type %s", flagAttachType)
	}

	if l == nil {
		panic("invalid ebpf link, but no error returned")
	} else if err != nil {
		panic(err)
	}

	if err := pin(l, flagProgram); err != nil {
		panic(err)
	}
}

func attachNetkit(prog *ebpf.Program, ifi int, typ string) (link.Link, error) {
	var attachType ebpf.AttachType
	if flagAttachType == "netkit_primary" {
		attachType = ebpf.AttachNetkitPrimary
	} else if flagAttachType == "netkit_peer" {
		attachType = ebpf.AttachNetkitPeer
	} else {
		return nil, fmt.Errorf("invalid attach type %s", typ)
	}

	return link.AttachNetkit(link.NetkitOptions{
		Program:   prog,
		Interface: ifi,
		Attach:    attachType,
	})
}

func attachTCX(prog *ebpf.Program, ifi int, typ string) (link.Link, error) {
	var attachType ebpf.AttachType
	if flagAttachType == "tcx_ingress" {
		attachType = ebpf.AttachTCXIngress
	} else {
		return nil, fmt.Errorf("invalid attach type %s", typ)
	}

	return link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Interface: ifi,
		Attach:    attachType,
	})
}

func pin(l link.Link, progName string) error {
	pinPath := "/sys/fs/bpf/" + progName

	if _, err := os.Stat(pinPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err == nil {
		if err := unix.Unlink(pinPath); err != nil {
			return err
		}
	}

	return l.Pin(pinPath)
}
