/*
Package cidranger provides utility to store CIDR blocks and perform ip
inclusion tests against it.

To create a new instance of the path-compressed trie:

			ranger := NewPCTrieRanger()

To insert or remove an entry (any object that satisfies the RangerEntry
interface):

			_, network, _ := net.ParseCIDR("192.168.0.0/24")
			ranger.Insert(NewBasicRangerEntry(*network))
			ranger.Remove(network)

If you desire for any value to be attached to the entry, simply
create custom struct that satisfies the RangerEntry interface:

			type RangerEntry interface {
				Network() net.IPNet
			}

To test whether an IP is contained in the constructed networks ranger:

			// returns bool, error
			containsBool, err := ranger.Contains(net.ParseIP("192.168.0.1"))

To get a list of CIDR blocks in constructed ranger that contains IP:

			// returns []RangerEntry, error
			entries, err := ranger.ContainingNetworks(net.ParseIP("192.168.0.1"))

To get a list of all IPv4/IPv6 rangers respectively:

			// returns []RangerEntry, error
			entries, err := ranger.CoveredNetworks(*AllIPv4)
			entries, err := ranger.CoveredNetworks(*AllIPv6)

*/
package cidranger

import (
	"container/list"
	"fmt"
	"net"

	rnet "github.com/censys/cidranger/net"
)

// ErrInvalidNetworkInput is returned upon invalid network input.
var ErrInvalidNetworkInput = fmt.Errorf("Invalid network input")

// ErrInvalidNetworkNumberInput is returned upon invalid network input.
var ErrInvalidNetworkNumberInput = fmt.Errorf("Invalid network number input")

// AllIPv4 is a IPv4 CIDR that contains all networks
var AllIPv4 = parseCIDRUnsafe("0.0.0.0/0")

// AllIPv6 is a IPv6 CIDR that contains all networks
var AllIPv6 = parseCIDRUnsafe("0::0/0")

func parseCIDRUnsafe(s string) *net.IPNet {
	_, cidr, _ := net.ParseCIDR(s)
	return cidr
}

// RangerEntry is an interface for insertable entry into a Ranger.
type RangerEntry interface {
	Network() net.IPNet
}

type basicRangerEntry struct {
	ipNet net.IPNet
}

func (b *basicRangerEntry) Network() net.IPNet {
	return b.ipNet
}

// NewBasicRangerEntry returns a basic RangerEntry that only stores the network
// itself.
func NewBasicRangerEntry(ipNet net.IPNet) RangerEntry {
	return &basicRangerEntry{
		ipNet: ipNet,
	}
}

// Ranger is an interface for cidr block containment lookups.
type Ranger interface {
	Insert(entry RangerEntry) error
	Remove(network net.IPNet) (RangerEntry, error)
	Contains(ip net.IP) (bool, error)
	ContainingNetworks(ip net.IP) ([]RangerEntry, error)
	CoveredNetworks(network net.IPNet) ([]RangerEntry, error)
	Len() int
	MissingNetworks() ([]net.IPNet, error)
}

// NewPCTrieRanger returns a versionedRanger that supports both IPv4 and IPv6
// using the path compressed trie implemention.
func NewPCTrieRanger() Ranger {
	return newVersionedRanger(newPrefixTree)
}

// NewIPv4PCTrieRanger returns an IPv4-only Ranger for use-cases where the additional
// version checking and second Trie overhead is not desired.
func NewIPv4PCTrieRanger() Ranger {
	return newPrefixTree(rnet.IPv4)
}

// Util function to leverage the subnet method on std lib net.IPNets
func Subnets(base net.IPNet, prefixlen int) (subnets []net.IPNet, err error) {
	network := rnet.NewNetwork(base)
	subnetworks, err := network.Subnet(prefixlen)
	if err != nil {
		return
	}
	for _, subnet := range subnetworks {
		subnets = append(subnets, subnet.IPNet)
	}
	return
}

// RangerIter is an interface to use with an iterator-like pattern
// ri := RangerIter(x Ranger)
// for ri.Next() {
//     entry := ri.Get()
//     ...
// }
// if err := ri.Error(); err != nil {
//     ...
// }
// While it's not really an iterator, this is exactly what bufio.Scanner does.
// Basically the idea is to have an Error() method which you call after
// iteration is complete to see whether iteration terminated because it was done
// or because an error was encountered midway through.
type RangerIter interface {
	Next() bool
	Get() RangerEntry
	Error() error
}

type bredthRangerIter struct {
	path *list.List
	node *prefixTrie
}

func NewBredthIter(root *prefixTrie) bredthRangerIter {
	iter := bredthRangerIter{
		node: root,
		path: list.New(),
	}
	iter.path.PushBack(root)
	return iter
}

func (i *bredthRangerIter) Next() bool {
	for i.path.Len() > 0 {
		element := i.path.Front()
		i.path.Remove(element)
		i.node = element.Value.(*prefixTrie)
		for _, child := range i.node.children {
			if child != nil {
				i.path.PushBack(child)
			}
		}
		if i.node.hasEntry() {
			return true
		}
	}
	return false
}

func (i *bredthRangerIter) Get() RangerEntry {
	return i.node.entry
}

func (i *bredthRangerIter) Error() error {
	return nil
}
