package cidranger

import (
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"net"
	"testing"
	"time"

	rnet "github.com/censys/cidranger/net"
	"github.com/stretchr/testify/assert"
)

/*
 ******************************************************************
 Test Contains/ContainingNetworks against basic brute force ranger.
 ******************************************************************
*/

func TestContainsAgainstBaseIPv4(t *testing.T) {
	testContainsAgainstBase(t, 100000, randIPv4Gen)
}

func TestContainingNetworksAgaistBaseIPv4(t *testing.T) {
	testContainingNetworksAgainstBase(t, 100000, randIPv4Gen)
}

func TestCoveredNetworksAgainstBaseIPv4(t *testing.T) {
	testCoversNetworksAgainstBase(t, 100000, randomIPNetGenFactory(ipV4AWSRangesIPNets))
}

// IPv6 spans an extremely large address space (2^128), randomly generated IPs
// will often fall outside of the test ranges (AWS public CIDR blocks), so it
// it more meaningful for testing to run from a curated list of IPv6 IPs.
func TestContainsAgaistBaseIPv6(t *testing.T) {
	testContainsAgainstBase(t, 100000, curatedAWSIPv6Gen)
}

func TestContainingNetworksAgaistBaseIPv6(t *testing.T) {
	testContainingNetworksAgainstBase(t, 100000, curatedAWSIPv6Gen)
}

func TestCoveredNetworksAgainstBaseIPv6(t *testing.T) {
	testCoversNetworksAgainstBase(t, 100000, randomIPNetGenFactory(ipV6AWSRangesIPNets))
}

func testContainsAgainstBase(t *testing.T, iterations int, ipGen ipGenerator) {
	if testing.Short() {
		t.Skip("Skipping memory test in `-short` mode")
	}
	rangers := []Ranger{NewPCTrieRanger()}
	baseRanger := newBruteRanger()
	for _, ranger := range rangers {
		configureRangerWithAWSRanges(t, ranger)
	}
	configureRangerWithAWSRanges(t, baseRanger)

	for i := 0; i < iterations; i++ {
		nn := ipGen()
		expected, err := baseRanger.Contains(nn.ToIP())
		assert.NoError(t, err)
		for _, ranger := range rangers {
			actual, err := ranger.Contains(nn.ToIP())
			assert.NoError(t, err)
			assert.Equal(t, expected, actual)
		}
	}
}

func testContainingNetworksAgainstBase(t *testing.T, iterations int, ipGen ipGenerator) {
	if testing.Short() {
		t.Skip("Skipping memory test in `-short` mode")
	}
	rangers := []Ranger{NewPCTrieRanger()}
	baseRanger := newBruteRanger()
	for _, ranger := range rangers {
		configureRangerWithAWSRanges(t, ranger)
	}
	configureRangerWithAWSRanges(t, baseRanger)

	for i := 0; i < iterations; i++ {
		nn := ipGen()
		expected, err := baseRanger.ContainingNetworks(nn.ToIP())
		assert.NoError(t, err)
		for _, ranger := range rangers {
			actual, err := ranger.ContainingNetworks(nn.ToIP())
			assert.NoError(t, err)
			assert.Equal(t, len(expected), len(actual))
			for _, network := range actual {
				assert.Contains(t, expected, network)
			}
		}
	}
}

func testCoversNetworksAgainstBase(t *testing.T, iterations int, netGen networkGenerator) {
	if testing.Short() {
		t.Skip("Skipping memory test in `-short` mode")
	}
	rangers := []Ranger{NewPCTrieRanger()}
	baseRanger := newBruteRanger()
	for _, ranger := range rangers {
		configureRangerWithAWSRanges(t, ranger)
	}
	configureRangerWithAWSRanges(t, baseRanger)

	for i := 0; i < iterations; i++ {
		network := netGen()
		expected, err := baseRanger.CoveredNetworks(network.IPNet)
		assert.NoError(t, err)
		for _, ranger := range rangers {
			actual, err := ranger.CoveredNetworks(network.IPNet)
			assert.NoError(t, err)
			assert.Equal(t, len(expected), len(actual))
			for _, network := range actual {
				assert.Contains(t, expected, network)
			}
		}
	}
}

func TestSubnets(t *testing.T) {
	cases := []struct {
		original string
		prefix   int
		subnets  []string
		err      error
		name     string
	}{
		{"0.0.0.0/8", 33, nil, rnet.ErrBadMaskLength, "IPv4 prefix too long"},
		{"0.0.0.0/0", 2, []string{"0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"}, nil, "IPv4 /0 to /2"},
		{"10.0.0.0/8", 0, []string{"10.0.0.0/9", "10.128.0.0/9"}, nil, "IPv4 default split /8"},
		{"::/2", 4, []string{"::/4", "1000::/4", "2000::/4", "3000::/4"}, nil, "IPv6 /2 to /4"},
		{"10.0.0.0/15", 15, []string{"10.0.0.0/15"}, nil, "IPv4 prefix self"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ipNet, _ := net.ParseCIDR(tc.original)
			subnets := []net.IPNet{}
			for _, cidr := range tc.subnets {
				_, subnet, _ := net.ParseCIDR(cidr)
				subnets = append(subnets, *subnet)
			}
			actual, err := Subnets(*ipNet, tc.prefix)
			if tc.err == nil {
				assert.Nil(t, err, "No error expected")
			} else {
				assert.Errorf(t, err, "Expected error: %v", tc.err)
			}
			if tc.err == nil && err == nil {
				assert.Equal(t, subnets, actual)
			}
		})
	}
}

/*
 ******************************************************************
 Benchmarks.
 ******************************************************************
*/

func BenchmarkPCTrieHitIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("52.95.110.1"), NewPCTrieRanger())
}
func BenchmarkBruteRangerHitIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("52.95.110.1"), newBruteRanger())
}

func BenchmarkPCTrieHitIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620:107:300f::36b7:ff81"), NewPCTrieRanger())
}
func BenchmarkBruteRangerHitIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620:107:300f::36b7:ff81"), newBruteRanger())
}

func BenchmarkPCTrieMissIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("123.123.123.123"), NewPCTrieRanger())
}
func BenchmarkBruteRangerMissIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("123.123.123.123"), newBruteRanger())
}

func BenchmarkPCTrieHMissIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620::ffff"), NewPCTrieRanger())
}
func BenchmarkBruteRangerMissIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainsUsingAWSRanges(b, net.ParseIP("2620::ffff"), newBruteRanger())
}

func BenchmarkPCTrieHitContainingNetworksIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("52.95.110.1"), NewPCTrieRanger())
}
func BenchmarkBruteRangerHitContainingNetworksIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("52.95.110.1"), newBruteRanger())
}

func BenchmarkPCTrieHitContainingNetworksIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("2620:107:300f::36b7:ff81"), NewPCTrieRanger())
}
func BenchmarkBruteRangerHitContainingNetworksIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("2620:107:300f::36b7:ff81"), newBruteRanger())
}

func BenchmarkPCTrieMissContainingNetworksIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("123.123.123.123"), NewPCTrieRanger())
}
func BenchmarkBruteRangerMissContainingNetworksIPv4UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("123.123.123.123"), newBruteRanger())
}

func BenchmarkPCTrieHMissContainingNetworksIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("2620::ffff"), NewPCTrieRanger())
}
func BenchmarkBruteRangerMissContainingNetworksIPv6UsingAWSRanges(b *testing.B) {
	benchmarkContainingNetworksUsingAWSRanges(b, net.ParseIP("2620::ffff"), newBruteRanger())
}

func benchmarkContainsUsingAWSRanges(tb testing.TB, nn net.IP, ranger Ranger) {
	configureRangerWithAWSRanges(tb, ranger)
	for n := 0; n < tb.(*testing.B).N; n++ {
		ranger.Contains(nn)
	}
}

func benchmarkContainingNetworksUsingAWSRanges(tb testing.TB, nn net.IP, ranger Ranger) {
	configureRangerWithAWSRanges(tb, ranger)
	for n := 0; n < tb.(*testing.B).N; n++ {
		ranger.ContainingNetworks(nn)
	}
}

/*
 ******************************************************************
 Helper methods and initialization.
 ******************************************************************
*/

type ipGenerator func() rnet.NetworkNumber

func randIPv4Gen() rnet.NetworkNumber {
	return rnet.NetworkNumber{rand.Uint32()}
}
func randIPv6Gen() rnet.NetworkNumber {
	return rnet.NetworkNumber{rand.Uint32(), rand.Uint32(), rand.Uint32(), rand.Uint32()}
}
func curatedAWSIPv6Gen() rnet.NetworkNumber {
	randIdx := rand.Intn(len(ipV6AWSRangesIPNets))

	// Randomly generate an IP somewhat near the range.
	network := ipV6AWSRangesIPNets[randIdx]
	nn := rnet.NewNetworkNumber(network.IP)
	ones, bits := network.Mask.Size()
	zeros := bits - ones
	nnPartIdx := zeros / rnet.BitsPerUint32
	nn[nnPartIdx] = rand.Uint32()
	return nn
}

type networkGenerator func() rnet.Network

func randomIPNetGenFactory(pool []*net.IPNet) networkGenerator {
	return func() rnet.Network {
		return rnet.NewNetwork(*pool[rand.Intn(len(pool))])
	}
}

type AWSRanges struct {
	Prefixes     []Prefix     `json:"prefixes"`
	IPv6Prefixes []IPv6Prefix `json:"ipv6_prefixes"`
}

type Prefix struct {
	IPPrefix string `json:"ip_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

type IPv6Prefix struct {
	IPPrefix string `json:"ipv6_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

var awsRanges *AWSRanges
var ipV4AWSRangesIPNets []*net.IPNet
var ipV6AWSRangesIPNets []*net.IPNet

func loadAWSRanges() *AWSRanges {
	file, err := ioutil.ReadFile("./testdata/aws_ip_ranges.json")
	if err != nil {
		panic(err)
	}
	var ranges AWSRanges
	err = json.Unmarshal(file, &ranges)
	if err != nil {
		panic(err)
	}
	return &ranges
}

func configureRangerWithAWSRanges(tb testing.TB, ranger Ranger) {
	for _, prefix := range awsRanges.Prefixes {
		_, network, err := net.ParseCIDR(prefix.IPPrefix)
		assert.NoError(tb, err)
		ranger.Insert(NewBasicRangerEntry(*network))
	}
	for _, prefix := range awsRanges.IPv6Prefixes {
		_, network, err := net.ParseCIDR(prefix.IPPrefix)
		assert.NoError(tb, err)
		ranger.Insert(NewBasicRangerEntry(*network))
	}
}

func init() {
	awsRanges = loadAWSRanges()
	for _, prefix := range awsRanges.IPv6Prefixes {
		_, network, _ := net.ParseCIDR(prefix.IPPrefix)
		ipV6AWSRangesIPNets = append(ipV6AWSRangesIPNets, network)
	}
	for _, prefix := range awsRanges.Prefixes {
		_, network, _ := net.ParseCIDR(prefix.IPPrefix)
		ipV4AWSRangesIPNets = append(ipV4AWSRangesIPNets, network)
	}
	rand.Seed(time.Now().Unix())
}
