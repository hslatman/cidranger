package cidranger

import (
	"encoding/binary"
	"math/rand"
	"net"
	"runtime"
	"testing"
	"time"

	rnet "github.com/censys/cidranger/net"
	"github.com/stretchr/testify/assert"
)

func getAllByVersion(version rnet.IPVersion) *net.IPNet {
	if version == rnet.IPv6 {
		return AllIPv6
	}
	return AllIPv4
}

func TestPrefixTrieInsert(t *testing.T) {
	cases := []struct {
		version                      rnet.IPVersion
		inserts                      []string
		expectedNetworksInDepthOrder []string
		name                         string
	}{
		{rnet.IPv4, []string{"192.168.0.1/24"}, []string{"192.168.0.1/24"}, "basic insert"},
		{
			rnet.IPv4,
			[]string{"1.2.3.4/32", "1.2.3.5/32"},
			[]string{"1.2.3.4/32", "1.2.3.5/32"},
			"single ip IPv4 network insert",
		},
		{
			rnet.IPv6,
			[]string{"0::1/128", "0::2/128"},
			[]string{"0::1/128", "0::2/128"},
			"single ip IPv6 network insert",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.1/16", "192.168.0.1/24"},
			[]string{"192.168.0.1/16", "192.168.0.1/24"},
			"in order insert",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.1/32", "192.168.0.1/32"},
			[]string{"192.168.0.1/32"},
			"duplicate network insert",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.1/24", "192.168.0.1/16"},
			[]string{"192.168.0.1/16", "192.168.0.1/24"},
			"reverse insert",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.1/24", "192.168.1.1/24"},
			[]string{"192.168.0.1/24", "192.168.1.1/24"},
			"branch insert",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.1/24", "192.168.1.1/24", "192.168.1.1/30"},
			[]string{"192.168.0.1/24", "192.168.1.1/24", "192.168.1.1/30"},
			"branch inserts",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trie := newPrefixTree(tc.version).(*prefixTrie)
			for _, insert := range tc.inserts {
				_, network, _ := net.ParseCIDR(insert)
				err := trie.Insert(NewBasicRangerEntry(*network))
				assert.NoError(t, err)
			}

			assert.Equal(t, len(tc.expectedNetworksInDepthOrder), trie.Len(), "trie size should match")

			allNetworks, err := trie.CoveredNetworks(*getAllByVersion(tc.version))
			assert.Nil(t, err)
			assert.Equal(t, len(allNetworks), trie.Len(), "trie size should match")

			walk := trie.walkDepth()
			for _, network := range tc.expectedNetworksInDepthOrder {
				_, ipnet, _ := net.ParseCIDR(network)
				expected := NewBasicRangerEntry(*ipnet)
				actual := <-walk
				assert.Equal(t, expected, actual)
			}

			// Ensure no unexpected elements in trie.
			for network := range walk {
				assert.Nil(t, network)
			}
		})
	}
}

func TestPrefixTrieString(t *testing.T) {
	inserts := []string{"192.168.0.1/24", "192.168.1.1/24", "192.168.1.1/30"}
	trie := newPrefixTree(rnet.IPv4).(*prefixTrie)
	for _, insert := range inserts {
		_, network, _ := net.ParseCIDR(insert)
		trie.Insert(NewBasicRangerEntry(*network))
	}
	expected := `0.0.0.0/0 (target_pos:31:has_entry:false)
| 1--> 192.168.0.0/23 (target_pos:8:has_entry:false)
| | 0--> 192.168.0.0/24 (target_pos:7:has_entry:true)
| | 1--> 192.168.1.0/24 (target_pos:7:has_entry:true)
| | | 0--> 192.168.1.0/30 (target_pos:1:has_entry:true)`
	assert.Equal(t, expected, trie.String())
}

func TestPrefixTrieRemove(t *testing.T) {
	cases := []struct {
		version                      rnet.IPVersion
		inserts                      []string
		removes                      []string
		expectedRemoves              []string
		expectedNetworksInDepthOrder []string
		expectedTrieString           string
		name                         string
	}{
		{
			rnet.IPv4,
			[]string{"192.168.0.1/24"},
			[]string{"192.168.0.1/24"},
			[]string{"192.168.0.1/24"},
			[]string{},
			"0.0.0.0/0 (target_pos:31:has_entry:false)",
			"basic remove",
		},
		{
			rnet.IPv4,
			[]string{"1.2.3.4/32", "1.2.3.5/32"},
			[]string{"1.2.3.5/32"},
			[]string{"1.2.3.5/32"},
			[]string{"1.2.3.4/32"},
			`0.0.0.0/0 (target_pos:31:has_entry:false)
| 0--> 1.2.3.4/32 (target_pos:-1:has_entry:true)`,
			"single ip IPv4 network remove",
		},
		{
			rnet.IPv4,
			[]string{"0::1/128", "0::2/128"},
			[]string{"0::2/128"},
			[]string{"0::2/128"},
			[]string{"0::1/128"},
			`0.0.0.0/0 (target_pos:31:has_entry:false)
| 0--> ::1/128 (target_pos:-1:has_entry:true)`,
			"single ip IPv6 network remove",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.1/24", "192.168.0.1/25", "192.168.0.1/26"},
			[]string{"192.168.0.1/25"},
			[]string{"192.168.0.1/25"},
			[]string{"192.168.0.1/24", "192.168.0.1/26"},
			`0.0.0.0/0 (target_pos:31:has_entry:false)
| 1--> 192.168.0.0/24 (target_pos:7:has_entry:true)
| | 0--> 192.168.0.0/26 (target_pos:5:has_entry:true)`,
			"remove path prefix",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.1/24", "192.168.0.1/25", "192.168.0.64/26", "192.168.0.1/26"},
			[]string{"192.168.0.1/25"},
			[]string{"192.168.0.1/25"},
			[]string{"192.168.0.1/24", "192.168.0.1/26", "192.168.0.64/26"},
			`0.0.0.0/0 (target_pos:31:has_entry:false)
| 1--> 192.168.0.0/24 (target_pos:7:has_entry:true)
| | 0--> 192.168.0.0/25 (target_pos:6:has_entry:false)
| | | 0--> 192.168.0.0/26 (target_pos:5:has_entry:true)
| | | 1--> 192.168.0.64/26 (target_pos:5:has_entry:true)`,
			"remove path prefix with more than 1 children",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.1/24", "192.168.0.1/25"},
			[]string{"192.168.0.1/26"},
			[]string{""},
			[]string{"192.168.0.1/24", "192.168.0.1/25"},
			`0.0.0.0/0 (target_pos:31:has_entry:false)
| 1--> 192.168.0.0/24 (target_pos:7:has_entry:true)
| | 0--> 192.168.0.0/25 (target_pos:6:has_entry:true)`,
			"remove non existent",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trie := newPrefixTree(tc.version).(*prefixTrie)
			for _, insert := range tc.inserts {
				_, network, _ := net.ParseCIDR(insert)
				err := trie.Insert(NewBasicRangerEntry(*network))
				assert.NoError(t, err)
			}
			for i, remove := range tc.removes {
				_, network, _ := net.ParseCIDR(remove)
				removed, err := trie.Remove(*network)
				assert.NoError(t, err)
				if str := tc.expectedRemoves[i]; str != "" {
					_, ipnet, _ := net.ParseCIDR(str)
					expected := NewBasicRangerEntry(*ipnet)
					assert.Equal(t, expected, removed)
				} else {
					assert.Nil(t, removed)
				}
			}

			assert.Equal(t, len(tc.expectedNetworksInDepthOrder), trie.Len(), "trie size should match after revmoval")

			allNetworks, err := trie.CoveredNetworks(*getAllByVersion(tc.version))
			assert.Nil(t, err)
			assert.Equal(t, len(allNetworks), trie.Len(), "trie size should match")

			walk := trie.walkDepth()
			for _, network := range tc.expectedNetworksInDepthOrder {
				_, ipnet, _ := net.ParseCIDR(network)
				expected := NewBasicRangerEntry(*ipnet)
				actual := <-walk
				assert.Equal(t, expected, actual)
			}

			// Ensure no unexpected elements in trie.
			for network := range walk {
				assert.Nil(t, network)
			}

			assert.Equal(t, tc.expectedTrieString, trie.String())
		})
	}
}

func TestToReplicateIssue(t *testing.T) {
	cases := []struct {
		version  rnet.IPVersion
		inserts  []string
		ip       net.IP
		networks []string
		name     string
	}{
		{
			rnet.IPv4,
			[]string{"192.168.0.1/32"},
			net.ParseIP("192.168.0.1"),
			[]string{"192.168.0.1/32"},
			"basic containing network for /32 mask",
		},
		{
			rnet.IPv6,
			[]string{"a::1/128"},
			net.ParseIP("a::1"),
			[]string{"a::1/128"},
			"basic containing network for /128 mask",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trie := newPrefixTree(tc.version)
			for _, insert := range tc.inserts {
				_, network, _ := net.ParseCIDR(insert)
				err := trie.Insert(NewBasicRangerEntry(*network))
				assert.NoError(t, err)
			}
			expectedEntries := []RangerEntry{}
			for _, network := range tc.networks {
				_, net, _ := net.ParseCIDR(network)
				expectedEntries = append(expectedEntries, NewBasicRangerEntry(*net))
			}
			contains, err := trie.Contains(tc.ip)
			assert.NoError(t, err)
			assert.True(t, contains)
			networks, err := trie.ContainingNetworks(tc.ip)
			assert.NoError(t, err)
			assert.Equal(t, expectedEntries, networks)
		})
	}
}

type expectedIPRange struct {
	start net.IP
	end   net.IP
}

func TestPrefixTrieContains(t *testing.T) {
	cases := []struct {
		version     rnet.IPVersion
		inserts     []string
		expectedIPs []expectedIPRange
		name        string
	}{
		{
			rnet.IPv4,
			[]string{"192.168.0.0/24"},
			[]expectedIPRange{
				{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.1.0")},
			},
			"basic contains",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.0/24", "128.168.0.0/24"},
			[]expectedIPRange{
				{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.1.0")},
				{net.ParseIP("128.168.0.0"), net.ParseIP("128.168.1.0")},
			},
			"multiple ranges contains",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trie := newPrefixTree(tc.version)
			for _, insert := range tc.inserts {
				_, network, _ := net.ParseCIDR(insert)
				err := trie.Insert(NewBasicRangerEntry(*network))
				assert.NoError(t, err)
			}
			for _, expectedIPRange := range tc.expectedIPs {
				var contains bool
				var err error
				start := expectedIPRange.start
				for ; !expectedIPRange.end.Equal(start); start = rnet.NextIP(start) {
					contains, err = trie.Contains(start)
					assert.NoError(t, err)
					assert.True(t, contains)
				}

				// Check out of bounds ips on both ends
				contains, err = trie.Contains(rnet.PreviousIP(expectedIPRange.start))
				assert.NoError(t, err)
				assert.False(t, contains)
				contains, err = trie.Contains(rnet.NextIP(expectedIPRange.end))
				assert.NoError(t, err)
				assert.False(t, contains)
			}
		})
	}
}

func TestPrefixTrieContainsNetwork(t *testing.T) {
	cases := []struct {
		version  rnet.IPVersion
		inserts  []string
		expected []string
		missing  []string
		name     string
	}{
		{
			rnet.IPv4,
			[]string{"192.168.0.0/24"},
			[]string{"192.168.0.0/24"},
			[]string{},
			"basic contains",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.0/24", "192.168.0.0/25"},
			[]string{},
			[]string{"192.168.0.0/23"},
			"basic not contains",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.0/24"},
			[]string{"192.168.0.1/24"},
			[]string{},
			"basic contains, mismatch bit",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.0/25", "192.168.0.128/25"},
			[]string{},
			[]string{"192.168.0.1/24"},
			"contains, empty parent",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trie := newPrefixTree(tc.version)
			for _, insert := range tc.inserts {
				_, network, _ := net.ParseCIDR(insert)
				err := trie.Insert(NewBasicRangerEntry(*network))
				assert.NoError(t, err)
			}
			for _, expected := range tc.expected {
				_, network, _ := net.ParseCIDR(expected)
				contains, err := trie.ContainsNetwork(*network)
				assert.NoError(t, err)
				assert.True(t, contains)
			}
			for _, expected := range tc.missing {
				_, network, _ := net.ParseCIDR(expected)
				contains, err := trie.ContainsNetwork(*network)
				assert.NoError(t, err)
				assert.False(t, contains)
			}
		})
	}
}

func TestPrefixTrieContainingNetworks(t *testing.T) {
	cases := []struct {
		version  rnet.IPVersion
		inserts  []string
		ip       net.IP
		networks []string
		name     string
	}{
		{
			rnet.IPv4,
			[]string{"192.168.0.0/24"},
			net.ParseIP("192.168.0.1"),
			[]string{"192.168.0.0/24"},
			"basic containing networks",
		},
		{
			rnet.IPv4,
			[]string{"192.168.0.0/24", "192.168.0.0/25"},
			net.ParseIP("192.168.0.1"),
			[]string{"192.168.0.0/24", "192.168.0.0/25"},
			"inclusive networks",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trie := newPrefixTree(tc.version)
			for _, insert := range tc.inserts {
				_, network, _ := net.ParseCIDR(insert)
				err := trie.Insert(NewBasicRangerEntry(*network))
				assert.NoError(t, err)
			}
			expectedEntries := []RangerEntry{}
			for _, network := range tc.networks {
				_, net, _ := net.ParseCIDR(network)
				expectedEntries = append(expectedEntries, NewBasicRangerEntry(*net))
			}
			networks, err := trie.ContainingNetworks(tc.ip)
			assert.NoError(t, err)
			assert.Equal(t, expectedEntries, networks)
		})
	}
}

type coveredNetworkTest struct {
	version  rnet.IPVersion
	inserts  []string
	search   string
	networks []string
	name     string
}

var coveredNetworkTests = []coveredNetworkTest{
	{
		rnet.IPv4,
		[]string{"192.168.0.0/24"},
		"192.168.0.0/16",
		[]string{"192.168.0.0/24"},
		"basic covered networks",
	},
	{
		rnet.IPv4,
		[]string{"192.168.0.0/24"},
		"10.1.0.0/16",
		nil,
		"nothing",
	},
	{
		rnet.IPv4,
		[]string{"192.168.0.0/24", "192.168.0.0/25"},
		"192.168.0.0/16",
		[]string{"192.168.0.0/24", "192.168.0.0/25"},
		"multiple networks",
	},
	{
		rnet.IPv4,
		[]string{"192.168.0.0/24", "192.168.0.0/25", "192.168.0.1/32"},
		"192.168.0.0/16",
		[]string{"192.168.0.0/24", "192.168.0.0/25", "192.168.0.1/32"},
		"multiple networks 2",
	},
	{
		rnet.IPv4,
		[]string{"192.168.1.1/32"},
		"192.168.0.0/16",
		[]string{"192.168.1.1/32"},
		"leaf",
	},
	{
		rnet.IPv4,
		[]string{"0.0.0.0/0", "192.168.1.1/32"},
		"192.168.0.0/16",
		[]string{"192.168.1.1/32"},
		"leaf with root",
	},
	{
		rnet.IPv4,
		[]string{
			"0.0.0.0/0", "192.168.0.0/24", "192.168.1.1/32",
			"10.1.0.0/16", "10.1.1.0/24",
		},
		"192.168.0.0/16",
		[]string{"192.168.0.0/24", "192.168.1.1/32"},
		"path not taken",
	},
	{
		rnet.IPv4,
		[]string{
			"192.168.0.0/15",
		},
		"192.168.0.0/16",
		nil,
		"only masks different",
	},
}

func TestPrefixTrieCoveredNetworks(t *testing.T) {
	for _, tc := range coveredNetworkTests {
		t.Run(tc.name, func(t *testing.T) {
			trie := newPrefixTree(tc.version)
			for _, insert := range tc.inserts {
				_, network, _ := net.ParseCIDR(insert)
				err := trie.Insert(NewBasicRangerEntry(*network))
				assert.NoError(t, err)
			}
			var expectedEntries []RangerEntry
			for _, network := range tc.networks {
				_, net, _ := net.ParseCIDR(network)
				expectedEntries = append(expectedEntries,
					NewBasicRangerEntry(*net))
			}
			_, snet, _ := net.ParseCIDR(tc.search)
			networks, err := trie.CoveredNetworks(*snet)
			assert.NoError(t, err)
			assert.Equal(t, expectedEntries, networks)
		})
	}
}

type missingNetworkTest struct {
	version  rnet.IPVersion
	inserts  []string
	networks []string
	name     string
}

var missingNetworkTests = []missingNetworkTest{
	{
		rnet.IPv4,
		[]string{},
		[]string{"0.0.0.0/0"},
		"empty missing networks",
	},
	{
		rnet.IPv4,
		[]string{"0.0.0.0/1"},
		[]string{"128.0.0.0/1"},
		"/1 missing networks",
	},
	{
		rnet.IPv4,
		[]string{"128.0.0.0/1", "0.0.0.0/2"},
		[]string{"64.0.0.0/2"},
		"path compressed network segment is accounted for",
	},
	{
		rnet.IPv4,
		[]string{"128.0.0.0/1", "0.0.0.0/5"},
		[]string{"64.0.0.0/2", "32.0.0.0/3", "16.0.0.0/4", "8.0.0.0/5"},
		"multiple path compressed segments",
	},
	{
		rnet.IPv4,
		[]string{"0.0.0.0/2", "224.0.0.0/3"},
		[]string{"64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/3"},
		"linear path compressed segments",
	},
	{
		rnet.IPv4,
		[]string{"80.0.0.0/5"},
		[]string{"0.0.0.0/2", "96.0.0.0/3", "64.0.0.0/4", "88.0.0.0/5", "128.0.0.0/1"},
		"non-linear path compressed segment",
	},
	{
		rnet.IPv4,
		[]string{"0.0.0.0/3", "64.0.0.0/3", "96.0.0.0/3", "160.0.0.0/3", "192.0.0.0/3"},
		[]string{"32.0.0.0/3", "128.0.0.0/3", "224.0.0.0/3"},
		"same-level missing blocks",
	},
	{
		rnet.IPv4,
		[]string{"128.0.0.0/1", "0.0.0.0/32"},
		[]string{"64.0.0.0/2", "32.0.0.0/3", "16.0.0.0/4", "8.0.0.0/5", "4.0.0.0/6",
			"2.0.0.0/7", "1.0.0.0/8", "0.128.0.0/9", "0.64.0.0/10", "0.32.0.0/11",
			"0.16.0.0/12", "0.8.0.0/13", "0.4.0.0/14", "0.2.0.0/15", "0.1.0.0/16",
			"0.0.128.0/17", "0.0.64.0/18", "0.0.32.0/19", "0.0.16.0/20", "0.0.8.0/21",
			"0.0.4.0/22", "0.0.2.0/23", "0.0.1.0/24", "0.0.0.128/25", "0.0.0.64/26",
			"0.0.0.32/27", "0.0.0.16/28", "0.0.0.8/29", "0.0.0.4/30", "0.0.0.2/31",
			"0.0.0.1/32"},
		"/32 missing handled correctly",
	},
	{
		rnet.IPv6,
		[]string{"::/1"},
		[]string{"8000::/1"},
		"/1 missing networks v6",
	},
}

func TestPrefixTrieMissingNetworks(t *testing.T) {
	for _, tc := range missingNetworkTests {
		t.Run(tc.name, func(t *testing.T) {
			trie := newPrefixTree(tc.version)
			for _, insert := range tc.inserts {
				_, network, _ := net.ParseCIDR(insert)
				err := trie.Insert(NewBasicRangerEntry(*network))
				assert.NoError(t, err)
			}
			var expectedEntries []net.IPNet
			for _, network := range tc.networks {
				_, net, _ := net.ParseCIDR(network)
				expectedEntries = append(expectedEntries, (*net))
			}
			networks, err := trie.MissingNetworks()
			assert.NoError(t, err)
			assert.Equal(t, expectedEntries, networks)
		})
	}
}

func TestTrieMemUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory test in `-short` mode")
	}
	numIPs := 100000
	runs := 10

	// Avg heap allocation over all runs should not be more than the heap allocation of first run multiplied
	// by threshold, picking 1% as sane number for detecting memory leak.
	thresh := 1.01

	trie := newPrefixTree(rnet.IPv4)

	var baseLineHeap, totalHeapAllocOverRuns uint64
	for i := 0; i < runs; i++ {
		t.Logf("Executing Run %d of %d", i+1, runs)

		// Insert networks.
		for n := 0; n < numIPs; n++ {
			trie.Insert(NewBasicRangerEntry(GenLeafIPNet(GenIPV4())))
		}
		t.Logf("Inserted All (%d networks)", trie.Len())
		assert.Less(t, 0, trie.Len(), "Len should > 0")
		assert.LessOrEqualf(t, trie.Len(), numIPs, "Len should <= %d", numIPs)

		allNetworks, err := trie.CoveredNetworks(*getAllByVersion(rnet.IPv4))
		assert.Nil(t, err)
		assert.Equal(t, len(allNetworks), trie.Len(), "trie size should match")

		// Remove networks.
		_, all, _ := net.ParseCIDR("0.0.0.0/0")
		ll, _ := trie.CoveredNetworks(*all)
		for i := 0; i < len(ll); i++ {
			trie.Remove(ll[i].Network())
		}
		t.Logf("Removed All (%d networks)", len(ll))
		assert.Equal(t, 0, trie.Len(), "Len after removal should == 0")

		// Perform GC
		runtime.GC()

		// Get HeapAlloc stats.
		heapAlloc := GetHeapAllocation()
		totalHeapAllocOverRuns += heapAlloc
		if i == 0 {
			baseLineHeap = heapAlloc
		}
	}

	// Assert that heap allocation from first loop is within set threshold of avg over all runs.
	assert.Less(t, uint64(0), baseLineHeap)
	assert.LessOrEqual(t, float64(baseLineHeap), float64(totalHeapAllocOverRuns/uint64(runs))*thresh)
}

func GenLeafIPNet(ip net.IP) net.IPNet {
	return net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(32, 32),
	}
}

// GenIPV4 generates an IPV4 address
func GenIPV4() net.IP {
	rand.Seed(time.Now().UnixNano())
	var min, max int
	min = 1
	max = 4294967295
	nn := rand.Intn(max-min) + min
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, uint32(nn))
	return ip
}

func GetHeapAllocation() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}
