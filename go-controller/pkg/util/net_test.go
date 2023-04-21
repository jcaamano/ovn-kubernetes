package util

import (
	"net"
	"testing"

	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
)

func TestCompareNetSize(t *testing.T) {
	type args struct {
		ipnet *net.IPNet
		to    int64
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "IPv4 bigger",
			args: args{
				ipnet: ovntest.MustParseIPNet("192.168.1.1/24"),
				to:    254,
			},
			want: 1,
		},
		{
			name: "IPv4 equal",
			args: args{
				ipnet: ovntest.MustParseIPNet("192.168.1.1/24"),
				to:    256,
			},
			want: 0,
		},
		{
			name: "IPv4 smaller",
			args: args{
				ipnet: ovntest.MustParseIPNet("192.168.1.1/24"),
				to:    257,
			},
			want: -1,
		},
		{
			name: "IPv6 bigger",
			args: args{
				ipnet: ovntest.MustParseIPNet("fda6::/120"),
				to:    254,
			},
			want: 1,
		},
		{
			name: "IPv4 equal",
			args: args{
				ipnet: ovntest.MustParseIPNet("fda6::/120"),
				to:    256,
			},
			want: 0,
		},
		{
			name: "IPv4 smaller",
			args: args{
				ipnet: ovntest.MustParseIPNet("fda6::/120"),
				to:    257,
			},
			want: -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CompareNetSize(tt.args.ipnet, tt.args.to); got != tt.want {
				t.Errorf("CompareNetSize() = %v, want %v", got, tt.want)
			}
		})
	}
}
