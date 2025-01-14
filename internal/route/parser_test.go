package route

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseFlowSpecRoute(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		in          string
		expectedOut FlowspecRoute
		expectedErr bool
	}{
		{
			name:        "empty input",
			in:          "",
			expectedOut: FlowspecRoute{},
			expectedErr: true,
		},
		{
			name: "bird2 sample route",
			in:   "flow6 { dst 2001:db8:2::/128; src 2001:db8:1::/128; next header 17; dport 123; }  [igp_router3 2025-01-13 from 2001:2::3] * (100) [i]\n\tType: BGP univ\n\tBGP.origin: IGP\n\tBGP.as_path: \n\tBGP.local_pref: 100\n\tBGP.ext_community: (generic, 0x80060000, 0x4ac80000)",
			expectedOut: FlowspecRoute{
				MatchAttrs: matchAttrs{
					Source:          func() net.IPNet { _, netw, _ := net.ParseCIDR("2001:db8:1::/128"); return *netw }(),
					Destination:     func() net.IPNet { _, netw, _ := net.ParseCIDR("2001:db8:2::/128"); return *netw }(),
					Protocol:        17,
					SourcePort:      0x0,
					DestinationPort: 123,
				},
				SessionAttrs: sessionAttrs{
					SessionName:     "igp_router3",
					NeighborAddress: net.ParseIP("2001:2::3"),
					ImportTime:      "2025-01-13",
				},
				Action:   ActionTrafficRateBytes,
				Argument: func() int64 { f, _ := parseIEEE754Float("0x4ac80000"); return int64(f) }(),
			},
			expectedErr: false,
		},
		{
			name: "bird3 sample route",
			in:   "flow6 { dst 2001:db8:2::/128; src 2001:db8:1::/128; next header 17; dport 123; } unknown [igp_rr 2025-01-13 from 2001:2::2] * (100) [i]\n\tpreference: 100\n\tfrom: 2001:2::2\n\tsource: BGP\n\tbgp_origin: IGP\n\tbgp_path: \n\tbgp_local_pref: 100\n\tbgp_originator_id: 188.245.118.170\n\tbgp_cluster_list: 162.55.169.45\n\tbgp_ext_community: (generic, 0x80060000, 0x4ac80000)\n\tInternal route handling values: 0L 7G 1S id 1",
			expectedOut: FlowspecRoute{
				MatchAttrs: matchAttrs{
					Source:          func() net.IPNet { _, netw, _ := net.ParseCIDR("2001:db8:1::/128"); return *netw }(),
					Destination:     func() net.IPNet { _, netw, _ := net.ParseCIDR("2001:db8:2::/128"); return *netw }(),
					Protocol:        17,
					SourcePort:      0x0,
					DestinationPort: 123,
				},
				SessionAttrs: sessionAttrs{
					SessionName:     "igp_rr",
					NeighborAddress: net.ParseIP("2001:2::2"),
					ImportTime:      "2025-01-13",
				},
				Action:   ActionTrafficRateBytes,
				Argument: func() int64 { f, _ := parseIEEE754Float("0x4ac80000"); return int64(f) }(),
			},
			expectedErr: false,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			out, parseError := ParseFlowSpecRoute(testCase.in)
			assert.Equal(t, testCase.expectedOut, out)

			if testCase.expectedErr {
				assert.Error(t, parseError)
			} else {
				assert.NoError(t, parseError)
			}
		})
	}
}

func Test_parseIEEE754Float(t *testing.T) {
	type args struct {
		hexStr string
	}
	tests := []struct {
		name    string
		args    args
		want    float32
		wantErr bool
	}{
		{
			name: "Without prefix",
			args: args{
				hexStr: "3f800000",
			},
			want: 1.0,
		},
		{
			name: "With prefix",
			args: args{
				hexStr: "0x3f800000",
			},
			want: 1.0,
		},
		{
			name: "Big number",
			args: args{
				hexStr: "0x4ac80000",
			},
			want: 6553600,
		},
		{
			name: "Zero",
			args: args{
				hexStr: "0x00000000",
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIEEE754Float(tt.args.hexStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseIEEE754Float() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseIEEE754Float() got = %v, want %v", got, tt.want)
			}
		})
	}
}
