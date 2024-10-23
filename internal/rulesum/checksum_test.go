//go:build linux

package rulesum_test

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"bird-flowspec-daemon/internal/rulesum"
)

func TestCheckSum(t *testing.T) {
	tests := []struct {
		name     string
		rules    []*nftables.Rule
		modify   func(rules []*nftables.Rule)
		wantSame bool // Whether the checksum should remain the same after modification
	}{
		{
			name: "Identical rules",
			rules: []*nftables.Rule{
				{
					Exprs: []expr.Any{
						// Match TCP protocol and drop
						&expr.Meta{
							Key:      expr.MetaKeyL4PROTO,
							Register: 1,
						},
						&expr.Cmp{
							Register: 1,
							Data:     []byte{6}, // 6 is the protocol number for TCP
							Op:       expr.CmpOpEq,
						},
						&expr.Verdict{
							Kind: expr.VerdictDrop,
						},
					},
				},
				{
					Exprs: []expr.Any{
						// Match UDP protocol and accept
						&expr.Meta{
							Key:      expr.MetaKeyL4PROTO,
							Register: 1,
						},
						&expr.Cmp{
							Register: 1,
							Data:     []byte{17}, // 17 is the protocol number for UDP
							Op:       expr.CmpOpEq,
						},
						&expr.Verdict{
							Kind: expr.VerdictAccept,
						},
					},
				},
			},
			modify:   func(rules []*nftables.Rule) {}, // No modification
			wantSame: true,
		},
		{
			name: "Modified rule",
			rules: []*nftables.Rule{
				{
					Exprs: []expr.Any{
						// Match TCP protocol and drop
						&expr.Meta{
							Key:      expr.MetaKeyL4PROTO,
							Register: 1,
						},
						&expr.Cmp{
							Register: 1,
							Data:     []byte{6}, // 6 is the protocol number for TCP
							Op:       expr.CmpOpEq,
						},
						&expr.Verdict{
							Kind: expr.VerdictDrop,
						},
					},
				},
				{
					Exprs: []expr.Any{
						// Match UDP protocol and accept
						&expr.Meta{
							Key:      expr.MetaKeyL4PROTO,
							Register: 1,
						},
						&expr.Cmp{
							Register: 1,
							Data:     []byte{17}, // 17 is the protocol number for UDP
							Op:       expr.CmpOpEq,
						},
						&expr.Verdict{
							Kind: expr.VerdictAccept,
						},
					},
				},
			},
			modify: func(rules []*nftables.Rule) {
				// Modify the second rule to match ICMP instead of UDP
				rules[1].Exprs = []expr.Any{
					&expr.Meta{
						Key:      expr.MetaKeyL4PROTO,
						Register: 1,
					},
					&expr.Cmp{
						Register: 1,
						Data:     []byte{1}, // 1 is the protocol number for ICMP
						Op:       expr.CmpOpEq,
					},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				}
			},
			wantSame: false,
		},
		{
			name: "Balanced modified rule",
			rules: []*nftables.Rule{
				{
					Exprs: []expr.Any{
						// Match TCP protocol and drop
						&expr.Meta{
							Key:      expr.MetaKeyL4PROTO,
							Register: 1,
						},
						&expr.Cmp{
							Register: 1,
							Data:     []byte{6}, // 6 is the protocol number for TCP
							Op:       expr.CmpOpEq,
						},
						&expr.Verdict{
							Kind: expr.VerdictDrop,
						},
					},
				},
				{
					Exprs: []expr.Any{
						// Match UDP protocol and accept
						&expr.Meta{
							Key:      expr.MetaKeyL4PROTO,
							Register: 1,
						},
						&expr.Cmp{
							Register: 1,
							Data:     []byte{17}, // 17 is the protocol number for UDP
							Op:       expr.CmpOpEq,
						},
						&expr.Verdict{
							Kind: expr.VerdictAccept,
						},
					},
				},
			},
			modify: func(rules []*nftables.Rule) {
				// Modify the rules to swap the protocol numbers
				rules[0].Exprs[1].(*expr.Cmp).Data = []byte{17}
				rules[1].Exprs[1].(*expr.Cmp).Data = []byte{6}
			},
			wantSame: false,
		},
		{
			name:     "No rules",
			rules:    []*nftables.Rule{},
			modify:   func(rules []*nftables.Rule) {}, // No modification
			wantSame: true,
		},
	}

	for _, tt := range tests {
		// Capture range variable
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Compute initial checksum
			originalChecksum := rulesum.CheckSum(tt.rules)

			// Apply modification
			tt.modify(tt.rules)

			// Compute new checksum
			newChecksum := rulesum.CheckSum(tt.rules)

			// Compare checksums
			if (originalChecksum == newChecksum) != tt.wantSame {
				t.Errorf("Checksum comparison failed for %s: expected same=%v, got same=%v", tt.name, tt.wantSame, originalChecksum == newChecksum)
			}
		})
	}
}
