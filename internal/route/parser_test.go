package route

import "testing"

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
