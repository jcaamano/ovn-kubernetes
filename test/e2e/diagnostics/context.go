package diagnostics

import "flag"

var (
	conntrack, iptables, ovsflows, tcpdump bool
)

func RegisterFlags(flags *flag.FlagSet) {
	flags.BoolVar(&conntrack, "collect-contrack", true, "Start daemonset to collect conntrack during test")
	flags.BoolVar(&iptables, "collect-iptables", true, "Start daemonset to collect iptables during test")
	flags.BoolVar(&ovsflows, "collect-ovsflows", true, "Start daemonset to collect OVS flows during test")
	flags.BoolVar(&tcpdump, "collect-tcpdump", true, "Start daemonset to collect tcpdump during test")
}
