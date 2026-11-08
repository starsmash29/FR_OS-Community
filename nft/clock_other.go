//go:build !linux

package nft

// kernelMinutesWest: only Linux has nftables.
func kernelMinutesWest() int { return 0 }
