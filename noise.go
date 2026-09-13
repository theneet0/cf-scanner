package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

func SendNoises(udp net.PacketConn, addr *net.UDPAddr, packets []NoisePacket) {
	for _, packet := range packets {
		switch packet.Type {
		case "str":
			udp.WriteTo([]byte(packet.Payload), addr)
		case "base64":
			b64, b64E := base64.StdEncoding.DecodeString(packet.Payload)
			if b64E != nil {
				exitOnError(fmt.Errorf("noise base64 decode error: %w", b64E))
			}
			udp.WriteTo(b64, addr)
		case "hex":
			hex, hexE := hex.DecodeString(packet.Payload)
			if hexE != nil {
				exitOnError(fmt.Errorf("noise hex decode error: %w", hexE))
			}
			udp.WriteTo(hex, addr)
		case "rand":
			bytes := make([]byte, randomRange(packet.Payload))
			_, err := rand.Read(bytes)
			if err != nil {
				exitOnError(fmt.Errorf("noise random bytes error: %w", err))
			}
			udp.WriteTo(bytes, addr)
		}
		time.Sleep(time.Millisecond * time.Duration(randomRange(packet.Sleep)))
	}
}
