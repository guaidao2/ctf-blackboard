package protocol_test

import (
	"testing"

	"github.com/guaidao2/ctf-blackboard/internal/protocol"
	"github.com/guaidao2/ctf-blackboard/internal/secure"
)

func TestWireAndAuthVersionsMatch(t *testing.T) {
	if protocol.Version != secure.ProtocolVersion {
		t.Fatalf("protocol.Version=%d secure.ProtocolVersion=%d", protocol.Version, secure.ProtocolVersion)
	}
}
