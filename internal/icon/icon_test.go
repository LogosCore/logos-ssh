package icon

import (
	"testing"

	"github.com/logoscore/logos-golang-protocol/protocol"
)

func TestIcons(t *testing.T) {
	for name, svg := range map[string]string{"dark": Dark, "light": Light} {
		if err := protocol.ValidateIcon(svg); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
