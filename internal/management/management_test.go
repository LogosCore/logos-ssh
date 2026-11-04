package management

import (
	"testing"

	"github.com/logoscore/logos-golang-module-core/pkg/mgmt"
)

func TestManifest(t *testing.T) {
	if _, err := mgmt.New(Manifest()); err != nil {
		t.Fatal(err)
	}
}
