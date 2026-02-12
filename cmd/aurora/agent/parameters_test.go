package agent

import "testing"

func TestDefaultParametersEnableSigmaNoCollapseWS(t *testing.T) {
	params := DefaultParameters()
	if !params.SigmaNoCollapseWS {
		t.Fatal("SigmaNoCollapseWS should default to true")
	}
}
