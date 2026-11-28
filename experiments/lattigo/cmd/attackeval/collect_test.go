package main

import (
	"flag"
	"testing"
)

func TestCollectionHelpDoesNotRunExperiments(t *testing.T) {
	if e := collectMain([]string{"--collect", "--help"}); e != flag.ErrHelp {
		t.Fatalf("help should stop before execution: %v", e)
	}
}
