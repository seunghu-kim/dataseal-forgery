package attackrun

import (
	"dsfgo/bfvpack"
	"encoding/json"
	"os"
	"path/filepath"
)

func runTimedTask(ctx bfvpack.Context, s schema, c Config, t task, machine, metadata string, seen map[string]string, emit func(Record) error) error {
	start := attackNow()
	err := runTask(ctx, s, c, t, machine, metadata, seen, emit)
	elapsed := attackNow().Sub(start).Nanoseconds()
	f, e := os.OpenFile(filepath.Join(c.Output, "execution-wall.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	status := "completed"
	if err != nil {
		status = err.Error()
	}
	e = json.NewEncoder(f).Encode(Record{"paired_ciphertext_id": t.ID, "attack": t.Scenario, "n": t.Size.N, "evaluation_key_profile": t.Profile, "is_warmup": t.Warmup, "wall_time_ns": elapsed, "scope": "runTask including all verifier emits and journal sync; excludes campaign context/environment/bootstrap and this wall-log append", "collector_error": status})
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if e != nil {
		return e
	}
	return closeErr
}
