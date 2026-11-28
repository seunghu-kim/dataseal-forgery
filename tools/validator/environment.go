package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Only fixed read-only commands are executed. The operator's experiment command
// is recorded as data and is never passed to a shell or executable.
func capture(root string, name string, args ...string) Record {
	c := exec.Command(name, args...)
	c.Dir = root
	b, e := c.CombinedOutput()
	r := Record{"command": append([]string{name}, args...), "stdout_stderr": strings.TrimSpace(string(b)), "status": "completed"}
	if e != nil {
		r["status"] = "metadata_unavailable"
		r["error"] = e.Error()
	}
	return r
}
func fileMetadata(path string) Record {
	b, e := os.ReadFile(path)
	if e != nil {
		return Record{"path": path, "content": missing, "error": e.Error()}
	}
	h := sha256.Sum256(b)
	r := Record{"path": path, "sha256": hex.EncodeToString(h[:])}
	var v any
	if json.Unmarshal(b, &v) == nil {
		r["content"] = v
	} else {
		r["content"] = string(b)
	}
	return r
}
func collectEnvironment(root, command, boundary, profile string, warmup, repeats int) Record {
	host, e := os.Hostname()
	hostValue := any(host)
	if e != nil {
		hostValue = missing
	}
	t := time.Now().UTC()
	thread := Record{}
	for _, k := range strings.Fields("GOMAXPROCS GOFLAGS GODEBUG OMP_NUM_THREADS OMP_DYNAMIC OPENBLAS_NUM_THREADS MKL_NUM_THREADS VECLIB_MAXIMUM_THREADS NUMEXPR_NUM_THREADS") {
		v, ok := os.LookupEnv(k)
		if ok {
			thread[k] = v
		} else {
			thread[k] = "unset"
		}
	}
	git := capture(root, "git", "--no-optional-locks", "rev-parse", "HEAD")
	status := capture(root, "git", "--no-optional-locks", "status", "--porcelain=v1", "--untracked-files=all")
	deps := []Record{}
	for _, p := range []string{"experiments/lattigo/go.mod", "experiments/lattigo/go.sum", "configs/veritas.lock.json", "configs/lattigo_bfv.lock.json", "external/veritas/go.mod"} {
		deps = append(deps, fileMetadata(filepath.Join(root, p)))
	}
	r := Record{"schema_version": "dataseal.environment.v1", "metadata_id": "env-" + t.Format("20060102T150405.000000000Z"), "timestamp_utc": t.Format(time.RFC3339Nano), "machine_id": hostValue, "git_commit": git, "working_tree": status, "os": runtime.GOOS, "os_version": missing, "cpu_model": missing, "physical_cores": missing, "logical_cores": runtime.NumCPU(), "available_ram_bytes": missing, "total_ram_bytes": missing, "go_version": capture(root, "go", "version"), "collector_runtime_version": runtime.Version(), "collector_gomaxprocs": runtime.GOMAXPROCS(0), "thread_environment": thread, "dependencies": deps, "veritas_git_commit": capture(root, "git", "-C", "external/veritas", "rev-parse", "HEAD"), "veritas_working_tree": capture(root, "git", "-C", "external/veritas", "status", "--porcelain=v1"), "bfv_parameter_profiles_operator_supplied": strings.Split(profile, ","), "exact_experiment_command_operator_supplied": command, "operator_command_executed": false, "warmup_count_operator_supplied": warmup, "repetition_count_operator_supplied": repeats, "time_unit": "ns", "timing_boundary_operator_supplied": boundary, "he_security_target_bits": 128, "he_security_verified_bits": missing, "sketch_assumptions": Record{"p": 65537, "r": 10, "Q_auth_max": uint64(4294967296)}, "notes": "Read-only metadata snapshot, not proof of fresh trial provenance. Collector GOMAXPROCS is not an experiment process measurement. No settings changed. Dependency lock contents are declarations, not proof that cached source matches them."}
	if runtime.GOOS == "windows" {
		script := `$o=Get-CimInstance Win32_OperatingSystem; $p=@(Get-CimInstance Win32_Processor); [pscustomobject]@{os_version=($o.Caption+' '+$o.Version+' build '+$o.BuildNumber); cpu_model=($p.Name -join '; '); physical_cores=($p|Measure-Object NumberOfCores -Sum).Sum; logical_cores=($p|Measure-Object NumberOfLogicalProcessors -Sum).Sum; available_ram_bytes=([uint64]$o.FreePhysicalMemory*1024); total_ram_bytes=([uint64]$o.TotalVisibleMemorySize*1024)} | ConvertTo-Json -Compress`
		c := capture(root, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
		r["platform_probe"] = c
		if c["status"] == "completed" {
			var m Record
			if json.Unmarshal([]byte(text(c["stdout_stderr"])), &m) == nil {
				for k, v := range m {
					r[k] = v
				}
			}
		}
	} else {
		r["platform_probe"] = capture(root, "uname", "-a")
		r["platform_limitation"] = "Detailed CPU/available RAM collector currently implemented for Windows; other OS fields remain not_measured."
	}
	return r
}
func validateMetadata(m Record) error {
	if text(m["schema_version"]) != "dataseal.environment.v1" {
		return fmt.Errorf("unsupported environment metadata schema")
	}
	return nil
}
