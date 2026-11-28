package main

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
	"image/color"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func shortID(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:6]) }
func csvTable(path string, header []string, rows [][]string) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if e != nil {
		return e
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if e = w.Write(header); e != nil {
		return e
	}
	for _, r := range rows {
		if e = w.Write(r); e != nil {
			return e
		}
	}
	w.Flush()
	return w.Error()
}
func display(v any) string {
	if v == nil {
		return missing
	}
	return fmt.Sprint(v)
}
func mdCell(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ") }
func label(s Summary) string {
	return text(s.Identity["implementation"]) + " / " + text(s.Identity["verifier"])
}
func figureLabel(s Summary) string {
	switch text(s.Identity["implementation"]) {
	case "synthetic_method_A":
		return "Method A"
	case "private_sketch_synthetic":
		return "Sketch"
	}
	return strings.ReplaceAll(label(s), "_", " ")
}
func metricLabel(s string) string {
	switch s {
	case "total_time_ns":
		return "Total"
	case "evaluation_time_ns":
		return "Server evaluation"
	case "packing_time_ns":
		return "Packing"
	case "paired_client_preparation_ns":
		return "Client preparation"
	case "paired_direct_computation_ns":
		return "Direct computation"
	}
	return s
}

type plotDatum struct {
	Label    string
	Metric   string
	Stat     Metric
	Identity Record
	GroupID  string
}
type errorData struct {
	plotter.XYs
	plotter.YErrors
}

func errorPlot(path, title string, points []plotDatum) error {
	if len(points) == 0 {
		return nil
	}
	p := plot.New()
	p.Title.Text = title
	p.Y.Label.Text = "Time (ms)"
	labels := []string{}
	data := errorData{}
	for i, x := range points {
		m := x.Stat.Median.(float64) / 1e6
		q1 := x.Stat.Q1.(float64) / 1e6
		q3 := x.Stat.Q3.(float64) / 1e6
		data.XYs = append(data.XYs, plotter.XY{X: float64(i), Y: m})
		data.YErrors = append(data.YErrors, struct{ Low, High float64 }{Low: m - q1, High: q3 - m})
		labels = append(labels, x.Label)
	}
	p.NominalX(labels...)
	p.X.Tick.Label.Rotation = 0
	p.X.Tick.Label.Font.Size = vg.Points(8)
	p.Add(plotter.NewGrid())
	sc, e := plotter.NewScatter(data.XYs)
	if e != nil {
		return e
	}
	sc.GlyphStyle.Color = color.NRGBA{R: 20, G: 70, B: 130, A: 255}
	sc.GlyphStyle.Radius = vg.Points(3)
	bars, e := plotter.NewYErrorBars(data)
	if e != nil {
		return e
	}
	bars.LineStyle.Color = sc.GlyphStyle.Color
	p.Add(bars, sc)
	p.Y.Min = 0
	width := vg.Inch * 7
	if len(points) > 6 {
		width = vg.Inch * 10
	}
	if e = p.Save(width, vg.Inch*4.5, path+".svg"); e != nil {
		return e
	}
	if e = p.Save(width, vg.Inch*4.5, path+".pdf"); e != nil {
		return e
	}
	return p.Save(width, vg.Inch*4.5, path+".png")
}
func sourceCSV(path string, points []plotDatum) error {
	rows := [][]string{}
	for _, p := range points {
		r := p.Identity
		rows = append(rows, []string{p.GroupID, text(r["data_origin"]), text(r["parameter_profile"]), text(r["evaluation_key_profile"]), text(r["implementation"]), text(r["verifier"]), canonical(r["input_dimensions"]), display(r["input_reuse_programs"]), display(r["reuse_policy"]), p.Metric, fmt.Sprint(p.Stat.N), display(p.Stat.Median), display(p.Stat.Q1), display(p.Stat.Q3), display(p.Stat.IQR), "ns", canonical(r["timing_boundary"]), p.Label, text(r["experiment_id"]), text(r["run_id"]), text(r["machine_id"]), text(r["metadata_id"]), text(r["workload"]), canonical(r["workload_definition"])})
	}
	return csvTable(path, []string{"group_id", "data_origin", "parameter_profile", "evaluation_key_profile", "implementation", "verifier", "input_dimensions", "input_reuse_programs", "reuse_policy", "metric", "n", "median_ns", "q1_ns", "q3_ns", "iqr_ns", "time_unit", "timing_boundary", "plot_label", "experiment_id", "run_id", "machine_id", "metadata_id", "workload", "workload_definition"}, rows)
}

func GenerateReport(rows []Record, out string) error {
	validation := Validate(rows)
	if !validation.Valid {
		return fmt.Errorf("validation failed: %d issues; run validate first", len(validation.Issues))
	}
	if e := os.Mkdir(out, 0755); e != nil {
		return fmt.Errorf("report needs a NEW output directory: %w", e)
	}
	if e := WriteJSON(filepath.Join(out, "validation.json"), validation); e != nil {
		return e
	}
	if e := WriteCSV(filepath.Join(out, "validated-trials.csv"), rows); e != nil {
		return e
	}
	sums := Analyze(rows)
	if e := WriteJSON(filepath.Join(out, "summary.json"), sums); e != nil {
		return e
	}
	attacks, performance := [][]string{}, [][]string{}
	missingLines := []string{"# Missing evidence", "", "This report consumes supplied observations only. Freshness and machine provenance are operator declarations unless independently audited. No prior dataset is loaded automatically.", "", "Classical 128-bit HE security is a target. No verified security claim is produced. DataSeal, private-sketch and VERITAS are not asserted to have equal authentication security.", ""}
	missingCounts := map[string]map[string]int{}
	for _, r := range rows {
		id := shortID(GroupKey(r))
		if missingCounts[id] == nil {
			missingCounts[id] = map[string]int{}
		}
		for _, k := range fields() {
			if !absent(r[k]) {
				continue
			}
			if k == "error_message" && r["execution_status"] == "completed" {
				continue
			}
			if k == "precondition_satisfied" && r["mathematical_precondition"] == "none" {
				continue
			}
			if (k == "accepted" || k == "attack_success") && r["verifier"] == "none" {
				continue
			}
			missingCounts[id][k]++
		}
	}
	if e := WriteJSON(filepath.Join(out, "missing-measurements.json"), missingCounts); e != nil {
		return e
	}
	missingIDs := []string{}
	for id := range missingCounts {
		missingIDs = append(missingIDs, id)
	}
	sort.Strings(missingIDs)
	for _, id := range missingIDs {
		ks := []string{}
		for k := range missingCounts[id] {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			missingLines = append(missingLines, fmt.Sprintf("- Raw partition %s: %s unavailable in %d supplied record(s); no value inferred.", id, k, missingCounts[id][k]))
		}
	}
	table := []string{"# Supplied-data summaries", "", "Every figure has SVG/PDF and a source-data CSV. Quartiles use linear interpolation (R type 7). Error bars show Q1–Q3, not confidence intervals. Synthetic panels are labeled SYNTHETIC EXAMPLES; they are not experimental evidence.", "", "Full identities, run/profile partitions, denominators, status counts and every timing sample count are in summary.json and the CSV tables.", "", "| Group | Origin | Workload | Method | HE profile | Key profile | Attempted | Completed | Eligible | Success numerator / decisive eligible denominator | Time samples | Repetition target |", "|---|---|---|---|---|---|---:|---:|---:|---|---:|---|"}
	captions := []string{"# Draft figure captions", "", "All figures describe supplied records, not experiments executed by this toolkit. No equal authentication-security claim is made. Measurements with incompatible definitions, runs, HE profiles or key capabilities are never pooled.", ""}
	standard := map[string][]Summary{}
	reuse := map[string][]Summary{}
	for _, s := range sums {
		r := s.Identity
		id := shortID(canonical(r))
		m := s.Metrics["total_time_ns"]
		prefix := []string{id, text(r["data_origin"]), text(r["experiment_id"]), text(r["run_id"]), text(r["workload"]), text(r["implementation"]), text(r["verifier"]), canonical(r["input_dimensions"]), text(r["parameter_profile"]), text(r["evaluation_key_profile"])}
		if text(r["experiment_category"]) == "attack" {
			a := append([]string{}, prefix...)
			a = append(a, fmt.Sprint(s.Attempted), fmt.Sprint(s.Completed), fmt.Sprint(s.Eligible), fmt.Sprint(s.AcceptedIncorrect), fmt.Sprint(s.EligibleSuccess), fmt.Sprint(s.Decisive), display(s.Conditional.Value), canonical(s.Statuses))
			a = append(a, display(s.DistinctPlaintextInputs), display(s.IndependentInputTrials), fmt.Sprint(s.IndependentConditional.Numerator), fmt.Sprint(s.IndependentConditional.Denominator), display(s.IndependentConditional.Value))
			attacks = append(attacks, a)
		}
		if text(r["experiment_category"]) == "performance" {
			for metric, stat := range s.Metrics {
				p := append([]string{}, prefix...)
				p = append(p, metric, fmt.Sprint(stat.N), display(stat.Median), display(stat.Q1), display(stat.Q3), display(stat.IQR), display(s.Target), s.TargetStatus)
				performance = append(performance, p)
			}
		}
		table = append(table, fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %d | %d | %d | %d / %d | %d | %s (%v) |", id, text(r["data_origin"]), mdCell(text(r["workload"])), mdCell(label(s)), text(r["parameter_profile"]), text(r["evaluation_key_profile"]), s.Attempted, s.Completed, s.Eligible, s.EligibleSuccess, s.Decisive, m.N, s.TargetStatus, s.Target))
		for metric, st := range s.Metrics {
			if st.N == 0 {
				missingLines = append(missingLines, fmt.Sprintf("- %s: %s not_measured; no figure synthesized.", id, metric))
			}
		}
		if s.TargetStatus == "unmet" {
			missingLines = append(missingLines, fmt.Sprintf("- %s: performance target unmet: %d valid total-time samples, target %v.", id, m.N, s.Target))
		}
		if s.Completed > s.Decisive && text(r["experiment_category"]) == "attack" {
			missingLines = append(missingLines, fmt.Sprintf("- %s: %d completed trial(s) ineligible or missing decisive observations; excluded from conditional denominator.", id, s.Completed-s.Decisive))
		}
		if key, ok := comparisonKey(r, false); ok {
			standard[key] = append(standard[key], s)
		} else {
			missingLines = append(missingLines, "- "+id+": compatible comparison cannot be established; only standalone table statistics emitted.")
		}
		if _, ok := number(r["input_reuse_programs"]); ok {
			if key, ok := comparisonKey(r, true); ok {
				reuse[key] = append(reuse[key], s)
			}
		}
	}
	baseHeader := []string{"group_id", "data_origin", "experiment_id", "run_id", "workload", "implementation", "verifier", "input_dimensions", "parameter_profile", "evaluation_key_profile"}
	if e := csvTable(filepath.Join(out, "attack-summary.csv"), append(append([]string{}, baseHeader...), "attempted", "completed", "eligible_completed", "accepted_incorrect_completed", "eligible_success_numerator", "eligible_decisive_denominator", "conditional_success_rate", "execution_status_counts", "distinct_plaintext_inputs", "distinct_input_trials_declared_independent", "independent_success_numerator", "independent_decisive_denominator", "independent_conditional_success_rate"), attacks); e != nil {
		return e
	}
	sort.Slice(performance, func(i, j int) bool { return strings.Join(performance[i], "|") < strings.Join(performance[j], "|") })
	if e := csvTable(filepath.Join(out, "performance-summary.csv"), append(append([]string{}, baseHeader...), "metric", "sample_count", "median_ns", "q1_ns", "q3_ns", "iqr_ns", "target_repetitions_total_time", "target_status_total_time"), performance); e != nil {
		return e
	}
	keys := []string{}
	for k := range standard {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		ss := standard[key]
		if text(ss[0].Identity["experiment_category"]) != "performance" {
			continue
		}
		for _, kind := range []string{"execution", "client-vs-direct", "server-packing"} {
			points := []plotDatum{}
			for _, s := range ss {
				metrics := []string{"total_time_ns", "evaluation_time_ns"}
				if kind == "client-vs-direct" {
					metrics = []string{"paired_client_preparation_ns", "paired_direct_computation_ns"}
					if s.Metrics[metrics[0]].N == 0 || s.Metrics[metrics[1]].N == 0 {
						continue
					}
				}
				if kind == "server-packing" {
					metrics = []string{"evaluation_time_ns", "packing_time_ns"}
					if s.Metrics["packing_time_ns"].N == 0 {
						continue
					}
				}
				for _, metric := range metrics {
					st := s.Metrics[metric]
					if st.N == 0 {
						continue
					}
					points = append(points, plotDatum{figureLabel(s) + "\n" + metricLabel(metric), metric, st, s.Identity, shortID(canonical(s.Identity))})
				}
			}
			if len(points) == 0 {
				missingLines = append(missingLines, "- "+shortID(key)+": "+kind+" comparison unavailable; required paired/stage measurements absent.")
				continue
			}
			name := kind + "-" + shortID(key)
			title := kind + " / " + text(ss[0].Identity["parameter_profile"])
			if text(ss[0].Identity["data_origin"]) == "synthetic_example" {
				title = "SYNTHETIC EXAMPLES / " + title
			}
			if e := errorPlot(filepath.Join(out, name), title, points); e != nil {
				return e
			}
			if e := sourceCSV(filepath.Join(out, name+"-source.csv"), points); e != nil {
				return e
			}
			captions = append(captions, "## "+name, "", title+". Points are medians; bars span Q1–Q3. Times are displayed in ms, converted from source-data ns. Stage medians are not additive; packing may overlap evaluation as declared in the supplied boundary. Client preparation is preparation+encryption using only paired complete observations with direct computation. Group sizes and boundaries are in "+name+"-source.csv. Repetition targets are reported separately, with unmet targets retained.", "")
		}
	}
	// Reuse panels retain all workload/profile/boundary identity fields except q and policy.
	rk := []string{}
	for k := range reuse {
		rk = append(rk, k)
	}
	sort.Strings(rk)
	for _, key := range rk {
		ss := reuse[key]
		sort.Slice(ss, func(i, j int) bool {
			ai, _ := number(ss[i].Identity["input_reuse_programs"])
			aj, _ := number(ss[j].Identity["input_reuse_programs"])
			if ai != aj {
				return ai < aj
			}
			return label(ss[i])+text(ss[i].Identity["reuse_policy"]) < label(ss[j])+text(ss[j].Identity["reuse_policy"])
		})
		points := []plotDatum{}
		observed := map[float64]bool{}
		for _, s := range ss {
			q, _ := number(s.Identity["input_reuse_programs"])
			observed[q] = true
			st := s.Metrics["total_time_ns"]
			if st.N > 0 {
				points = append(points, plotDatum{fmt.Sprintf("%s / %s\n%g programs", figureLabel(s), text(s.Identity["reuse_policy"]), q), "total_time_ns", st, s.Identity, shortID(canonical(s.Identity))})
			}
		}
		for _, q := range []float64{1, 2, 4, 8} {
			if !observed[q] {
				missingLines = append(missingLines, fmt.Sprintf("- reuse %s: %g-program observations missing; no interpolation.", shortID(key), q))
			}
		}
		if len(points) == 0 {
			continue
		}
		name := "input-reuse-" + shortID(key)
		title := "Input reuse / " + text(ss[0].Identity["parameter_profile"])
		if text(ss[0].Identity["data_origin"]) == "synthetic_example" {
			title = "SYNTHETIC EXAMPLES / " + title
		}
		if e := errorPlot(filepath.Join(out, name), title, points); e != nil {
			return e
		}
		if e := sourceCSV(filepath.Join(out, name+"-source.csv"), points); e != nil {
			return e
		}
		captions = append(captions, "## "+name, "", title+". Supplied 1/2/4/8-program total costs; medians and Q1–Q3 shown without interpolation. Same program family, input shape, run, HE/key profile and timing definition only. Prefix or repeated-input observations need not be statistically independent; no confidence interval is claimed.", "")
	}
	for _, i := range validation.Issues {
		if i.Severity == "warning" {
			missingLines = append(missingLines, fmt.Sprintf("- row %d / %s: %s", i.Row, i.Field, i.Message))
		}
	}
	for name, lines := range map[string][]string{"TABLES.md": table, "CAPTIONS.md": captions, "MISSING-EVIDENCE.md": missingLines} {
		if e := exclusive(filepath.Join(out, name), []byte(strings.Join(lines, "\n")+"\n")); e != nil {
			return e
		}
	}
	return nil
}
