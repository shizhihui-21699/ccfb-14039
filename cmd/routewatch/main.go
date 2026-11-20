// Command routewatch is the operator entry point.
//
// Subcommands:
//
//	generate   write a simulated scenario feed to disk
//	replay     run a saved scenario through the detector and score it
//	serve      run the streaming service over a saved feed or live source
//	validate   check the configuration
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"routewatch/internal/config"
	"routewatch/internal/eval"
	"routewatch/internal/feed"
	"routewatch/internal/model"
	"routewatch/internal/report"
	"routewatch/internal/sim"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "generate":
		err = cmdGenerate(os.Args[2:])
	case "replay":
		err = cmdReplay(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "routewatch:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `routewatch — multi-vantage-point BGP hijack detection

usage:
  routewatch generate -config config/topology.yaml -out scenario.json [-seed N] [-duration 36h]
  routewatch replay   -config config/topology.yaml -scenario scenario.json [-json out.json]
  routewatch serve    -config config/topology.yaml -scenario scenario.json [-speed 60] [-addr :8080]
  routewatch validate -config config/topology.yaml
`)
}

func cmdGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	cfgPath := fs.String("config", "config/topology.yaml", "path to configuration")
	out := fs.String("out", "scenario.json", "output scenario file")
	seed := fs.Int64("seed", sim.DefaultOptions().Seed, "scenario seed")
	dur := fs.Duration("duration", sim.DefaultOptions().Duration, "scenario duration")
	name := fs.String("name", "sim-default", "scenario name")
	churn := fs.Float64("churn", sim.DefaultOptions().ChurnPerHour, "ordinary path-churn rate per view")
	outage := fs.Float64("outage", sim.DefaultOptions().OutageFraction, "fraction of views with data gaps")
	attacksOnly := fs.Bool("attacks-only", false, "omit benign look-alike operations")
	if err := fs.Parse(args); err != nil {
		return err
	}
	reg, _, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	opt := sim.DefaultOptions()
	opt.Seed = *seed
	opt.Duration = *dur
	opt.ChurnPerHour = *churn
	opt.OutageFraction = *outage
	opt.AttacksOnly = *attacksOnly
	sc, err := sim.Build(reg, *name, opt)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil && filepath.Dir(*out) != "." {
		return err
	}
	if err := writeJSON(*out, sc); err != nil {
		return err
	}
	fmt.Printf("wrote %s: %d observations, %d labels, %d collectors, %s..%s\n",
		*out, len(sc.Observations), len(sc.Labels), len(reg.VPs),
		sc.Start.Format(time.RFC3339), sc.End.Format(time.RFC3339))
	return nil
}

func cmdReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	cfgPath := fs.String("config", "config/topology.yaml", "path to configuration")
	scPath := fs.String("scenario", "scenario.json", "scenario file")
	jsonOut := fs.String("json", "", "write full result as JSON here")
	verbose := fs.Bool("v", false, "print every alert")
	if err := fs.Parse(args); err != nil {
		return err
	}
	reg, cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	var sc model.Scenario
	if err := readJSON(*scPath, &sc); err != nil {
		return err
	}
	res, err := eval.Replay(reg, cfg, sc, eval.Options{})
	if err != nil {
		return err
	}
	report.Print(os.Stdout, res, reg, report.Options{Verbose: *verbose})
	if *jsonOut != "" {
		if err := writeJSON(*jsonOut, res); err != nil {
			return err
		}
	}
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "config/topology.yaml", "path to configuration")
	scPath := fs.String("scenario", "", "scenario file to stream")
	addr := fs.String("addr", ":8080", "listen address")
	speed := fs.Float64("speed", 60, "replay speed multiplier")
	quiet := fs.Bool("quiet", false, "suppress alert log lines")
	if err := fs.Parse(args); err != nil {
		return err
	}
	reg, cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *scPath == "" {
		return fmt.Errorf("serve requires -scenario")
	}
	var sc model.Scenario
	if err := readJSON(*scPath, &sc); err != nil {
		return err
	}
	srv := feed.NewServer(reg, cfg, feed.Options{
		Speed: *speed,
		Addr:  *addr,
		Quiet: *quiet,
	})
	return srv.Run(sc)
}

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	cfgPath := fs.String("config", "config/topology.yaml", "path to configuration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	reg, cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	fmt.Printf("configuration OK\n")
	fmt.Printf("  self ASN          %s (%s)\n", reg.SelfASN, reg.OrgName)
	fmt.Printf("  monitored         %d prefix(es)\n", len(reg.OurPrefixes))
	for _, p := range reg.OurPrefixes {
		fmt.Printf("                    %s\n", p)
	}
	fmt.Printf("  collectors        %d\n", len(reg.VPs))
	fmt.Printf("  known ASNs        %d\n", len(reg.ASNs))
	fmt.Printf("  ROAs              %d\n", len(reg.ROAs))
	fmt.Printf("  authorizations    %d\n", len(reg.Auths))
	fmt.Printf("  scrub agreements  %d\n", len(reg.Scrubs))
	fmt.Printf("  thresholds        warning>=%d critical>=%d, min %d VP(s), %d window(s)\n",
		cfg.WarningScore, cfg.CriticalScore, cfg.MinVPs, cfg.MinWindows)
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
