// Command hijackwatch is a BGP route-hijack monitor for a small set of
// organisation-owned prefixes.
//
// Subcommands:
//
//	hijackwatch sim  -write dataset.json          generate a synthetic dataset
//	hijackwatch eval -data dataset.json           replay + score against truth
//	hijackwatch serve -data dataset.json          stream it into the live API
//	hijackwatch serve -config hijackwatch.yaml    run the live API only
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"hijackwatch/internal/api"
	"hijackwatch/internal/detect"
	"hijackwatch/internal/policy"
	"hijackwatch/internal/replay"
	"hijackwatch/internal/sim"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "sim":
		err = cmdSim(os.Args[2:])
	case "eval":
		err = cmdEval(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `hijackwatch - BGP hijack monitoring

usage:
  hijackwatch sim   [-out dataset.json] [-seed N] [-hours H] [-noise N]
  hijackwatch eval  [-data dataset.json] [-v]
  hijackwatch serve [-data dataset.json] [-config file.yaml] [-addr :8080] [-speed 240]

The generated data is entirely fictional (documentation prefixes and invented
AS numbers).  eval replays it through the detector and scores the alerts
against the ground truth built into the dataset.
`)
}

func cmdSim(args []string) error {
	fs := flag.NewFlagSet("sim", flag.ExitOnError)
	out := fs.String("out", "dataset.json", "output dataset path")
	seed := fs.Int64("seed", sim.DefaultOptions().Seed, "random seed")
	hours := fs.Int("hours", 36, "simulated hours")
	noise := fs.Int("noise", sim.DefaultOptions().NoisePrefixes, "background noise prefixes")
	fs.Parse(args)

	opt := sim.DefaultOptions()
	opt.Seed = *seed
	opt.Duration = time.Duration(*hours) * time.Hour
	opt.NoisePrefixes = *noise
	ds, err := sim.Build(opt)
	if err != nil {
		return err
	}
	return writeJSON(*out, ds)
}

func cmdEval(args []string) error {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	data := fs.String("data", "dataset.json", "dataset path")
	verbose := fs.Bool("v", false, "print every alert")
	fs.Parse(args)

	ds, err := loadDataset(*data)
	if err != nil {
		return err
	}
	det := detect.New(ds.Policy)
	res := replay.Run(ds, det)
	fmt.Print(replay.Report(res))
	if *verbose {
		fmt.Println("\n=== alerts ===")
		for _, a := range res.Alerts {
			fmt.Println(replay.AlertLine(a))
		}
	}
	m := replay.Score(res)
	if m.FalseNegatives > 0 || m.FalsePositives > 0 {
		os.Exit(1)
	}
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	data := fs.String("data", "", "optional dataset to replay into the API")
	cfgPath := fs.String("config", "", "policy YAML (otherwise the sim's built-in policy)")
	addr := fs.String("addr", ":8080", "listen address")
	usPerStep := fs.Int("us", 0, "replay pacing: real microseconds per simulated second (0 = as fast as possible)")
	fs.Parse(args)

	var det *detect.Detector
	var ds *sim.Dataset
	if *data != "" {
		d, err := loadDataset(*data)
		if err != nil {
			return err
		}
		ds = &d
		det = detect.New(d.Policy)
	} else if *cfgPath != "" {
		cfg, err := policy.Load(*cfgPath)
		if err != nil {
			return err
		}
		det = detect.New(cfg)
	} else {
		return fmt.Errorf("serve needs -data or -config")
	}

	srv := api.New(det)
	srv.SetMeta(apiMeta(*data, ds))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if ds != nil {
		go replayInto(ctx, det, *ds, *usPerStep)
	}
	go srv.StartTicker(ctx, 5*time.Second)

	httpSrv := &http.Server{Addr: *addr, Handler: srv.Handler()}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		httpSrv.Shutdown(shutCtx)
	}()

	fmt.Fprintf(os.Stderr, "hijackwatch listening on %s\n", *addr)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func apiMeta(dataPath string, ds *sim.Dataset) api.Meta {
	m := api.Meta{Dataset: dataPath, Mode: "live"}
	if ds != nil {
		m.Mode = "replay"
		m.Incidents = ds.Incidents
		m.Start = ds.Start
		m.End = ds.End
		m.Collectors = ds.Collectors
	}
	return m
}

// replayInto streams a dataset into the detector, pacing only when asked.  It
// always sleeps between batches so the HTTP API stays responsive.
func replayInto(ctx context.Context, det *detect.Detector, ds sim.Dataset, usPerStep int) {
	lastTick := ds.Start
	start := time.Now()
	for _, u := range ds.Updates {
		select {
		case <-ctx.Done():
			return
		default:
		}
		for !u.ReceivedAt.Before(lastTick.Add(5 * time.Minute)) {
			lastTick = lastTick.Add(5 * time.Minute)
			det.Tick(lastTick)
		}
		det.Process(u)
		if usPerStep > 0 {
			target := start.Add(time.Duration(u.ReceivedAt.Sub(ds.Start).Seconds() * float64(usPerStep) * float64(time.Microsecond)))
			if wait := time.Until(target); wait > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
			}
		}
	}
	det.Tick(ds.End)
	det.Flush()
}

func loadDataset(path string) (sim.Dataset, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return sim.Dataset{}, err
	}
	var ds sim.Dataset
	if err := json.Unmarshal(raw, &ds); err != nil {
		return sim.Dataset{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return ds, nil
}

func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
