package oseol

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

//go:embed data/lifecycle.json
var lifecycleJSON []byte

// The snapshot is refreshed by a weekly PR, never by a scan-time network call.
// End dates are the final supported calendar day; nil means no known cutoff.
type lifecycleProduct struct {
	Source    string             `json:"source"`
	VendorURL string             `json:"vendor_url"`
	Support   string             `json:"support"`
	Releases  map[string]*string `json:"releases"`
}

type lifecycleSnapshot struct {
	SchemaVersion int                         `json:"schema_version"`
	RefreshedAt   string                      `json:"refreshed_at"`
	Products      map[string]lifecycleProduct `json:"products"`
}

var lifecycleData = mustLoadLifecycle()

func mustLoadLifecycle() lifecycleSnapshot {
	snapshot, err := parseLifecycle(lifecycleJSON)
	if err != nil {
		panic(fmt.Sprintf("invalid embedded OS lifecycle snapshot: %v", err))
	}
	return snapshot
}

func parseLifecycle(data []byte) (lifecycleSnapshot, error) {
	var snapshot lifecycleSnapshot
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return snapshot, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return snapshot, fmt.Errorf("unexpected trailing lifecycle data")
	}
	if snapshot.SchemaVersion != 2 || len(snapshot.Products) == 0 {
		return snapshot, fmt.Errorf("unsupported or empty lifecycle snapshot")
	}
	if _, err := time.Parse(time.RFC3339, snapshot.RefreshedAt); err != nil {
		return snapshot, fmt.Errorf("invalid refresh timestamp: %w", err)
	}
	for name, product := range snapshot.Products {
		if name == "" || product.Support == "" || len(product.Releases) == 0 ||
			!strings.HasPrefix(product.Source, "https://") || !strings.HasPrefix(product.VendorURL, "https://") {
			return snapshot, fmt.Errorf("invalid lifecycle product %q", name)
		}
		for version, end := range product.Releases {
			if version == "" {
				return snapshot, fmt.Errorf("empty release in %s", name)
			}
			if end != nil {
				if _, err := time.Parse(time.DateOnly, *end); err != nil {
					return snapshot, fmt.Errorf("invalid cutoff for %s/%s: %w", name, version, err)
				}
			}
		}
	}
	return snapshot, nil
}

func lifecycleEnd(product, version string) (time.Time, string) {
	entry, ok := lifecycleData.Products[product]
	if !ok {
		return time.Time{}, ""
	}
	endDate, ok := entry.Releases[version]
	if !ok || endDate == nil {
		return time.Time{}, ""
	}
	end, _ := time.Parse(time.DateOnly, *endDate) // Validated on load.
	return end.AddDate(0, 0, 1), entry.VendorURL + " (data: " + entry.Source + ")"
}
