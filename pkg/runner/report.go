// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runner

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

type outputFormat string

const (
	JSON    outputFormat = "JSON"
	CSV     outputFormat = "CSV"
	DEFAULT outputFormat = "DEFAULT"
)

// FormatService formats a single service result as a string based on output format.
func FormatService(service plugins.Service, format outputFormat) string {
	switch format {
	case JSON:
		data, err := json.Marshal(service)
		if err != nil {
			return ""
		}
		return string(data)
	default:
		if len(service.Host) > 0 {
			if service.TLS {
				return fmt.Sprintf("%s://%s:%d (%s) (tls)", strings.ToLower(service.Protocol), service.Host, service.Port, service.IP)
			}
			return fmt.Sprintf("%s://%s:%d (%s)", strings.ToLower(service.Protocol), service.Host, service.Port, service.IP)
		}
		if service.TLS {
			return fmt.Sprintf("%s://%s:%d (tls)", strings.ToLower(service.Protocol), service.IP, service.Port)
		}
		return fmt.Sprintf("%s://%s:%d", strings.ToLower(service.Protocol), service.IP, service.Port)
	}
}

// ResultPrinter handles thread-safe real-time printing of results to stdout.
type ResultPrinter struct {
	mu     sync.Mutex
	format outputFormat
}

// NewResultPrinter creates a printer for the configured output format.
func NewResultPrinter() *ResultPrinter {
	format := DEFAULT
	if config.outputJSON {
		format = JSON
	}
	return &ResultPrinter{format: format}
}

// Print outputs a single service result to stdout. Thread-safe.
func (p *ResultPrinter) Print(service plugins.Service) {
	line := FormatService(service, p.format)
	if line == "" {
		return
	}
	p.mu.Lock()
	fmt.Fprintln(os.Stdout, line)
	p.mu.Unlock()
}

// Report writes all results to file. If no output file is configured, it is a no-op
// (results were already printed to stdout in real-time).
func Report(services []plugins.Service) error {
	if len(config.outputFile) == 0 {
		// Already printed to stdout in real-time
		return nil
	}

	writeFile, err := os.Create(config.outputFile)
	if err != nil {
		return err
	}
	defer writeFile.Close()

	var format = DEFAULT
	if config.outputJSON {
		format = JSON
	} else if config.outputCSV {
		format = CSV
	}

	if format == CSV {
		csvWriter := csv.NewWriter(writeFile)
		if config.showErrors {
			if err := csvWriter.Write([]string{"Host", "Port", "Service", "Metadata", "Error"}); err != nil {
				return err
			}
		} else {
			if err := csvWriter.Write([]string{"Host", "Port", "Service", "Data"}); err != nil {
				return err
			}
		}
		for _, service := range services {
			portStr := strconv.FormatInt(int64(service.Port), 10)
			if err := csvWriter.Write([]string{service.Host, service.IP, portStr, service.Protocol,
				strconv.FormatBool(service.TLS), string(service.Raw)}); err != nil {
				return err
			}
		}
		csvWriter.Flush()
		return csvWriter.Error()
	}

	for _, service := range services {
		line := FormatService(service, format)
		if line != "" {
			fmt.Fprintln(writeFile, line)
		}
	}
	return nil
}
