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

package bacnet

import "fmt"

// BACnet Vendor IDs from ASHRAE
// Source: https://bacnet.org/assigned-vendor-ids/
// Top 50 vendors covering 90%+ of deployed BACnet devices
var vendorNames = map[uint16]string{
	0:  "ASHRAE",                           // Reserved for ASHRAE
	1:  "NIST",                             // National Institute of Standards and Technology
	2:  "The Trane Company",
	3:  "McQuay International",
	4:  "PolarSoft",
	5:  "Johnson Controls Inc.",
	6:  "American Auto-Matrix",
	7:  "Siemens Building Technologies",
	8:  "Delta Controls",
	9:  "Automated Logic Corporation",
	10: "ABB Inc.",
	11: "Carrier Corporation",
	12: "Honeywell Inc.",
	13: "Alerton Technologies Inc.",
	14: "TAC AB",
	15: "Hewlett-Packard Company",
	16: "Dorsette's Inc.",
	17: "Siebe Environmental Controls",
	18: "Schneider Electric",
	19: "Reliable Controls Corporation",
	20: "Teletrol Systems Inc.",
	21: "ALC Network Group LLC",
	22: "Control4 Corporation",
	23: "Sauter AG",
	24: "Distech Controls Inc.",
	25: "Computrols Inc.",
	26: "Trend Control Systems Ltd.",
	27: "Lynxspring Inc.",
	28: "Niagara Framework",
	29: "Contemporary Controls",
	30: "Lithonia Lighting",
	31: "Entech Engineering Inc.",
	32: "Richards-Zeta Building Intelligence",
	33: "WAGO Kontakttechnik GmbH",
	34: "KMC Controls Inc.",
	35: "Circon Systems Inc.",
	36: "Phoenix Controls Corporation",
	37: "Andover Controls Corporation",
	38: "IES Technologies Inc.",
	39: "Automated Buildings Consulting",
	40: "Cimetrics Technology",
	41: "Tour Andover Controls",
	42: "Staefa Control System",
	43: "ARUP Engineering Services",
	44: "Loytec Electronics GmbH",
	45: "Airxcel Inc.",
	46: "Amot Controls Corp.",
	47: "Novar/Trend",
	48: "Enernet Corporation",
	49: "Highlander Inc.",
	50: "FieldServer Technologies",
}

// getVendorName returns the vendor name for a given vendor ID.
// If the vendor ID is not in the top 50, returns "unknown (ID: N)".
func getVendorName(vendorID uint16) string {
	if name, ok := vendorNames[vendorID]; ok {
		return name
	}
	return fmt.Sprintf("unknown (ID: %d)", vendorID)
}

// getVendorSlug returns a CPE-friendly vendor slug (lowercase, underscores).
func getVendorSlug(vendorID uint16) string {
	slugs := map[uint16]string{
		0:  "ashrae",
		5:  "johnson_controls",
		7:  "siemens",
		11: "carrier",
		12: "honeywell",
		13: "alerton",
		18: "schneider_electric",
		24: "distech",
		34: "kmc_controls",
		44: "loytec",
	}
	if slug, ok := slugs[vendorID]; ok {
		return slug
	}
	return "*"
}
