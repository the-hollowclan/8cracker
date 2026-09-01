package core

import (
	"bufio"
	"os"
	"strings"
)

// AP is a single access point discovered during a scan.
type AP struct {
	BSSID   string
	Channel string
	Power   string
	ESSID   string
}

// colIdx maps semantic fields to their column positions in airodump-ng's CSV.
type colIdx struct {
	bssid, channel, power, essid int
}

// columnIndex resolves the column positions from the CSV header line. airodump-ng
// occasionally reorders columns, and the ESSID is always the last column (and may
// itself contain commas), so we locate columns by name rather than hard offsets.
func columnIndex(header string) colIdx {
	cols := strings.Split(header, ",")
	idx := colIdx{bssid: 0, channel: 3, power: 8, essid: len(cols) - 1}
	for i, c := range cols {
		switch strings.TrimSpace(strings.ToLower(c)) {
		case "bssid":
			idx.bssid = i
		case "channel", "chan":
			idx.channel = i
		case "power", "pwr":
			idx.power = i
		case "essid", "ssid":
			idx.essid = i
		}
	}
	return idx
}

// colAt returns columns[i], or "" if i is out of range.
func colAt(cols []string, i int) string {
	if i < 0 || i >= len(cols) {
		return ""
	}
	return cols[i]
}

// ParseAPs reads airodump-ng's AP section (the block headed by "BSSID") from a
// scan CSV and returns the discovered access points. A blank line separates the AP
// block from the station block, which is where we stop.
func ParseAPs(csvPath string) []AP {
	aps := []AP{}
	f, err := os.Open(csvPath)
	if err != nil {
		return aps
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if sc.Err() != nil {
		return aps
	}

	start := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "BSSID") {
			start = i
			break
		}
	}
	if start < 0 {
		return aps
	}

	idx := columnIndex(lines[start])
	for _, line := range lines[start+1:] {
		if strings.TrimSpace(line) == "" {
			break
		}
		cols := strings.Split(line, ",")
		bssid := strings.TrimSpace(colAt(cols, idx.bssid))
		if bssid == "" {
			continue
		}
		aps = append(aps, AP{
			BSSID:   bssid,
			Channel: strings.TrimSpace(colAt(cols, idx.channel)),
			Power:   strings.TrimSpace(colAt(cols, idx.power)),
			ESSID:   strings.TrimSpace(colAt(cols, idx.essid)),
		})
	}
	return aps
}

// stationColIdx maps semantic fields to their column positions in airodump-ng's
// station (client) section.
type stationColIdx struct {
	mac, bssid int
}

func stationColumnIndex(header string) stationColIdx {
	cols := strings.Split(header, ",")
	idx := stationColIdx{mac: 0, bssid: 5}
	for i, c := range cols {
		switch strings.TrimSpace(strings.ToLower(c)) {
		case "station mac", "mac":
			idx.mac = i
		case "bssid":
			idx.bssid = i
		}
	}
	return idx
}

// ParseStations returns the MAC addresses of clients seen associated with bssid.
// When bssid is empty, all stations in the CSV are returned. This is used to
// pre-fill the deauth target and to show how many clients are present during a
// live capture (no clients => deauthentication is pointless).
func ParseStations(csvPath, bssid string) []string {
	out := []string{}
	f, err := os.Open(csvPath)
	if err != nil {
		return out
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if sc.Err() != nil {
		return out
	}

	start := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "Station MAC") {
			start = i
			break
		}
	}
	if start < 0 {
		return out
	}

	idx := stationColumnIndex(lines[start])
	for _, line := range lines[start+1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		cols := strings.Split(line, ",")
		mac := strings.TrimSpace(colAt(cols, idx.mac))
		ap := strings.TrimSpace(colAt(cols, idx.bssid))
		if mac == "" {
			continue
		}
		if bssid == "" || strings.EqualFold(ap, bssid) {
			out = append(out, mac)
		}
	}
	return out
}
