package core

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleCSV = `BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # data, #/s, Last throughput, PROBE, ESSID
AA:BB:CC:DD:EE:01, 2024-01-01 00:00:00, 2024-01-01 00:00:01, 6, 54, WPA2, CCMP, PSK, -50, 10, 0, 0, 0, , HomeNet
AA:BB:CC:DD:EE:02, 2024-01-01 00:00:00, 2024-01-01 00:00:01, 1, 54, WPA2, CCMP, PSK, -70, 5, 0, 0, 0, , 
AA:BB:CC:DD:EE:03, 2024-01-01 00:00:00, 2024-01-01 00:00:01, 11, 54, WPA2, CCMP, PSK, -30, 20, 0, 0, 0, , HiddenOne

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
`

func TestParseAPs(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "scan-01.csv")
	if err := os.WriteFile(csv, []byte(sampleCSV), 0o644); err != nil {
		t.Fatal(err)
	}
	aps := ParseAPs(csv)
	if len(aps) != 3 {
		t.Fatalf("expected 3 APs, got %d: %+v", len(aps), aps)
	}
	want := []struct {
		bssid, ch, pwr, essid string
	}{
		{"AA:BB:CC:DD:EE:01", "6", "-50", "HomeNet"},
		{"AA:BB:CC:DD:EE:02", "1", "-70", ""},
		{"AA:BB:CC:DD:EE:03", "11", "-30", "HiddenOne"},
	}
	for i, w := range want {
		if aps[i].BSSID != w.bssid || aps[i].Channel != w.ch || aps[i].Power != w.pwr || aps[i].ESSID != w.essid {
			t.Errorf("AP %d = %+v, want bssid=%s ch=%s pwr=%s essid=%s", i, aps[i], w.bssid, w.ch, w.pwr, w.essid)
		}
	}
}

func TestParseAPsNoProbeColumn(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "scan-01.csv")
	data := `BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # data, #/s, Last throughput, ESSID
AA:BB:CC:DD:EE:01, 2024-01-01 00:00:00, 2024-01-01 00:00:01, 6, 54, WPA2, CCMP, PSK, -50, 10, 0, 0, 0, HomeNet
AA:BB:CC:DD:EE:02, 2024-01-01 00:00:00, 2024-01-01 00:00:01, 11, 54, WPA2, CCMP, PSK, -30, 7, 0, 0, 0, 

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
`
	if err := os.WriteFile(csv, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	aps := ParseAPs(csv)
	if len(aps) != 2 {
		t.Fatalf("expected 2 APs, got %d: %+v", len(aps), aps)
	}
	if aps[0].ESSID != "HomeNet" || aps[0].Power != "-50" || aps[0].Channel != "6" {
		t.Errorf("AP0 = %+v", aps[0])
	}
	if aps[1].ESSID != "" || aps[1].Power != "-30" {
		t.Errorf("AP1 = %+v", aps[1])
	}
}

func TestParseStations(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "scan-01.csv")
	data := `BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # data, #/s, Last throughput, ESSID
AA:BB:CC:DD:EE:01, 2024-01-01 00:00:00, 2024-01-01 00:00:01, 6, 54, WPA2, CCMP, PSK, -50, 10, 0, 0, 0, HomeNet

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2024-01-01 00:00:00, 2024-01-01 00:00:01, -40, 5, AA:BB:CC:DD:EE:01,
99:88:77:66:55:44, 2024-01-01 00:00:00, 2024-01-01 00:00:01, -60, 2, AA:BB:CC:DD:EE:02,
`
	if err := os.WriteFile(csv, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	got := ParseStations(csv, "AA:BB:CC:DD:EE:01")
	want := "11:22:33:44:55:66"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("expected [%s], got %v", want, got)
	}
	if all := ParseStations(csv, ""); len(all) != 2 {
		t.Fatalf("expected 2 stations for empty bssid, got %v", all)
	}
}
