package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// IsMonitor reports whether iface is already in monitor mode, detected via the
// kernel net device type (803 == ARPHRD_IEEE80211_MONITOR in sysfs).
func IsMonitor(iface string) bool {
	data, err := os.ReadFile(filepath.Join("/sys/class/net", iface, "type"))
	if err != nil {
		return false
	}
	t, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return false
	}
	return t == 803
}

// WirelessInterface describes a WiFi network interface discovered on the system.
type WirelessInterface struct {
	Name    string
	Driver  string
	Monitor bool
}

// exists reports whether path exists.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ListWirelessInterfaces enumerates /sys/class/net for devices that expose a
// wireless (or phy80211) directory. For each it records the driver (from the
// device's driver symlink) and whether it is already in monitor mode.
func ListWirelessInterfaces() []WirelessInterface {
	var found []WirelessInterface
	net := "/sys/class/net"
	entries, err := os.ReadDir(net)
	if err != nil {
		return found
	}
	for _, e := range entries {
		iface := e.Name()
		if !exists(filepath.Join(net, iface, "wireless")) && !exists(filepath.Join(net, iface, "phy80211")) {
			continue
		}
		driver := ""
		if link, err := os.Readlink(filepath.Join(net, iface, "device", "driver")); err == nil {
			driver = filepath.Base(link)
		}
		found = append(found, WirelessInterface{
			Name:    iface,
			Driver:  driver,
			Monitor: IsMonitor(iface),
		})
	}
	return found
}

// StartMonitor enables monitor mode on iface via airmon-ng. If the interface is
// already in monitor mode it is returned unchanged. Otherwise airmon-ng creates a
// new "<iface>mon" interface, whose name we parse out of the command output.
func StartMonitor(iface string) (string, error) {
	if IsMonitor(iface) {
		return iface, nil
	}
	out, err := exec.Command("airmon-ng", "start", iface).CombinedOutput()
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`([A-Za-z0-9]+mon)`)
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(strings.ToLower(line), "monitor") {
			if m := re.FindStringSubmatch(line); m != nil {
				return m[1], nil
			}
		}
	}
	return iface + "mon", nil
}
