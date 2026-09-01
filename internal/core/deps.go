package core

import (
	"os/exec"
	"strings"
)

// DepPackages maps a package manager name to the set of system packages 8cracker
// needs on that distribution. The lists include both the cracking tools
// (aircrack-ng, hcxtools, hashcat, john) and an OpenCL runtime so the GPU backend
// works.
var DepPackages = map[string][]string{
	"pacman": {"intel-compute-runtime", "ocl-icd", "hashcat", "hcxtools", "aircrack-ng", "john"},
	"apt":    {"intel-opencl-icd", "ocl-icd-libopencl1", "hashcat", "hcxtools", "aircrack-ng", "john"},
	"dnf":    {"intel-compute-runtime", "ocl-icd", "hashcat", "hcxtools", "aircrack-ng", "john"},
	"zypper": {"intel-compute-runtime", "ocl-icd", "hashcat", "hcxtools", "aircrack-ng", "john"},
	"apk":    {"opencl-intel", "opencl", "hashcat", "hcxtools", "aircrack-ng", "john"},
}

// DetectDistro returns the package-manager name for the running distribution, or ""
// if none of the supported managers are on PATH.
func DetectDistro() string {
	candidates := []struct {
		bin  string
		name string
	}{
		{"pacman", "pacman"},
		{"apt-get", "apt"},
		{"apt", "apt"},
		{"dnf", "dnf"},
		{"zypper", "zypper"},
		{"apk", "apk"},
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c.bin); err == nil {
			return c.name
		}
	}
	return ""
}

// InstallCommand returns the full shell command to install 8cracker's dependencies
// on the given package manager. It returns "" for an unknown manager.
func InstallCommand(pm string) string {
	pkgs, ok := DepPackages[pm]
	if !ok {
		return ""
	}
	switch pm {
	case "pacman":
		return "sudo pacman -S " + strings.Join(pkgs, " ")
	case "apt":
		return "sudo apt-get update && sudo apt-get install -y " + strings.Join(pkgs, " ")
	case "dnf":
		return "sudo dnf install -y " + strings.Join(pkgs, " ")
	case "zypper":
		return "sudo zypper install -y " + strings.Join(pkgs, " ")
	case "apk":
		return "sudo apk add " + strings.Join(pkgs, " ")
	}
	return ""
}

// MissingTools returns the subset of tools that are not present on PATH.
func MissingTools(tools ...string) []string {
	var missing []string
	for _, t := range tools {
		if _, err := exec.LookPath(t); err != nil {
			missing = append(missing, t)
		}
	}
	return missing
}
