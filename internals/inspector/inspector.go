// internals/inspector/inspector.go

package inspector

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type FirewallRuleInfo struct {
	Family string
	Table  string
	Chain  string
	Proto  string
	Port   int
	Iif    string
	Oif    string
}

type Inspector interface {
	PackageInstalled(name string) bool
	AptAutoremovePreview() ([]string, error)
	AptUpgradePreview() ([]string, error)
	AptInstallPreview(pkgs []string) ([]string, error)

	Stat(path string) (os.FileInfo, error)
	ReadRootFile(path string) (string, error)

	IsServiceEnabled(unit string) bool
	IsServiceActive(unit string) bool

	SSHIncludePresent() bool
	SSHConfigTest() error

	FirewallIncludePresent() bool
	FirewallConfigTest() error
	FirewallAllowedPorts() (map[string][]int, error)
	FirewallPolicySummary() ([]string, error)
	FirewallOtherManagers() ([]string, error)
	FirewallOnDiskPolicySummary(confPath string) ([]string, error)
	FirewallHasStatefulBaseline() (bool, error)
	FirewallHasDefaultDropInput() (bool, error)
	FirewallAllowedPortsDetailed() ([]FirewallRuleInfo, error)
}

type SSHInspector struct {
	client *ssh.Client
}

func NewSSHInspector(client *ssh.Client) *SSHInspector {
	return &SSHInspector{client: client}
}

func (i *SSHInspector) PackageInstalled(name string) bool {
	cmd := fmt.Sprintf("dpkg -s %q >/dev/null 2>&1", name)
	err := remote.RunRoot(i.client, cmd)
	return err == nil
}

func (i *SSHInspector) AptAutoremovePreview() ([]string, error) {
	cmd := "DEBIAN_FRONTEND=noninteractive apt-get -s autoremove"

	out, err := remote.RunRootWithOutput(i.client, cmd)
	if err != nil {
		return nil, err
	}

	var pkgs []string
	seen := make(map[string]struct{})

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if !strings.HasPrefix(line, "Remv ") && !strings.HasPrefix(line, "Remv\t") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		name := fields[1]
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		pkgs = append(pkgs, name)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return pkgs, nil
}

func (i *SSHInspector) Stat(path string) (os.FileInfo, error) {
	sftpClient, err := sftp.NewClient(i.client)
	if err != nil {
		return nil, err
	}
	defer sftpClient.Close()

	return sftpClient.Stat(path)
}

func (i *SSHInspector) IsServiceEnabled(unit string) bool {
	cmd := fmt.Sprintf("systemctl is-enabled %s >/dev/null 2>&1", unit)
	err := remote.RunRoot(i.client, cmd)
	return err == nil
}

func (i *SSHInspector) IsServiceActive(unit string) bool {
	cmd := fmt.Sprintf("systemctl is-active %s >/dev/null 2>&1", unit)
	err := remote.RunRoot(i.client, cmd)
	return err == nil
}

func (i *SSHInspector) SSHIncludePresent() bool {
	includeCmd := `grep -q '^Include /etc/ssh/sshd_config.d/\*.conf' /etc/ssh/sshd_config`
	err := remote.RunRoot(i.client, includeCmd)
	return err == nil
}

func (i *SSHInspector) SSHConfigTest() error {
	return remote.RunRoot(i.client, "sshd -t -f /etc/ssh/sshd_config")
}

func (i *SSHInspector) FirewallIncludePresent() bool {
	includeCmd := `grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf`
	err := remote.RunRoot(i.client, includeCmd)
	return err == nil
}

func (i *SSHInspector) FirewallConfigTest() error {
	return remote.RunRoot(i.client, "nft -c -f /etc/nftables.conf")
}

func (i *SSHInspector) AptUpgradePreview() ([]string, error) {
	cmd := "DEBIAN_FRONTEND=noninteractive apt-get -s upgrade"

	out, err := remote.RunRootWithOutput(i.client, cmd)
	if err != nil {
		return nil, err
	}

	var pkgs []string
	seen := make(map[string]struct{})

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if !strings.HasPrefix(line, "Inst ") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		name := fields[1]
		if _, ok := seen[name]; ok {
			continue
		}

		seen[name] = struct{}{}
		pkgs = append(pkgs, name)
	}

	if err := scanner.Err(); err != nil {
		logger.Debugf("AptUpgradePreview: scanner error: %v\n", err)
		return pkgs, err
	}

	return pkgs, nil
}

func (i *SSHInspector) AptInstallPreview(pkgs []string) ([]string, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	cmd := "DEBIAN_FRONTEND=noninteractive apt-get -s install " + strings.Join(pkgs, " ")

	out, err := remote.RunRootWithOutput(i.client, cmd)
	if err != nil {
		return nil, err
	}

	var result []string
	seen := make(map[string]struct{})

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if !strings.HasPrefix(line, "Inst ") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		pkg := fields[1]
		if _, ok := seen[pkg]; ok {
			continue
		}

		seen[pkg] = struct{}{}
		result = append(result, pkg)
	}

	if err := scanner.Err(); err != nil {
		logger.Debugf("AptInstallPreview: scanner error: %v\n", err)
		return result, err
	}

	return result, nil
}

func (i *SSHInspector) ReadRootFile(path string) (string, error) {
	return remote.ReadRootFile(i.client, path)
}

func (i *SSHInspector) FirewallAllowedPorts() (map[string][]int, error) {
	out, err := remote.RunRootWithOutput(i.client, "nft list ruleset")
	if err != nil {
		return nil, fmt.Errorf("nft list ruleset failed: %w", err)
	}

	re := regexp.MustCompile(`\b(tcp|udp)\s+dport\s+(\d+)\b.*\baccept\b`)

	seen := make(map[string]map[int]struct{})
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) != 3 {
				continue
			}
			proto := strings.ToLower(strings.TrimSpace(m[1]))
			portStr := m[2]

			port, err := strconv.Atoi(portStr)
			if err != nil || port <= 0 || port > 65535 {
				continue
			}

			if _, ok := seen[proto]; !ok {
				seen[proto] = make(map[int]struct{})
			}
			seen[proto][port] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning nft output failed: %w", err)
	}

	result := make(map[string][]int, len(seen))
	for proto, ports := range seen {
		for p := range ports {
			result[proto] = append(result[proto], p)
		}
	}

	return result, nil
}

func (i *SSHInspector) FirewallPolicySummary() ([]string, error) {
	out, err := remote.RunRootWithOutput(i.client, "nft list ruleset")
	if err != nil {
		return nil, fmt.Errorf("nft list ruleset failed: %w", err)
	}

	type chainInfo struct {
		table    string
		chain    string
		ctype    string
		hook     string
		priority string
		policy   string
	}

	var (
		curFamily string
		curTable  string
		curChain  string
	)
	var chains []chainInfo

	reTable := regexp.MustCompile(`\btable\s+(\S+)\s+(\S+)\s*\{`)
	reChain := regexp.MustCompile(`\bchain\s+(\S+)\s*\{`)
	reType := regexp.MustCompile(`\btype\s+(\S+)\s+hook\s+(\S+)\s+priority\s+(\S+);\s*policy\s+(\S+);`)

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()

		if m := reTable.FindStringSubmatch(line); m != nil {
			curFamily = m[1]
			_ = curFamily // currently unused but kept for completeness
			curTable = m[2]
			continue
		}
		if m := reChain.FindStringSubmatch(line); m != nil {
			curChain = m[1]
			continue
		}
		if m := reType.FindStringSubmatch(line); m != nil && curChain != "" {
			ci := chainInfo{
				table:    curTable,
				chain:    curChain,
				ctype:    m[1],
				hook:     m[2],
				priority: m[3],
				policy:   m[4],
			}
			chains = append(chains, ci)
			continue
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning nft output failed: %w", err)
	}

	var res []string
	for _, c := range chains {
		res = append(res,
			fmt.Sprintf("table=%s chain=%s type=%s hook=%s priority=%s policy=%s",
				c.table, c.chain, c.ctype, c.hook, c.priority, strings.ToLower(c.policy)),
		)
	}
	return res, nil
}

func (i *SSHInspector) FirewallOtherManagers() ([]string, error) {
	candidates := []string{"ufw", "firewalld", "iptables", "iptables-persistent"}
	var active []string

	for _, svc := range candidates {
		cmd := fmt.Sprintf("systemctl is-enabled %s >/dev/null 2>&1 || systemctl is-active %s >/dev/null 2>&1", svc, svc)
		if err := remote.RunRoot(i.client, cmd); err == nil {
			active = append(active, svc)
		}
	}

	return active, nil
}

func (i *SSHInspector) FirewallOnDiskPolicySummary(confPath string) ([]string, error) {
	if strings.TrimSpace(confPath) == "" {
		confPath = "/etc/nftables.conf"
	}

	text, err := remote.ReadRootFile(i.client, confPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s failed: %w", confPath, err)
	}

	type chainInfo struct {
		table    string
		chain    string
		ctype    string
		hook     string
		priority string
		policy   string
	}

	var (
		curFamily string
		curTable  string
		curChain  string
	)
	var chains []chainInfo

	reTable := regexp.MustCompile(`\btable\s+(\S+)\s+(\S+)\s*\{`)
	reChain := regexp.MustCompile(`\bchain\s+(\S+)\s*\{`)
	reType := regexp.MustCompile(`\btype\s+(\S+)\s+hook\s+(\S+)\s+priority\s+(\S+);\s*policy\s+(\S+);`)

	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()

		if m := reTable.FindStringSubmatch(line); m != nil {
			curFamily = m[1]
			_ = curFamily
			curTable = m[2]
			continue
		}
		if m := reChain.FindStringSubmatch(line); m != nil {
			curChain = m[1]
			continue
		}
		if m := reType.FindStringSubmatch(line); m != nil && curChain != "" {
			ci := chainInfo{
				table:    curTable,
				chain:    curChain,
				ctype:    m[1],
				hook:     m[2],
				priority: m[3],
				policy:   m[4],
			}
			chains = append(chains, ci)
			continue
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning %s failed: %w", confPath, err)
	}

	var res []string
	for _, c := range chains {
		res = append(res,
			fmt.Sprintf("table=%s chain=%s type=%s hook=%s priority=%s policy=%s",
				c.table, c.chain, c.ctype, c.hook, c.priority, strings.ToLower(c.policy)),
		)
	}
	return res, nil
}

func (i *SSHInspector) FirewallHasStatefulBaseline() (bool, error) {
	out, err := remote.RunRootWithOutput(i.client, "nft list ruleset")
	if err != nil {
		return false, fmt.Errorf("nft list ruleset failed: %w", err)
	}

	re := regexp.MustCompile(`ct\s+state\s+established,related.*\baccept\b`)
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if re.MatchString(line) {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("scanning nft output failed: %w", err)
	}

	return false, nil
}

func (i *SSHInspector) FirewallHasDefaultDropInput() (bool, error) {
	lines, err := i.FirewallPolicySummary()
	if err != nil {
		return false, err
	}

	for _, line := range lines {
		if strings.Contains(line, "hook=input") && strings.Contains(line, "policy=drop") {
			return true, nil
		}
	}

	return false, nil
}

func (i *SSHInspector) FirewallAllowedPortsDetailed() ([]FirewallRuleInfo, error) {
	out, err := remote.RunRootWithOutput(i.client, "nft list ruleset")
	if err != nil {
		return nil, fmt.Errorf("nft list ruleset failed: %w", err)
	}

	reTable := regexp.MustCompile(`\btable\s+(\S+)\s+(\S+)\s*\{`)
	reChain := regexp.MustCompile(`\bchain\s+(\S+)\s*\{`)
	reRule := regexp.MustCompile(`\b(tcp|udp)\s+dport\s+(\d+)\b.*\baccept\b`)
	reIif := regexp.MustCompile(`\biif\s+"([^"]+)"`)
	reOif := regexp.MustCompile(`\boif\s+"([^"]+)"`)

	var (
		curFamily string
		curTable  string
		curChain  string
	)
	var rules []FirewallRuleInfo

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()

		if m := reTable.FindStringSubmatch(line); m != nil {
			curFamily = m[1]
			curTable = m[2]
			continue
		}
		if m := reChain.FindStringSubmatch(line); m != nil {
			curChain = m[1]
			continue
		}

		m := reRule.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if len(m) != 3 {
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(m[1]))
		portStr := m[2]

		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}

		var iifVal, oifVal string
		if im := reIif.FindStringSubmatch(line); len(im) == 2 {
			iifVal = im[1]
		}
		if om := reOif.FindStringSubmatch(line); len(om) == 2 {
			oifVal = om[1]
		}

		rules = append(rules, FirewallRuleInfo{
			Family: curFamily,
			Table:  curTable,
			Chain:  curChain,
			Proto:  proto,
			Port:   port,
			Iif:    iifVal,
			Oif:    oifVal,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning nft output failed: %w", err)
	}

	return rules, nil
}
