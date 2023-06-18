package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/api/compute/v1"
	"os"
	"sort"
	"strings"
)

type FirewallRule struct {
	Name         string
	Network      string
	SourceRanges []string
	Tags         []string
	Disabled     bool
	isOrphaned   bool
	CreationTime string
}

type VMInstance struct {
	Name         string
	Status       string
	NetworkTags  []string
	CreationTime string
}

type VMInstanceList []VMInstance

type FirewallRuleList []FirewallRule

func (e VMInstanceList) Len() int {
	return len(e)
}

func (e VMInstanceList) Less(i, j int) bool {
	return e[i].Name < e[j].Name
}

func (e VMInstanceList) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

func (e FirewallRuleList) Len() int {
	return len(e)
}

func (e FirewallRuleList) Less(i, j int) bool {
	return e[i].Name < e[j].Name
}

func (e FirewallRuleList) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

func initClient() (*compute.Service, error) {
	ctx := context.Background()
	logrus.Debugf("initializing client...")
	computeService, err := compute.NewService(ctx)
	if err != nil {
		return nil, err
	}
	return computeService, nil
}

func isOrphaned(firewallName string, orphanedRules map[string]FirewallRule) bool {
	for _, orphaned := range orphanedRules {
		if firewallName == orphaned.Name {
			return true
		}
	}
	return false
}

func getFirewallRulesWithOrphanedRule(computeService *compute.Service, projectID string) (*[]FirewallRule, error) {
	var rules []FirewallRule
	ctx := context.Background()
	req := computeService.Firewalls.List(projectID).Filter(`direction="ingress"`)
	firewallRules, err := getFirewallRules(computeService, projectID)
	if err != nil {
		logrus.Fatalf("error getting firewall rules for host project %s, %v", projectID, err)
	}

	orphanedRules := make(map[string]FirewallRule, len(*firewallRules))
	orphanedRules, err = getOrphanedFirewallRules(computeService, projectID, firewallRules, orphanedRules)
	if err != nil {
		logrus.Warnf("Could not check project %s for orphaned rules: %s", projectID, err)
	}

	if err := req.Pages(ctx, func(page *compute.FirewallList) error {
		logrus.Debugf("listing Network Tags...")
		for _, firewall := range page.Items {
			if len(firewall.TargetTags) >= 0 {
				rules = append(rules, FirewallRule{
					Name:         firewall.Name,
					Network:      firewall.Network,
					SourceRanges: firewall.SourceRanges,
					Tags:         firewall.TargetTags,
					Disabled:     firewall.Disabled,
					isOrphaned:   isOrphaned(firewall.Name, orphanedRules),
					CreationTime: firewall.CreationTimestamp,
				})
			}
		}
		return nil
	}); err != nil {
		logrus.Errorf("error getting firewall rules: %v", err)
		return nil, err
	}
	logrus.Infof("number of TargetTags Rules: %d", len(rules))
	return &rules, nil
}

func getFirewallRules(computeService *compute.Service, projectID string) (*[]FirewallRule, error) {
	var rules []FirewallRule
	ctx := context.Background()
	req := computeService.Firewalls.List(projectID).Filter(`direction="ingress"`)
	if err := req.Pages(ctx, func(page *compute.FirewallList) error {
		for _, firewall := range page.Items {
			if len(firewall.TargetTags) >= 0 {
				rules = append(rules, FirewallRule{Name: firewall.Name, Tags: firewall.TargetTags})
			}
		}
		return nil
	}); err != nil {
		logrus.Errorf("error getting firewall rules: %v", err)
		return nil, err
	}
	return &rules, nil
}

func outputFirewallRules(firewallRulesAll *[]FirewallRule) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	header := []string{"Firewall Name", "Network", "Source Ranges", "Tags", "Disabled", "Is Orphaned", "Creation Time"}
	t.AppendHeader(table.Row{header})
	for _, rule := range *firewallRulesAll {
		t.AppendRows([]table.Row{
			{rule.Name, rule.Network, strings.Join(rule.SourceRanges, ", "), strings.Join(rule.Tags, ", "), rule.Disabled, rule.CreationTime},
		})
		t.AppendSeparator()
	}
	t.SortBy([]table.SortBy{
		{Name: "Firewall Name", Mode: table.Asc},
	})
	if viper.GetString("format") == "csv" {
		file, err := os.Create(fmt.Sprintf("firewalls_%s.csv", viper.GetString("projectID")))
		if err != nil {
			logrus.Errorf("error opening file: %v", err)
		}

		w := csv.NewWriter(file)
		_ = w.Write(header)
		sort.Sort(FirewallRuleList(*firewallRulesAll))
		for _, instance := range *firewallRulesAll {
			_ = w.Write([]string{
				instance.Name,
				instance.Network,
				strings.Join(instance.SourceRanges, ", "),
				strings.Join(instance.Tags, ", "),
				fmt.Sprintf("%t", instance.Disabled),
				fmt.Sprintf("%t", instance.isOrphaned),
				instance.CreationTime,
			})
		}

		defer w.Flush()
		return
	}
	t.Render()
}

func outputVMInstances(instances *[]VMInstance) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	header := []string{"Instance Name", "Status", "Network Tags", "Creation Time"}
	t.AppendHeader(table.Row{header})
	for _, instance := range *instances {
		t.AppendRows([]table.Row{
			{instance.Name,
				instance.Status,
				strings.Join(instance.NetworkTags, ", "),
				instance.CreationTime,
			},
		})
		t.AppendSeparator()
	}
	t.SortBy([]table.SortBy{
		{Name: "Instance Name", Mode: table.Asc},
	})
	if viper.GetString("format") == "csv" {
		file, err := os.Create(fmt.Sprintf("instances_%s.csv", viper.GetString("projectID")))
		if err != nil {
			logrus.Errorf("error opening file: %v", err)
		}

		w := csv.NewWriter(file)
		_ = w.Write(header)
		sort.Sort(VMInstanceList(*instances))
		for _, instance := range *instances {
			_ = w.Write([]string{instance.Name,
				instance.Status,
				strings.Join(instance.NetworkTags, ", "),
				instance.CreationTime,
			})
		}

		defer w.Flush()
		return
	}
	t.Render()
}
func getVMInstances(computeService *compute.Service, projectID string) (*[]VMInstance, error) {
	ctx := context.Background()
	var instances []VMInstance
	req := computeService.Instances.AggregatedList(projectID)
	if viper.GetBool("running") {
		logrus.Debugf("filtering for running instances")
		req.Filter(`status=Running`)
	}
	if err := req.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for _, instancesScopedList := range page.Items {
			for _, vmInstance := range instancesScopedList.Instances {
				logrus.Debug("getting VM Name: %s, Network Tags: %s", vmInstance.Name, vmInstance.Tags.Items)
				instances = append(instances, VMInstance{
					Name:         vmInstance.Name,
					Status:       vmInstance.Status,
					NetworkTags:  vmInstance.Tags.Items,
					CreationTime: vmInstance.CreationTimestamp,
				})
			}
		}
		return nil
	}); err != nil {
		logrus.Fatalf("error listing VM instances %s", err)
		return nil, err
	}
	logrus.Infof("number of VM Instances: %d", len(instances))
	return &instances, nil
}

func isEmptyIntersection(set1, set2 []string) bool {
	for _, val1 := range set1 {
		for _, val2 := range set2 {
			if val1 == val2 {
				return false
			}
		}
	}
	return true
}

func getOrphanedFirewallRules(computeService *compute.Service, projectID string, firewallRules *[]FirewallRule, orphans map[string]FirewallRule) (map[string]FirewallRule, error) {
	vmInstances, err := getVMInstances(computeService, projectID)
	if err != nil {
		return nil, err
	}
	for _, rule := range *firewallRules {
		if rule.Name != "nil" {
			orphans[rule.Name] = rule
		}
	}
	for _, rule := range *firewallRules {
		for _, instance := range *vmInstances {
			if len(instance.NetworkTags) > 0 {
				if !isEmptyIntersection(rule.Tags, instance.NetworkTags) {
					if _, ok := orphans[rule.Name]; ok {
						logrus.Debugf("remove active rule from orphans list: %v", rule.Name)
						delete(orphans, rule.Name)
					}
				}
			} else {
				logrus.Warnf(
					"skipping instance %v since it does not have any network tags",
					instance.Name,
				)
			}
		}
	}

	logrus.Infof("%v potential orphaned firewall rules to evalute...", len(orphans))
	for _, orphan := range orphans {
		logrus.Debugf("potential orphan rule name: %v", orphan.Name)
	}
	return orphans, nil
}
func main() {
	flag.Bool("running", false, "Filter only running VM instances")
	flag.String("projectID", "", "Project ID")
	flag.String("format", "table", "Output format (csv, table)")
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()

	if err := viper.BindPFlags(pflag.CommandLine); err != nil {
		logrus.Fatalf("error binding pflags: %s", err)
	}

	projectID := viper.GetString("projectID")

	computeService, err := initClient()
	if err != nil {
		logrus.Fatalf("error creating compute client: %s", err)
	}
	instances, err := getVMInstances(computeService, projectID)
	if err != nil {
		logrus.Fatalf("error getting VM instances: %s", err)
	}
	outputVMInstances(instances)

	firewalls, err := getFirewallRulesWithOrphanedRule(computeService, projectID)
	if err != nil {
		logrus.Fatalf("error getting firewall rules for host project %s, %v", projectID, err)
	}
	outputFirewallRules(firewalls)
}
