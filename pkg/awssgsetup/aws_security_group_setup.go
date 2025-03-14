// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package awssgsetup

import (
	"context"
	"errors"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("AWS_SG_Setup")
var TRACE = 7
var DEBUG = 5

type errorSecurityGroupNotFound struct {
	FilterKey   string
	FilterValue string
}

func (e errorSecurityGroupNotFound) Error() string {
	return fmt.Sprintf("No security groups found matching filter %s = %s", e.FilterKey, e.FilterValue)
}

// setupAWSSecurityGroups updates the master and worker security groups used in an
// OpenShift AWS setup. It sets a time that should be checked before attempting
// to do another call to setup. 'hosted' should be true if this is an OpenShift
// hosted control planes (HCP) hosted cluster.
func SetupAWSSecurityGroups(ctx context.Context, client client.Client, hosted bool) error {
	// Grab ConfigMap kube-system aws-creds
	//		get aws_access_key_id and aws_secret_access_key
	awsKeyId, awsSecret, err := getAWSCreds(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to get AWS credentials: %v", err)
	}

	metaSess, err := session.NewSession()
	if err != nil {
		return fmt.Errorf("failed to get metadata session: %v", err)
	}

	meta := ec2metadata.New(metaSess)
	if !meta.Available() {
		return fmt.Errorf("Instance metadata is not available, unable to configure Security Groups")
	}

	doc, err := meta.GetInstanceIdentityDocument()
	if err != nil {
		return fmt.Errorf("failed to get metadata document: %v", err)
	}

	region := doc.Region
	vpcId, err := getVPCid(meta)
	if err != nil {
		return fmt.Errorf("failed to update AWS SecurityGroups: %v", err)
	}

	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(awsKeyId, awsSecret, ""),
	})
	if err != nil {
		return fmt.Errorf("failed to update AWS SecurityGroups: %v", err)
	}

	ec2Cli := ec2.New(sess)
	if hosted {
		return setupHostedClusterSGs(ec2Cli, vpcId)
	}

	return setupClusterSGs(ec2Cli, vpcId)
}

func setupClusterSGs(ec2Cli *ec2.EC2, vpcId string) error {
	// Get SG ids in VPC
	// Get controlplane SG with role filter
	controlPlaneSg, err := getSecurityGroup(ec2Cli, vpcId, "tag:sigs.k8s.io/cluster-api-provider-aws/role", "controlplane")
	// Fall back to using filter tag:Name with *-master-sg if not found
	var notFound errorSecurityGroupNotFound
	if err != nil && errors.As(err, &notFound) {
		controlPlaneSg, err = getSecurityGroup(ec2Cli, vpcId, "tag:Name", "*-master-sg")
	}
	if err != nil {
		return fmt.Errorf("failed to get controlplane AWS SecurityGroup: %v", err)
	}

	// Get node SG with role filter
	nodeSg, err := getSecurityGroup(ec2Cli, vpcId, "tag:sigs.k8s.io/cluster-api-provider-aws/role", "node")
	// Fall back to using filter tag:Name with *-worker-sg if not found
	if err != nil && errors.As(err, &notFound) {
		nodeSg, err = getSecurityGroup(ec2Cli, vpcId, "tag:Name", "*-worker-sg")
	}
	if err != nil {
		return fmt.Errorf("failed to get node AWS SecurityGroup: %v", err)
	}

	err = setupSG(ec2Cli, controlPlaneSg, []*string{controlPlaneSg.GroupId, nodeSg.GroupId})
	if err != nil {
		return fmt.Errorf("failed to update controlplane AWS SecurityGroup: %v", err)
	}

	err = setupSG(ec2Cli, nodeSg, []*string{controlPlaneSg.GroupId, nodeSg.GroupId})
	if err != nil {
		return fmt.Errorf("failed to update node AWS SecurityGroup: %v", err)
	}

	return nil
}

func setupHostedClusterSGs(ec2Cli *ec2.EC2, vpcId string) error {
	// On an OpenShift HCP hosted (guest) cluster, there are no master and worker
	// security groups, there is only one sg named '*-default-sg'
	defaultSg, err := getSecurityGroup(ec2Cli, vpcId, "tag:Name", "*-default-sg")
	if err != nil {
		return fmt.Errorf("failed to get AWS SecurityGroups: %v", err)
	}
	err = setupSG(ec2Cli, defaultSg, []*string{defaultSg.GroupId})
	if err != nil {
		return fmt.Errorf("failed to update default AWS SecurityGroup: %v", err)
	}
	return nil
}

// getAWSCreds reads the aws-creds Secret that is created by an Openshift install and returns
// the id and secret.
func getAWSCreds(ctx context.Context, client client.Client) (id, secret string, err error) {
	// Grab Secret kube-system aws-creds
	//		get aws_access_key_id and aws_secret_access_key
	creds := &v1.Secret{}
	key := types.NamespacedName{Name: "aws-creds", Namespace: metav1.NamespaceSystem}

	if err := client.Get(ctx, key, creds); err != nil {
		return "", "", err
	}
	log.V(DEBUG).Info("Retrieved aws-creds")

	idByte, ok := creds.Data["aws_access_key_id"]
	if !ok {
		return "", "", fmt.Errorf("aws-creds ConfigMap does not have key aws_access_key_id")
	}
	secretByte, ok := creds.Data["aws_secret_access_key"]
	if !ok {
		return "", "", fmt.Errorf("aws-creds ConfigMap does not have key aws_secret_access_key")
	}
	return string(idByte), string(secretByte), nil
}

// getVPCid gets the VPC id by querying the instance metadata.
func getVPCid(meta *ec2metadata.EC2Metadata) (string, error) {
	mac, err := meta.GetMetadata("mac")
	if err != nil {
		return "", fmt.Errorf("failed to read MAC for VPC Id: %v", err)
	}
	log.V(TRACE).Info("MAC read from metadata", "MAC", mac)
	if len(mac) < 1 {
		return "", fmt.Errorf("no MAC read for VPC Id: %v", err)
	}
	vpcId, err := meta.GetMetadata(fmt.Sprintf("network/interfaces/macs/%s/vpc-id", mac))
	if err != nil {
		return "", fmt.Errorf("failed to read VPC Id: %v", err)
	}

	log.V(TRACE).Info("VPC id read from metadata", "VPCid", vpcId)
	return vpcId, nil
}

// getSecurityGroup returns the first SG that is in the specified VPC and matches the nameFilter.
// nameFilter matches tag:Name.
func getSecurityGroup(cli *ec2.EC2, vpcId string, filterKey string, filterValue string) (*ec2.SecurityGroup, error) {
	in := &ec2.DescribeSecurityGroupsInput{}
	in.SetFilters([]*ec2.Filter{
		{
			Name:   aws.String("vpc-id"),
			Values: []*string{aws.String(vpcId)},
		},
		{
			Name:   aws.String(filterKey),
			Values: []*string{aws.String(filterValue)},
		},
	})
	out, err := cli.DescribeSecurityGroups(in)
	if err != nil {
		return nil, err
	}

	if len(out.SecurityGroups) == 0 {
		log.Info("No security groups found", "vpc-id", vpcId, filterKey, filterValue, "SecurityGroupOutput", out)
		return nil, errorSecurityGroupNotFound{FilterKey: filterKey, FilterValue: filterValue}
	}

	if len(out.SecurityGroups) > 1 {
		log.Info("Multiple security groups matching filter, using the first", filterKey, "=", filterValue, "SecurityGroupOutput", out)
	}

	log.V(TRACE).Info("DescribeSecurityGroups", "SecurityGroupOutput", out)
	return out.SecurityGroups[0], nil
}

type ingressSrc struct {
	port     *int64
	protocol string
	srcSGId  string
}

func (is *ingressSrc) String() string {
	if is.port == nil {
		return fmt.Sprintf("SourceSGId: %s, Protocol: %s, Port: nil", is.srcSGId, is.protocol)
	}
	return fmt.Sprintf("SourceSGId: %s, Protocol: %s, Port: %d", is.srcSGId, is.protocol, *is.port)
}

// ingressSrcMatchesIpPermission checks if the s (source) is already in the
// IpPermission and returns true if so, otherwise file is returned.
func ingressSrcMatchesIpPermission(s ingressSrc, ipp *ec2.IpPermission) bool {
	if aws.StringValue(ipp.IpProtocol) != s.protocol {
		return false
	}
	// Some protocols do not use port so skip checking that if we don't have one
	// specified in s
	p := aws.Int64Value(s.port)
	if s.port != nil && (aws.Int64Value(ipp.FromPort) != p || aws.Int64Value(ipp.ToPort) != p) {
		return false
	}
	for _, y := range ipp.UserIdGroupPairs {
		if *y.GroupId == s.srcSGId {
			return true
		}
	}
	return false
}

// setupSG adds rules to SG that allow incoming from srcSGIDs for BGP, IPIP, Typha comms
func setupSG(ec2Cli *ec2.EC2, sg *ec2.SecurityGroup, srcSGIDs []*string) error {
	src := []ingressSrc{}
	for _, srcSGID := range srcSGIDs {
		src = append(src, []ingressSrc{
			{
				// BGP
				srcSGId:  aws.StringValue(srcSGID),
				protocol: "tcp",
				port:     aws.Int64(179),
			},
			{
				// IP-in-IP
				srcSGId:  aws.StringValue(srcSGID),
				protocol: "4",
			},
			{
				// Typha
				srcSGId:  aws.StringValue(srcSGID),
				protocol: "tcp",
				port:     aws.Int64(5473),
			},
		}...)
	}

	err := allowIngressToSG(ec2Cli, sg, src)
	if err != nil {
		return fmt.Errorf("failed to update AWS SecurityGroup Name: %v, ID: %v, error: %v", sg.GroupName, sg.GroupId, err)
	}
	return nil
}

// allowIngressToSG adds rules to the toSG Security Group for each element of sources.
// Before attempting to add a rule the function checks the toSG to see if the rule already exists.
// If there is an error adding the rules then an error is returned.
func allowIngressToSG(cli *ec2.EC2, toSG *ec2.SecurityGroup, sources []ingressSrc) error {
	in := &ec2.AuthorizeSecurityGroupIngressInput{}
	sgId := aws.StringValue(toSG.GroupId)
	in.SetGroupId(sgId)
	for _, s := range sources {
		log.V(DEBUG).Info("Ingress src being added", "toSG.GroupId", sgId, "ingressSrc", s.String())
		skip := false
		// Check the allowed IpPermissions to see if the s (source) is already allowed
		for _, x := range toSG.IpPermissions {
			if ingressSrcMatchesIpPermission(s, x) {
				log.V(DEBUG).Info("Ingress rule already exists", "toSG.GroupId", sgId, "ingressSrc", s.String())
				skip = true
				break
			}
		}
		// If the s (source) is already allowed then nothing more to do so continue
		// to the next loop iteration.
		if skip {
			continue
		}
		in.SetIpPermissions([]*ec2.IpPermission{&ec2.IpPermission{
			UserIdGroupPairs: []*ec2.UserIdGroupPair{{
				GroupId: aws.String(s.srcSGId),
			}},
			IpProtocol: aws.String(s.protocol),
			FromPort:   s.port,
			ToPort:     s.port,
		}})
		_, err := cli.AuthorizeSecurityGroupIngress(in)
		if err != nil {
			return fmt.Errorf("Failed to add to SG '%s' the ingress rule '%s': %v: %v", sgId, s.String(), toSG, err)
		}
		log.V(DEBUG).Info("Added Ingress rule", "toSG.GroupId", sgId, "ingressSrc", s.String())
	}
	log.Info("Ingress configured for Security Group", "toSG.GroupId", sgId)
	return nil
}
