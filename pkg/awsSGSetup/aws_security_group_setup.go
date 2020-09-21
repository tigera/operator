// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var log = logf.Log.WithName("AWS_SG_Setup")
var TRACE = 7
var DEBUG = 5

// setupAWSSecurityGroups updates the master and worker security groups used in an
// OpenShift AWS setup. It sets a time that should be checked before attempting
// to do another call to setup.
func SetupAWSSecurityGroups(ctx context.Context, client client.Client) error {
	// Grab ConfigMap kube-system aws-creds
	//		get aws_access_key_id and aws_secret_access_key
	awsKeyId, awsSecret, err := getAWSCreds(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to update AWS SecurityGroups: %s", err.Error())
	}

	region, err := getAWSRegion()
	if err != nil {
		return fmt.Errorf("failed to update AWS SecurityGroups: %s", err.Error())
	}

	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(awsKeyId, awsSecret, ""),
	})
	if err != nil {
		return fmt.Errorf("failed to update AWS SecurityGroups: %s", err.Error())
	}

	ec2Cli := ec2.New(sess)

	vpcId, err := getVPCid()
	if err != nil {
		return fmt.Errorf("failed to update AWS SecurityGroups: %s", err.Error())
	}

	// Get SG ids in VPC
	// Get one with filter tag:Name with *-master-sg
	// Get one with filter tag:Name with *-worker-sg
	masterSg, err := getSGGroup(ec2Cli, vpcId, "*-master-sg")
	if err != nil {
		return fmt.Errorf("failed to get AWS SecurityGroups: %s", err.Error())
	}
	workerSg, err := getSGGroup(ec2Cli, vpcId, "*-worker-sg")
	if err != nil {
		return fmt.Errorf("failed to get AWS SecurityGroups: %s", err.Error())
	}

	// # Add rules to master and worker SG that allow incoming from master and worker for BGP, IPIP, Typha comms
	src := []ingressSrc{
		{
			srcSGId:  aws.StringValue(masterSg.GroupId),
			protocol: "tcp",
			port:     aws.Int64(179),
		},
		{
			srcSGId:  aws.StringValue(masterSg.GroupId),
			protocol: "4",
		},
		{
			srcSGId:  aws.StringValue(masterSg.GroupId),
			protocol: "tcp",
			port:     aws.Int64(5473),
		},
		{
			srcSGId:  aws.StringValue(workerSg.GroupId),
			protocol: "tcp",
			port:     aws.Int64(179),
		},
		{
			srcSGId:  aws.StringValue(workerSg.GroupId),
			protocol: "4",
		},
		{
			srcSGId:  aws.StringValue(workerSg.GroupId),
			protocol: "tcp",
			port:     aws.Int64(5473),
		},
	}
	err = allowIngressToSG(ec2Cli, masterSg, src)
	if err != nil {
		return fmt.Errorf("failed to update master AWS SecurityGroup: %s", err.Error())
	}

	err = allowIngressToSG(ec2Cli, workerSg, src)
	if err != nil {
		return fmt.Errorf("failed to update worker AWS SecurityGroup: %v", err)
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

//readMeta queries the metadata at the specified subpath on the instance.
func readMeta(subpath string) (string, error) {
	u, err := url.Parse("http://169.254.169.254/latest/meta-data")
	if err != nil {
		return "", fmt.Errorf("failed to parse metadata base url %v", err)
	}
	u.Path = path.Join(u.Path, subpath)
	resp, err := http.Get(u.String())
	if err != nil {
		return "", fmt.Errorf("failed to retrieve %s from metadata: %v", subpath, err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("failed to read response from metadata query: %v", err)
	}
	return string(body), nil
}

// getAvailabilityZone retrieves the availability zone from instance metadata.
// Get Availability zone from curl --silent http://169.254.169.254/latest/meta-data/placement/availability-zone
func getAvailabilityZone() (string, error) {
	az, err := readMeta("placement/availability-zone")
	if err != nil {
		return "", fmt.Errorf("failed to read availability zone: %v", err)
	}
	log.V(TRACE).Info("Retrieved availability zone", "availability-zone", az)
	return az, nil
}

// getAWSRegion gets the region by querying the instance metadata.
// Get AWS_DEFAULT_REGION from curl --silent http://169.254.169.254/latest/meta-data/placement/availability-zone | sed -e 's/^\(.*[0-9]\)[a-z]*/\1/')
func getAWSRegion() (string, error) {
	az, err := getAvailabilityZone()
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`^(.*[0-9])[a-z]*`)
	m := re.FindStringSubmatch(az)
	// Match should have elements <matched-string> and <submatch-string>
	if m == nil || len(m) != 2 {
		return "", fmt.Errorf("failed to parse availability zone for region")
	}
	log.V(DEBUG).Info("Parsed region", "region", m[1])
	return m[1], nil
}

// getVPCid gets the VPC id by querying the instance metadata.
// curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/ | head -n 1
// curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/$mac/vpc-id
func getVPCid() (string, error) {
	macs, err := readMeta("network/interfaces/macs")
	if err != nil {
		return "", fmt.Errorf("failed to read MAC for VPC Id: %s", err)
	}
	log.V(TRACE).Info("MACs read from metadata", "MACs", macs)
	if len(macs) < 1 {
		return "", fmt.Errorf("no MACs read for VPC Id: %s", err)
	}
	mac := strings.Fields(macs)[0]
	// curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/$mac/vpc-id
	vpcId, err := readMeta(fmt.Sprintf("network/interfaces/macs/%s/vpc-id", mac))
	if err != nil {
		return "", fmt.Errorf("failed to read VPC Id: %s", err)
	}

	log.V(TRACE).Info("VPC id read from metadata", "VPCid", vpcId)
	return vpcId, nil
}

// getSGGroup returns the first SG that is in the specified VPC and matches the nameFilter.
// nameFilter matches tag:Name.
func getSGGroup(cli *ec2.EC2, vpcId string, nameFilter string) (*ec2.SecurityGroup, error) {
	in := &ec2.DescribeSecurityGroupsInput{}
	in.SetFilters([]*ec2.Filter{
		&ec2.Filter{
			Name:   aws.String("vpc-id"),
			Values: []*string{aws.String(vpcId)},
		},
		&ec2.Filter{
			Name:   aws.String("tag:Name"),
			Values: []*string{aws.String(nameFilter)},
		},
	})
	out, err := cli.DescribeSecurityGroups(in)
	if err != nil {
		return nil, err
	}

	if len(out.SecurityGroups) == 0 {
		log.Info("No security groups found", "vpc-id", vpcId, "tag:Name", nameFilter, "SecurityGroupOutput", out)
		return nil, fmt.Errorf("No security groups found matching name %s", nameFilter)
	}

	if len(out.SecurityGroups) > 1 {
		log.Info("Multiple security groups matching filter, using the first", "tag:Name", nameFilter, "SecurityGroupOutput", out)
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
		for _, x := range toSG.IpPermissions {
			if aws.StringValue(x.IpProtocol) != s.protocol {
				continue
			}
			p := aws.Int64Value(s.port)
			if s.port != nil && (aws.Int64Value(x.FromPort) != p || aws.Int64Value(x.ToPort) != p) {
				continue
			}
			for _, y := range x.UserIdGroupPairs {
				if *y.GroupId == s.srcSGId {
					// The Security Group already allows the traffic so skip adding this
					// ingress rule.
					log.V(DEBUG).Info("Ingress rule already exists", "toSG.GroupId", sgId, "ingressSrc", s.String())
					skip = true
					break
				}
			}
			if skip {
				break
			}
		}
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
			log.Error(err, "Failed to add Ingress rule", "toSG", toSG, "ingressSrc", s.String())
			return err
		}
		log.V(DEBUG).Info("Added Ingress rule", "toSG.GroupId", sgId, "ingressSrc", s.String())
	}
	log.Info("Ingress configured for Security Group", "toSG.GroupId", sgId)
	return nil
}
