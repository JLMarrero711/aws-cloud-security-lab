# Incident Report: Security Assessment of AWS Security Lab
**Date:** March 2026  
**Analyst:** Joshua Marrero  
**Classification:** Simulated — authorized testing on personal infrastructure  

## Executive Summary

An authorized port scan and access attempt was conducted against the 
security-lab AWS environment to validate defensive controls. The assessment 
revealed a minimal attack surface, effective network segmentation, and 
partial detection capability. One detection gap was identified and remediated 
during the exercise.

## Scope

- Bastion host: 3.149.214.109 (only internet-facing EC2)
- Application Load Balancer: security-lab-alb-148942645.us-east-2.elb.amazonaws.com
- Private web server: 10.0.2.x (private subnet, no public IP)
- Testing period: 4-07-2026 10:30AM 
- Tools used: nmap 7.99, curl, SSH client

## Findings

### Finding 1 — Attack surface is minimal (LOW)
**What happened:** nmap scan of the bastion host revealed only port 22 
open. All other ports filtered by security group.

**Evidence:** 
marrz@MacBook-Air-2 awskey % nmap -sV -sC -A -p- -Pn 3.149.214.109
Starting Nmap 7.99 ( https://nmap.org ) at 2026-04-07 08:13 -0400
Nmap scan report for ec2-3-149-214-109.us-east-2.compute.amazonaws.com (3.149.214.109)
Host is up (0.034s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.7 (protocol 2.0)
| ssh-hostkey: 
|   256 23:35:f4:70:8a:03:ac:9e:31:f0:f0:d2:2f:fd:01:c9 (ECDSA)
|_  256 38:4d:8d:a1:26:df:bd:c2:82:14:ba:78:af:16:bc:71 (ED25519)
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 3784.91 seconds


**Analysis:** Security group `bastion-sg` correctly restricts inbound 
access to SSH only, and further restricts SSH to a specific IP address. 
An attacker from any other IP would see all ports filtered.

**Control status:** EFFECTIVE

### Finding 2 — Private EC2 unreachable from internet (LOW — expected)
**What happened:** Direct connection attempt to private EC2 
(10.0.2.x) timed out from external network.

**Evidence:** 
ssh -o ConnectTimeout=10 ec2-user@10.0.2.x → Connection timed out

**Analysis:** 10.0.2.x is a RFC 1918 private address. The private 
subnet has no Internet Gateway route — traffic from the internet has 
no path to this address regardless of security group rules. This is 
defense in depth: two independent controls (no IGW route + restrictive 
security group) both independently prevent access.

**Control status:** EFFECTIVE

### Finding 3 — Port scan not detected by API-layer logging (MEDIUM)
**What happened:** nmap scan generated no CloudTrail events. The scan 
operated at the network layer (TCP packets) not the API layer, making 
it invisible to CloudTrail.

**Evidence:** CloudTrail search for activity during scan window returned 
no network-related events.

**Root cause:** CloudTrail only records AWS API calls. Raw network 
activity requires VPC Flow Logs and a behavioral detection tool 
(GuardDuty) to detect.

**Control status:** GAP IDENTIFIED

**Remediation taken:** Enabled VPC Flow Logs during this exercise. 
Post-remediation scan confirmed REJECT entries visible in flow logs 
for all blocked port probe attempts.

**What GuardDuty would add:** GuardDuty analyzes VPC Flow Logs 
automatically using ML-based detection. It has a specific finding type 
— Recon:EC2/Portscan — that would have triggered within minutes of 
the scan starting, generating a Medium severity finding and sending 
an SNS alert via the pipeline built in Day 4. This capability is 
unavailable on the current free-tier account.

### Finding 4 — WAF not deployed (HIGH — known gap)
**What happened:** AWS WAF could not be provisioned on free-tier 
account. ALB currently accepts all HTTP requests without 
application-layer filtering.

**Impact:** OWASP Top 10 attacks (SQL injection, XSS, path 
traversal) would not be blocked before reaching the web server.

**Remediation:** On a paid account, attach WAF Web ACL 
`security-lab-waf` with AWS-AWSManagedRulesCommonRuleSet to 
`security-lab-alb`. This provides managed rules covering CVE-listed 
vulnerabilities and OWASP Top 10 with no custom rule writing required.

**Control status:** REMEDIATION PENDING (account upgrade required)

## Controls That Worked

| Control | What it prevented |
| Security group: bastion-sg | All ports except 22 unreachable |
| Security group: bastion-sg | SSH from non-admin IPs blocked |
| Private subnet — no IGW route | Private EC2 completely unreachable from internet |
| Security group: private-sg | Port 80 only from public subnet CIDR |
| IAM least privilege | EC2 roles scoped to minimum required permissions |
| CloudTrail + CloudWatch | API-layer actions logged and alerted |
| ALB as single entry point | Web server has no public IP |

## What I Would Add Next

1. **GuardDuty** — automated behavioral threat detection analyzing 
   VPC Flow Logs, DNS logs, and CloudTrail in real time

2. **AWS WAF** — OWASP Top 10 protection at the ALB layer

3. **HTTPS on ALB** — SSL certificate via ACM, HTTP→HTTPS redirect, 
   eliminating cleartext traffic between users and the load balancer

4. **IMDSv2 enforcement** — require token-based metadata requests on 
   all EC2 instances, closing the Capital One SSRF vector

5. **Config auto-remediation** — Lambda function triggered by Config 
   rules to automatically re-enable S3 Block Public Access if it's 
   ever turned off, reducing exposure window from hours to seconds

6. **S3 Object Lock on log bucket** — WORM (write once read many) 
   storage for CloudTrail logs so an attacker who gains account access 
   cannot delete audit evidence

## Conclusion

The core network architecture is sound. The bastion pattern, private 
subnet isolation, and security group rules all performed as designed. 
The primary gaps are at the application layer (WAF) and behavioral 
detection layer (GuardDuty), both of which require account-level 
access beyond free tier. VPC Flow Logs were added during this exercise 
as a partial compensating control for the GuardDuty gap.
