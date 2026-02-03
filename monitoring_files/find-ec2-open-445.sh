#!/usr/bin/env bash
# Finds EC2 instances with port 445 exposed to the Internet via SG rules.
# Requires: aws CLI and jq.
# Optional env vars: AWS_PROFILE, AWS_REGION

set -euo pipefail

AWS="${AWS:-aws}"

# 1) Collect all SGs that allow TCP/445 from 0.0.0.0/0 or ::/0 (or all protocols).
open_sg_ids="$(
  $AWS ec2 describe-security-groups \
    ${AWS_PROFILE:+--profile "$AWS_PROFILE"} \
    ${AWS_REGION:+--region "$AWS_REGION"} \
    --output json |
  jq -r '
    .SecurityGroups[]
    | select(
        any(.IpPermissions[]?; (
          # protocol tcp on port 445 (range or exact), OR protocol -1 (all)
          ((.IpProtocol == "tcp" and (.FromPort // 0) <= 445 and 445 <= (.ToPort // 65535))
           or .IpProtocol == "-1")
          and
          # open to the world (IPv4 or IPv6)
          (
            (any(.IpRanges[]?; .CidrIp == "0.0.0.0/0"))
            or
            (any(.Ipv6Ranges[]?; .CidrIpv6 == "::/0"))
          )
        ))
      )
    | .GroupId
  '
)"

# If no SGs match, exit quietly.
if [[ -z "$open_sg_ids" ]]; then
  exit 0
fi

# Turn list into a jq set
jq_sg_set="$(printf '%s\n' "$open_sg_ids" | jq -R . | jq -s 'map(. ) | unique')"

# 2) List running instances that reference any of those SGs; print Name + PrivateIp.
$AWS ec2 describe-instances \
  ${AWS_PROFILE:+--profile "$AWS_PROFILE"} \
  ${AWS_REGION:+--region "$AWS_REGION"} \
  --filters "Name=instance-state-name,Values=running" \
  --output json |
jq -r --argjson openSGs "$jq_sg_set" '
  .Reservations[]
  .Instances[]
  | select( any(.SecurityGroups[]?.GroupId; . as $gid | ($openSGs | index($gid))) )
  | {
      name: (
        (.Tags // []) | map(select(.Key=="Name")) | .[0].Value // "(no-Name)"
      ),
      ip: .PrivateIpAddress // "(no-PrivateIp)"
    }
  | "\(.name)\t\(.ip)"
'