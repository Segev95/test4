# main.tf

## Policy Document for CKV2_AWS_40 Violation: Overly permissive Action element
# This policy grants full administrative privileges ("Action": "*")
data "aws_iam_policy_document" "ckv2_aws_40_doc" {
  statement {
    effect = "Allow"
    # CKV2_AWS_40 is violated here (Action: *)
    actions = [
      "*" 
    ]
    resources = [
      "arn:aws:s3:::my-insecure-bucket/*"
    ]
  }
}

## Policy Document for CKV2_AWS_43 Violation: Overly permissive Principal element
# This policy uses a wild card Principal ("Principal": "*")
data "aws_iam_policy_document" "ckv2_aws_43_doc" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject"
    ]
    resources = [
      "arn:aws:s3:::my-other-insecure-bucket/*"
    ]
    
    # CKV2_AWS_43 is violated here (Principal: *)
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

# --- Checkov VIOLATION Triggers ---

## 1. CKV2_AWS_40 VIOLATION: Resource creating a policy with Action: "*"
resource "aws_iam_policy" "insecure_policy_40" {
  name        = "insecure-policy-ckv2-aws-40"
  description = "Triggers CKV2_AWS_40: Policy with wildcard Action"
  policy      = data.aws_iam_policy_document.ckv2_aws_40_doc.json
}


## 2. CKV2_AWS_43 VIOLATION: Resource creating a policy with Principal: "*"
# Note: This is an Identity Policy (aws_iam_policy). Using "*" for Principal on an identity policy is a severe misconfiguration.
resource "aws_iam_policy" "insecure_policy_43" {
  name        = "insecure-policy-ckv2-aws-43"
  description = "Triggers CKV2_AWS_43: Policy with wildcard Principal on an identity policy"
  policy      = data.aws_iam_policy_document.ckv2_aws_43_doc.json
}
