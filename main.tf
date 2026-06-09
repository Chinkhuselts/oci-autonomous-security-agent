# main.tf

# 1. Create the Isolated Sandbox Compartment
resource "oci_identity_compartment" "thesis_sandbox" {
    compartment_id = var.tenancy_ocid
    description    = "Isolated sandbox for Autonomous Cloud Governance thesis"
    name           = "thesis-sandbox"
}
# 2. Get your specific Object Storage Namespace (Required by OCI)
data "oci_objectstorage_namespace" "user_namespace" {
    # Fetch using the root tenancy to avoid propagation race conditions
    compartment_id = var.tenancy_ocid
}

# 3. Create the Intentionally Vulnerable Bucket
resource "oci_objectstorage_bucket" "vulnerable_bucket" {
    compartment_id = oci_identity_compartment.thesis_sandbox.id
    name           = "cis-benchmark-target-bucket"
    namespace      = data.oci_objectstorage_namespace.user_namespace.namespace
    
    # THE DELIBERATE VULNERABILITY
    # "ObjectRead" allows public anonymous access to download objects.
    access_type    = "ObjectRead" 
}

# 4. Create a Dynamic Group for our Serverless Functions
resource "oci_identity_dynamic_group" "thesis_functions_group" {
    # IAM resources MUST be created in the root tenancy
    compartment_id = var.tenancy_ocid 
    name           = "thesis-functions-dynamic-group"
    description    = "Dynamic group for autonomous governance functions"
    
    # This rule says: "Any OCI Function living inside the thesis_sandbox compartment is part of this group"
    matching_rule  = "ALL {resource.type = 'fnfunc', resource.compartment.id = '${oci_identity_compartment.thesis_sandbox.id}'}"
}

# 5. Create the IAM Policy (Least Privilege Enforcement)
resource "oci_identity_policy" "thesis_functions_policy" {
    # Policies MUST also be created in the root tenancy
    compartment_id = var.tenancy_ocid 
    name           = "thesis-functions-policy"
    description    = "Allows functions to remediate object storage in the sandbox"
    
    # Grant the dynamic group permission to manage object storage ONLY in the sandbox
    statements = [
        "Allow dynamic-group ${oci_identity_dynamic_group.thesis_functions_group.name} to manage object-family in compartment ${oci_identity_compartment.thesis_sandbox.name}"
    ]
}
