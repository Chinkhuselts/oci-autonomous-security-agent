# provider.tf
terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }
}

provider "oci" {
  tenancy_ocid     = "ocid1.tenancy.oc1..aaaaaaaalgfpb4xeo7i6r7ux2y5x3h5saglvp5oolzcgurdh6hhcxv6hjjna"
  user_ocid        = "ocid1.user.oc1..aaaaaaaaqwrjqcj5tcoxdkw27e7k72ptgofhdhu24u673pleis2qorvgxjja"
  fingerprint      = "35:fb:57:99:c5:2c:60:37:b7:c5:3b:c0:78:16:62:ee"
  private_key_path = "/home/husel/.oci/oci_api_key_legacy.pem"
  region           = "eu-stockholm-1" # or whatever your region is
}
