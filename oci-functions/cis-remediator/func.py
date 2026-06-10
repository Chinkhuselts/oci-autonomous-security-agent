import io
import json
import os
import requests
import oci
import urllib.parse
import hashlib
from fdk import response

def handler(ctx, data: io.BytesIO):
    try:
        print("⚡ INCOMING OCI EVENT DETECTED ⚡", flush=True)
        
        # 1. INGEST & PARSE THE OCI EVENT
        event_body = json.loads(data.getvalue())
        event_data = event_body.get("data", {})
        additional_details = event_data.get("additionalDetails", {})
        
        # Smart Extraction
        namespace = event_data.get("namespace") or additional_details.get("namespace")
        bucket_name = event_data.get("bucketName") or additional_details.get("bucketName")
        
        if not namespace or not bucket_name:
            print("❌ ERROR: Missing critical event data (namespace or bucket).", flush=True)
            return response.Response(ctx, response_data=json.dumps({"status": "error"}), headers={"Content-Type": "application/json"})

        # --- EVENT ROUTING & CIS COMPLIANCE (ENGINE 1) ---
        event_type = event_body.get("eventType", "")
        
        # ROUTE A: Infrastructure Compliance (Bucket Changes)
        if "updatebucket" in event_type.lower() or "createbucket" in event_type.lower():
            print(f"🛡️ INFRASTRUCTURE CHECK: Evaluating bucket '{bucket_name}' for CIS compliance...", flush=True)
            signer = oci.auth.signers.get_resource_principals_signer()
            object_storage_client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
            
            try:
                # Fetch the current, live status of the bucket
                bucket_info = object_storage_client.get_bucket(namespace, bucket_name).data
                
                # Check if someone made it public
                if bucket_info.public_access_type != 'NoPublicAccess':
                    print(f"🚨 CIS VIOLATION DETECTED: Bucket '{bucket_name}' is PUBLIC. Remediating...", flush=True)
                    
                    # Overwrite the settings back to Private
                    update_details = oci.object_storage.models.UpdateBucketDetails(
                        public_access_type='NoPublicAccess'
                    )
                    object_storage_client.update_bucket(namespace, bucket_name, update_details)
                    print(f"✅ REMEDIATION SUCCESS: Bucket '{bucket_name}' locked down to PRIVATE.", flush=True)
                else:
                    print(f"ℹ️ COMPLIANT: Bucket '{bucket_name}' remains private.", flush=True)
                    
            except Exception as e:
                print(f"❌ ERROR: Failed to check/update bucket compliance. Details: {e}", flush=True)
                
            # Exit the function early so it doesn't run the malware engine
            return response.Response(
                ctx, response_data=json.dumps({"status": "success", "module": "compliance_engine"}), 
                headers={"Content-Type": "application/json"}
            )
        # -------------------------------------------------

        # ROUTE B: AI Malware Defense (File Uploads)
        
        # Decode the filename to handle spaces
        raw_resource_name = event_data.get("resourceName")
        resource_name = urllib.parse.unquote(raw_resource_name) if raw_resource_name else None
        
        if not resource_name:
            print("ℹ️ IGNORING: Event did not contain a resourceName. Exiting.", flush=True)
            return response.Response(ctx, response_data=json.dumps({"status": "ignored"}), headers={"Content-Type": "application/json"})

        # Extract metadata
        file_size = additional_details.get("size", "Unknown")
        mime_type = additional_details.get("contentType", "Unknown")

        print(f"🔍 Inspecting uploaded file: {resource_name}", flush=True)

        # 2. INITIALIZE OCI SDK & ACTIVE SHA-256 HASHING
        signer = oci.auth.signers.get_resource_principals_signer()
        object_storage_client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)

        true_file_hash = None
        try:
            print(f"🧮 Calculating true SHA-256 hash for {resource_name}...", flush=True)
            get_obj_response = object_storage_client.get_object(namespace, bucket_name, resource_name)
            
            # Stream the file in safe 1MB chunks
            sha256_hash = hashlib.sha256()
            for chunk in get_obj_response.data.raw.stream(1024 * 1024, decode_content=False):
                sha256_hash.update(chunk)
            
            true_file_hash = sha256_hash.hexdigest()
            print(f"✅ Cryptographic Hash generated: {true_file_hash}", flush=True)
        except Exception as e:
            print(f"⚠️ Could not compute hash. Ensure Dynamic Group has read permissions. Error: {e}", flush=True)

        # 3. ENRICHMENT: VIRUSTOTAL
        vt_api_key = os.environ.get("VT_API_KEY")
        vt_score = "Unscanned"
        
        if vt_api_key and true_file_hash:
            vt_headers = {"x-apikey": vt_api_key}
            vt_url = f"https://www.virustotal.com/api/v3/files/{true_file_hash}"
            
            try:
                vt_response = requests.get(vt_url, headers=vt_headers, timeout=5)
                if vt_response.status_code == 200:
                    stats = vt_response.json()["data"]["attributes"]["last_analysis_stats"]
                    malicious_count = stats.get("malicious", 0)
                    total_scanners = sum(stats.values())
                    vt_score = f"{malicious_count}/{total_scanners} engines flagged this as malicious."
                elif vt_response.status_code == 404:
                    vt_score = "File hash not found (Normal for new, custom, or internal business files)."
            except Exception as e:
                vt_score = f"VirusTotal query failed: {str(e)}"

        # 4. ENRICHMENT: NVD CVE DATABASE
        cve_findings = "None"
        if resource_name and any(char.isdigit() for char in resource_name):
            try:
                nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={resource_name}&resultsPerPage=3"
                nvd_response = requests.get(nvd_url, timeout=5)
                if nvd_response.status_code == 200:
                    vulnerabilities = nvd_response.json().get("vulnerabilities", [])
                    if vulnerabilities:
                        cve_list = [vuln["cve"]["id"] for vuln in vulnerabilities]
                        cve_findings = f"Found known vulnerabilities: {', '.join(cve_list)}"
            except Exception as e:
                cve_findings = "CVE lookup timed out or failed."

        # 5. AI RISK EVALUATION (GROQ / LLAMA 3.1)
        print("🧠 Consulting AI Security Agent...", flush=True)
        groq_api_key = os.environ.get("GROQ_API_KEY")
        
        if not groq_api_key:
             raise ValueError("GROQ_API_KEY environment variable is missing.")

        system_prompt = """You are an elite autonomous Cloud Security Analyst. 
Evaluate the file upload for malware, evasion, and social engineering indicators.
You are provided with external Threat Intelligence (VirusTotal and CVEs).

CRITICAL RULES:
1. Do NOT classify a file as malicious solely because it is unknown to VirusTotal. Internal business files are naturally unknown.
2. ABSOLUTE ANCHOR: Any file with an executable or script extension (.exe, .sh, .js, .vbs, .bat, .cmd, .ps1, .msi) MUST be scored at least 50 (MEDIUM / QUARANTINE), even if the filename sounds completely harmless (e.g., 'docs.exe', 'update.exe').
3. A file should reach HIGH or CRITICAL risk (70+ / DELETE) if there are positive VirusTotal hits, double extensions (e.g., invoice.pdf.exe), or MIME mismatches.
4. Unknown files with benign extensions (.pdf, .txt, .jpg, .docx) and no suspicious traits MUST be scored low risk (ALLOW).
5. If you lack concrete evidence but find the file mildly suspicious, use QUARANTINE.

You MUST respond in valid JSON format exactly like this:
{
  "risk_score": <int 0-100>,
  "confidence": <int 0-100 (how certain are you of this assessment)>,
  "severity": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "reason": "<short explanation of your analysis>",
  "action": "<ALLOW|QUARANTINE|DELETE>"
}"""

        user_prompt = f"""
        File Name: {resource_name}
        File Size: {file_size} bytes
        MIME Type: {mime_type}
        VirusTotal Report: {vt_score}
        CVE Database Findings: {cve_findings}
        """

        headers = {
            "Authorization": f"Bearer {groq_api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "llama-3.1-8b-instant",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1
        }
        
        groq_response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=payload)
        groq_response.raise_for_status()
        ai_output = groq_response.json()["choices"][0]["message"]["content"]
        
        # Parse Llama 3.1 JSON
        security_decision = json.loads(ai_output)
        risk_score = security_decision.get("risk_score", 0)
        confidence = security_decision.get("confidence", 100)
        action = security_decision.get("action", "ALLOW")
        reason = security_decision.get("reason", "No reason provided")

        print(f"📊 AI ASSESSMENT | Score: {risk_score}/100 | Confidence: {confidence}% | Action: {action} | Reason: {reason}", flush=True)

        # 6. REMEDIATION WITH CONFIDENCE FAIL-SAFE
        
        # Fail-safe: If the AI says DELETE but is unsure, downgrade to QUARANTINE
        if risk_score >= 70 and confidence < 60:
            print(f"⚠️ SAFETY OVERRIDE: High risk but low confidence ({confidence}%). Downgrading DELETE to QUARANTINE.", flush=True)
            action = "QUARANTINE"

        # Execute actions
        if action == "DELETE" or (risk_score >= 70 and confidence >= 60):
            print(f"⚡ EXECUTING: Hard Delete on {resource_name}...", flush=True)
            object_storage_client.delete_object(namespace, bucket_name, resource_name)
            print(f"✅ SUCCESS: High-risk threat '{resource_name}' deleted.", flush=True)

        elif action == "QUARANTINE" or risk_score >= 30:
            print(f"⚠️ EXECUTING: Quarantine on {resource_name}...", flush=True)
            quarantine_name = f"QUARANTINED_{resource_name}.locked"
            rename_details = oci.object_storage.models.RenameObjectDetails(
                source_name=resource_name,
                new_name=quarantine_name
            )
            object_storage_client.rename_object(namespace, bucket_name, rename_details)
            print(f"✅ SUCCESS: Suspicious file '{resource_name}' locked in quarantine.", flush=True)

        else:
            print(f"🛡️ SAFE: File '{resource_name}' allowed.", flush=True)

        return response.Response(
            ctx, response_data=json.dumps({"status": "success", "action_taken": action}),
            headers={"Content-Type": "application/json"}
        )

    except Exception as e:
        print(f"❌ ERROR: Function failed. Details: {str(e)}", flush=True)
        return response.Response(
            ctx, response_data=json.dumps({"status": "error", "message": str(e)}),
            headers={"Content-Type": "application/json"}
        )
