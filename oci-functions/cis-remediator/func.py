import io
import json
import os
import requests
import oci
import urllib.parse
from fdk import response

def handler(ctx, data: io.BytesIO = None):
    try:
        # ---------------------------------------------------------
        # 1. INGEST & PARSE THE OCI EVENT
        # ---------------------------------------------------------
        event_payload = json.loads(data.getvalue())
        print("⚡ INCOMING OCI EVENT DETECTED ⚡")
        
        # Extract metadata from the CloudEvent
        event_type = event_payload.get("eventType", "")
        event_data = event_payload.get("data", {})
        additional_details = event_data.get("additionalDetails", {})
        
        # Smart Extraction: OCI hides these depending on the event type!
        namespace = event_data.get("namespace") or additional_details.get("namespace")
        bucket_name = event_data.get("bucketName") or additional_details.get("bucketName")
        
        # Grab the raw name, and decode any URL formatting (like %20 to spaces)
        raw_resource_name = event_data.get("resourceName")
        resource_name = urllib.parse.unquote(raw_resource_name) if raw_resource_name else None
        # ---------------------------------------------------------
        # 2. CONSULT THE AI (Llama 3.1 via Groq)
        # ---------------------------------------------------------
        print("🧠 Consulting AI Security Agent...")
        
        system_prompt = """
        You are an Autonomous Cloud Security Agent. Analyze the incoming OCI Event JSON.
        
        RULE 1: PUBLIC BUCKETS
        If the event type involves updating a bucket to be public, you MUST output the action: "SET_PRIVATE".
        
        RULE 2: PROHIBITED FILE UPLOADS
        If the event type involves creating an object (file upload), check the file extension in the resourceName. 
        Enterprise policy strictly forbids uploading executable files (.exe, .sh, .bat) and unverified archives (.zip, .tar.gz).
        If a prohibited file type is detected, you MUST output the action: "DELETE_OBJECT". 
        If the file is a safe document (.pdf, .txt, .csv, .png, .jpg), output the action: "ALLOW".
        
        Respond ONLY with a valid, raw JSON payload exactly like this: {"action": "YOUR_DECISION"}
        """

        # Prepare the request to Groq API
        groq_api_key = os.environ.get("GROQ_API_KEY")
        headers = {
            "Authorization": f"Bearer {groq_api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "llama-3.1-8b-instant",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Event Payload: {json.dumps(event_payload)}"}
            ],
            "temperature": 0.0, # Deterministic, zero hallucinations
            "response_format": {"type": "json_object"}
        }

        # Make the API call
        llm_response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=headers, json=payload)
        llm_json = llm_response.json()
        
        # Parse the AI's decision
        ai_decision = json.loads(llm_json["choices"][0]["message"]["content"])
        ai_action = ai_decision.get("action", "ALLOW")
        
        print(f"🤖 AI REMEDIATION DECISION RECEIVED: {ai_action}")

        # ---------------------------------------------------------
        # 3. ENFORCEMENT & REMEDIATION (OCI Python SDK)
        # ---------------------------------------------------------
        # Authenticate using the Function's Resource Principal badge
        signer = oci.auth.signers.get_resource_principals_signer()
        os_client = oci.object_storage.ObjectStorageClient(config={}, signer=signer)

        if ai_action == "SET_PRIVATE":
            print("⚡ EXECUTING: oci.object_storage.update_bucket()...")
            
            update_details = oci.object_storage.models.UpdateBucketDetails(
                public_access_type="NoPublicAccess"
            )
            os_client.update_bucket(
                namespace_name=namespace,
                bucket_name=bucket_name,
                update_bucket_details=update_details
            )
            print("✅ SUCCESS: The bucket has been successfully locked down!")

        elif ai_action == "DELETE_OBJECT":
            print(f"⚡ EXECUTING: oci.object_storage.delete_object() on {resource_name}...")
            
            os_client.delete_object(
                namespace_name=namespace,
                bucket_name=bucket_name,
                object_name=resource_name
            )
            print(f"✅ SUCCESS: Threat neutralized. The prohibited file '{resource_name}' has been locked down and deleted!")
            
        elif ai_action == "ALLOW":
            print(f"✅ SUCCESS: File '{resource_name}' is safe. No action taken.")

        else:
            print(f"⚠️ WARNING: Unknown AI action '{ai_action}'. No action taken.")

        return response.Response(
            ctx, response_data=json.dumps({"status": "completed", "action": ai_action}),
            headers={"Content-Type": "application/json"}
        )

    except Exception as e:
        print(f"❌ ERROR: Function failed. Details: {str(e)}")
        return response.Response(
            ctx, response_data=json.dumps({"error": str(e)}),
            headers={"Content-Type": "application/json"}
        )
