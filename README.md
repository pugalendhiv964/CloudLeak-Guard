# CloudLeak Guard

A local-first prototype that scans Terraform source for selected security, governance, and policy-based cost-review signals before deployment.

## What it does
- Checks for a text pattern suggesting SSH port 22 is open to `0.0.0.0/0`.
- Flags S3 bucket resource blocks where encryption is not visibly configured in that block.
- Checks selected AWS resources for `Environment` and `Owner` tags.
- Flags selected large instance-type strings for human review (not a price estimate).
- Optionally runs Checkov and combines its failed checks.
- Exports JSON and HTML reports, and compares two JSON reports.

## Limitations
This is an educational MVP, not a complete Terraform/HCL parser or security scanner. Custom checks use conservative text patterns and may miss cases or produce false positives. Verify results against the actual Terraform configuration and cloud provider behavior. No cloud resources are created and no credentials are needed. Cost findings are policy signals, not actual pricing calculations or guaranteed savings.

## Windows quick start (VS Code terminal)
Open this folder in VS Code. In PowerShell:
```powershell
py -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
streamlit run app.py
```
Open the local URL printed by Streamlit (normally `http://localhost:8501`).

If PowerShell blocks activation, you can use Command Prompt:
```cmd
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
streamlit run app.py
```

## Run tests
```powershell
python -m unittest discover -s tests -v
```

## Git
```powershell
git init
git add .
git commit -m "Build CloudLeak Guard Terraform scanner"
```
Create a GitHub repository separately when you are ready to publish. Never commit credentials, Terraform state files, or secret values.
