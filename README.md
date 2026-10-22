# CloudLeak Guard

CloudLeak Guard is a Streamlit app for static security review of Terraform `.tf` files before deployment.

## Features
- Upload a ZIP containing Terraform files or scan a bundled sample.
- Custom heuristic checks for public SSH ingress, S3 encryption review, required tags, and large EC2 instance types.
- Optional Checkov findings when Checkov is installed.
- Severity summary, searchable/filterable findings, JSON/HTML reports, and report comparison.
- Automated compilation and unit tests through GitHub Actions.

## Run locally (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

If activation is blocked:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

## Run tests
```powershell
python -m py_compile app.py scanner.py report_generator.py
python -m unittest discover -s tests -v
```

## Limitations and safety
Custom checks are lightweight heuristics, not a complete Terraform/HCL parser. Complex expressions, modules, and organization-specific policies may require manual review or a dedicated policy engine. Checkov results appear only when Checkov is installed and returns parseable output. A clean scan is not proof that a configuration is secure.

Do not upload secrets, credentials, or private keys. This app performs static analysis and does not need to create AWS resources. Do not run `terraform apply` just to scan a configuration.

## Deployment
Push the repository to GitHub and deploy it through Streamlit Community Cloud with `app.py` as the entry point. Review deployment logs if installation or startup fails.
