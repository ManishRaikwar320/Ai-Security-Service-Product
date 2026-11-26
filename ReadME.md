AI_Security/
│
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/
│   │   │   ├── scan.py
│   │   │   └── reports.py
│   │   │
│   │   ├── scanner/
│   │   │   ├── repository.py
│   │   │   ├── file_filter.py
│   │   │   ├── language_detector.py
│   │   │   ├── sast_engine.py
│   │   │   ├── bandit_engine.py
│   │   │   ├── secret_engine.py
│   │   │   ├── dependency_engine.py
│   │   │   ├── config_engine.py
│   │   │   └── normalizer.py
│   │   │
│   │   ├── analysis/
│   │   │   ├── context_extractor.py
│   │   │   ├── taint_analysis.py
│   │   │   ├── ai_validator.py
│   │   │   ├── risk_engine.py
│   │   │   └── remediation.py
│   │   │
│   │   ├── ml/
│   │   │   ├── classifier.py
│   │   │   ├── false_positive.py
│   │   │   ├── risk_model.py
│   │   │   └── training/
│   │   │
│   │   ├── workflow/
│   │   │   └── scan_graph.py
│   │   │
│   │   ├── reports/
│   │   │   ├── json_report.py
│   │   │   ├── html_report.py
│   │   │   └── sarif_report.py
│   │   │
│   │   ├── database/
│   │   └── schemas/
│   │
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
│
└── frontend/
    └── dashboard/