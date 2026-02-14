# Vestigia Integrations

## SIEM
Set `VESTIGIA_SIEM_TARGETS` to an array of SIEM targets:
```json
[
  {"type": "splunk", "url": "https://splunk.example.com", "token": "HEC_TOKEN"}
]
```

## Status Page
Use `/status` for a lightweight status page JSON payload or run:
```bash
streamlit run web_ui/status_page.py
```

## Backup & Restore
```bash
./backup.sh
python ops/backup_verify.py
./ops/restore_from_backup.sh backups/latest.tar.gz /tmp/vestigia_restore
```
