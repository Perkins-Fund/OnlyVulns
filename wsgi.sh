#!/bin/bash
set -e

amInVenv=$(python -c "import sys; print(hasattr(sys, 'real_prefix') or sys.prefix != getattr(sys, 'base_prefix', sys.prefix))")
if [[ "${amInVenv}" == "False" ]]; then
  if [[ -d ".venv" ]]; then
    source .venv/bin/activate
  elif [[ -d "venv" ]]; then
    source venv/bin/activate
  else
    echo "No virtual environment found"
    exit 1
  fi
fi

ip="${1:-127.0.0.1}"
port="${2:-80}"
ncore=$(nproc 2>/dev/null || echo 1)
workers=$(( (ncore / 2) + 1 ))
nohup python scheduled_tasks.py >> scheduled_tasks.log 2>&1 &
exec gunicorn \
  --bind "${ip}:${port}" \
  --workers "${workers}" \
  --timeout 400 \
  --access-logfile "access.log" \
  --error-logfile "error.log" \
  wsgi:app