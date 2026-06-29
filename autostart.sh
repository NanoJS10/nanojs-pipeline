#!/bin/bash
cd ~/nanojs_vuln_scanner
from dotenv import load_dotenv 2>/dev/null || true

python3 -c "
import requests, os
from dotenv import load_dotenv
load_dotenv()
token = os.getenv('TELEGRAM_BOT_TOKEN')
chat  = os.getenv('TELEGRAM_CHAT_ID')
requests.post(
    f'https://api.telegram.org/bot{token}/sendMessage',
    json={'chat_id': chat,
          'text': '✅ NanoJS System Online\nVM started — scanner ready.\nRun: python3 nanojs_master.py --contract 0xADDRESS --chain Ethereum --alert'},
    timeout=5
)
" 2>/dev/null

echo "NanoJS started at $(date)"

