# DAC DEFENSE

This project is a multi-faceted script that integrates network logging, cryptographic functions, and a local LLM for analysis, all controlled through a Telegram bot.

## Features

- **Network Sniffer:** Captures network packets and logs them to a file.
- **LLM Analyzer:** Uses a local Ollama instance to analyze the network log.
- **Cryptographic Utilities:** Provides simple cryptographic functions.
- **Telegram Bot:** Controls the sniffer, triggers the LLM analysis, and uses the cryptographic functions.

## Setup

1.  **Install dependencies:**

    ```bash
    uv pip install -r requirements.txt
    ```

2.  **Set up your Telegram bot token:**

    - Open the `.env` file and replace `"YOUR_TELEGRAM_BOT_TOKEN"` with your actual Telegram bot token.

3.  **Run the bot:**

    ```bash
    python main.py
    ```

## Usage

- **/start:** Start the bot.
- **/start_sniffer:** Start the network sniffer.
- **/stop_sniffer:** Stop the network sniffer.
- **/analyze_network:** Analyze the network log with the local LLM.
- **/encrypt <text>:** Encrypt a message.
- **/decrypt <encrypted_text>:** Decrypt a message.
