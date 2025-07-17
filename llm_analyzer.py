from network_sniffer import start_sniffer, stop_sniffer
from crypto_utils import encrypt_message, decrypt_message
from scapy.all import rdpcap
import ollama
import json

def analyze_network_log():
    """Reads the network log, sends it to the LLM for analysis, and returns the response."""
    try:
        packets = rdpcap("network_log.pcap")
        packet_summaries = [packet.summary() for packet in packets]

        if not packet_summaries:
            return "Network log is empty. Nothing to analyze."

        analysis_prompt = (
            "Analyze the following network packet summaries and provide a brief overview of the activity. "
            "Highlight any suspicious or unusual traffic patterns:\n\n"
            + "\n".join(packet_summaries)
        )

        response = ollama.chat(
            model="gemma:2b",
            messages=[
                {
                    'role': 'user',
                    'content': analysis_prompt,
                },
            ]
        )
        return response['message']['content']

    except FileNotFoundError:
        return "Network log file not found. Please start the sniffer first."
    except Exception as e:
        return f"An error occurred during analysis: {e}"

async def process_user_message(user_message: str) -> str:
    """
    Processes a user's message, using the LLM to determine if a tool needs to be called
    or if a conversational response is appropriate.
    """
    system_prompt = """
    You are a helpful AI assistant for cybersecurity tasks. You can perform the following actions:
    - Start network sniffing: To start capturing network traffic.
    - Stop network sniffing: To stop capturing network traffic.
    - Analyze network log: To analyze the captured network traffic.
    - Encrypt a message: To encrypt a given text message.
    - Decrypt a message: To decrypt a given hexadecimal encrypted message.

    When a user asks you to perform one of these actions, respond with a JSON object in the format:
    {"action": "action_name", "parameters": {"param1": "value1", "param2": "value2"}}

    Possible action_names and their parameters:
    - "start_sniffer": {}
    - "stop_sniffer": {}
    - "analyze_network": {}
    - "encrypt_message": {"message": "text_to_encrypt"}
    - "decrypt_message": {"encrypted_hex": "hex_string_to_decrypt"}

    If the user's request is not a tool action, respond conversationally.
    """

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]

    try:
        response = ollama.chat(model="gemma:2b", messages=messages)
        llm_response_content = response['message']['content']

        # Attempt to parse as JSON for tool calls
        try:
            tool_call = json.loads(llm_response_content)
            action = tool_call.get("action")
            parameters = tool_call.get("parameters", {})

            if action == "start_sniffer":
                start_sniffer()
                return "Network sniffer started."
            elif action == "stop_sniffer":
                stop_sniffer()
                return "Network sniffer stopped."
            elif action == "analyze_network":
                return analyze_network_log()
            elif action == "encrypt_message":
                message = parameters.get("message")
                if message:
                    encrypted_text = encrypt_message(message)
                    return f"Encrypted message: `{encrypted_text.hex()}`"
                else:
                    return "Please provide a message to encrypt."
            elif action == "decrypt_message":
                encrypted_hex = parameters.get("encrypted_hex")
                if encrypted_hex:
                    try:
                        decrypted_text = decrypt_message(bytes.fromhex(encrypted_hex))
                        return f"Decrypted message: `{decrypted_text}`"
                    except ValueError:
                        return "Invalid hexadecimal string for decryption."
                else:
                    return "Please provide a hexadecimal message to decrypt."
            else:
                return llm_response_content # Not a recognized action, return as conversational
        except json.JSONDecodeError:
            # Not a JSON response, treat as conversational
            return llm_response_content

    except Exception as e:
        return f"An error occurred while processing your request: {e}"
