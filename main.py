import os
import logging
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

from llm_analyzer import process_user_message

# Load environment variables from .env file
load_dotenv(override=True)

# Set up logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# Get the Telegram bot token from the environment variables
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send a message when the command /start is issued."""
    await update.message.reply_text("Welcome to the DAC DEFENSE Bot! I'm your AI assistant for cybersecurity tasks. How can I help you today?")

async def handle_llm_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles all text messages and routes them to the LLM for processing."""
    user_message = update.message.text
    response = await process_user_message(user_message)
    await update.message.reply_text(response)



def main():
    """Start the bot."""
    # Create the Application and pass it your bot's token.
    application = Application.builder().token(TOKEN).build()

    # on different commands - answer in Telegram
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_llm_message))

    # Run the bot until the user presses Ctrl-C
    application.run_polling()

if __name__ == "__main__":
    main()
