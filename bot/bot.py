#!/usr/bin/env python3
"""Telegram bot for Frida QuickJS bytecode decompilation"""

import os
import sys
import tempfile
import logging
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# Add parent dir for decompiler import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from frida_decompile import parse_file

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🔱 **Frida QuickJS Bytecode Decompiler**\n\n"
        "Send me a compiled Frida bytecode file and I'll decompile it back to JavaScript.\n\n"
        "**Supported formats:**\n"
        "• Frida QuickJS bytecode (BC\\_VERSION=2, CONFIG\\_BIGNUM)\n"
        "• Files compiled with `frida-compile` or Frida's internal QuickJS\n\n"
        "Just send the file as a document.",
        parse_mode="Markdown"
    )


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "**Commands:**\n"
        "/start — Welcome message\n"
        "/help — This message\n\n"
        "**Usage:** Send any Frida compiled bytecode file as a document.\n"
        "I'll decompile it and send back the JavaScript source.",
        parse_mode="Markdown"
    )


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    if not doc:
        return

    # Download file
    status_msg = await update.message.reply_text("⏳ Downloading...")

    try:
        file = await context.bot.get_file(doc.file_id)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            tmp_path = tmp.name
            await file.download_to_drive(tmp_path)

        # Read and validate
        with open(tmp_path, "rb") as f:
            data = f.read()

        if len(data) < 4:
            await status_msg.edit_text("❌ File too small — not valid bytecode.")
            return

        # Check magic byte (BC_VERSION=2)
        if data[0] != 0x02:
            await status_msg.edit_text(
                f"⚠️ BC\\_VERSION={data[0]}, expected 2 (Frida QuickJS).\n"
                "Attempting decompilation anyway...",
                parse_mode="Markdown"
            )

        await status_msg.edit_text("🔍 Decompiling...")

        # Decompile
        result, atoms = parse_file(data)

        # Extract the main function (Function #0) with children inlined
        js_output = []
        lines_r = result.split('\n')
        in_recon = False
        found_main = False
        for line in lines_r:
            if '── Reconstructed JS' in line and 'Function #0' in line:
                in_recon = True
                found_main = True
                continue
            elif '── Reconstructed JS' in line and found_main:
                in_recon = False
                continue
            if in_recon and ('════' in line):
                in_recon = False
                continue
            if in_recon:
                js_output.append(line.replace('    ', '', 1))

        js_code = '\n'.join(js_output).strip()

        if not js_code:
            await status_msg.edit_text("❌ Could not decompile — no valid bytecode found.")
            return

        # Send result
        if len(js_code) > 4000:
            # Send as file
            with tempfile.NamedTemporaryFile(
                mode='w', delete=False, suffix='.js',
                prefix=f"{doc.file_name or 'decompiled'}_"
            ) as out_f:
                out_f.write(f"// Decompiled from: {doc.file_name or 'unknown'}\n")
                out_f.write(f"// Atoms: {', '.join(atoms)}\n\n")
                out_f.write(js_code)
                out_path = out_f.name

            await status_msg.edit_text("✅ Decompiled! Sending as file (output too large for message).")
            await update.message.reply_document(
                document=open(out_path, 'rb'),
                filename=f"{doc.file_name or 'decompiled'}.js",
                caption="🔱 Decompiled JavaScript"
            )
            os.unlink(out_path)
        else:
            # Send as message
            await status_msg.edit_text(
                f"✅ **Decompiled from** `{doc.file_name or 'unknown'}`\n\n"
                f"```javascript\n{js_code}\n```",
                parse_mode="Markdown"
            )

        # Also send full analysis as file if requested
        if len(result) > 100:
            with tempfile.NamedTemporaryFile(
                mode='w', delete=False, suffix='.txt',
                prefix="analysis_"
            ) as anal_f:
                anal_f.write(result)
                anal_path = anal_f.name
            await update.message.reply_document(
                document=open(anal_path, 'rb'),
                filename=f"{doc.file_name or 'file'}_analysis.txt",
                caption="📋 Full analysis (atoms, disassembly, debug info)"
            )
            os.unlink(anal_path)

    except Exception as e:
        logger.exception("Decompilation error")
        await status_msg.edit_text(f"❌ Error: {str(e)}")
    finally:
        if 'tmp_path' in locals():
            try:
                os.unlink(tmp_path)
            except:
                pass


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Send me a bytecode file as a document to decompile it.\n"
        "Use /help for more info."
    )


def main():
    token = BOT_TOKEN
    if not token:
        print("Set BOT_TOKEN environment variable")
        sys.exit(1)

    app = Application.builder().token(token).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    logger.info("Bot starting...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
