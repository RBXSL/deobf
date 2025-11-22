import discord
import os
import aiohttp
from discord.ext import commands
from dotenv import load_dotenv
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

from deobfuscators import deobf_moonsec_v3, deobf_jayfuscator, deobf_luraph, deobf_constant_dump, deobf_custom

# Load environment variables from .env file
load_dotenv()
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
PORT = int(os.getenv("PORT", 10000))

# --- Simple HTTP Server for Render Health Checks ---
class HealthCheckHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')
        else:
            self.send_response(404)
            self.end_headers()

def run_http_server():
    with HTTPServer(("", PORT), HealthCheckHandler) as httpd:
        print(f"HTTP server listening on port {PORT} for health checks...")
        httpd.serve_forever()
# ----------------------------------------------------

# Set up bot intents
intents = discord.Intents.default()
intents.message_content = True

# Create bot instance
bot = commands.Bot(command_prefix="!", intents=intents)

@bot.event
async def on_ready():
    """Event handler for when the bot has connected to Discord."""
    print(f'Logged in as {bot.user.name}')
    print('Bot is ready to deobfuscate!')

async def deobfuscate_code(source_code: str, method: str, keywords: list = None, techniques: list = None) -> str:
    """
    Dispatches to the appropriate deobfuscation function based on the selected method.
    """
    if method == "Moonsecv3":
        return deobf_moonsec_v3(source_code)
    elif method == "Jayfuscator":
        return deobf_jayfuscator(source_code)
    elif method == "Luraph":
        return deobf_luraph(source_code)
    elif method == "Constant Dump":
        return deobf_constant_dump(source_code)
    elif method == "Custom Deobf":
        return deobf_custom(source_code, keywords, techniques)
    else:
        return f"--- Unknown Deobfuscation Method: {method} ---\n\n{source_code}"

class CustomDeobfModal(discord.ui.Modal, title="Custom Deobfuscation Options"):
    keywords_input = discord.ui.TextInput(
        label="Keywords (comma-separated)",
        placeholder="e.g., player, game, print",
        required=False,
        max_length=500
    )
    techniques_input = discord.ui.TextInput(
        label="Techniques (comma-separated)",
        placeholder="Available: hex_decode, basic_string_concat",
        required=False,
        max_length=500
    )

    def __init__(self, bot_instance, channel_id):
        super().__init__()
        self.bot_instance = bot_instance
        self.channel_id = channel_id

    async def on_submit(self, interaction: discord.Interaction):
        keywords = [kw.strip() for kw in self.keywords_input.value.split(',') if kw.strip()]
        techniques = [tech.strip() for tech in self.techniques_input.value.split(',') if tech.strip()]

        # Store context for next message (URL input)
        self.bot_instance.waiting_for_url[interaction.user.id] = {
            "method": "Custom Deobf",
            "channel_id": self.channel_id,
            "keywords": keywords,
            "techniques": techniques
        }
        await interaction.response.send_message(
            "Custom Deobf selected. Please paste the URL of the obfuscated Lua/Luau code:",
            ephemeral=True
        )

# Define the view for deobfuscation options
class DeobfView(discord.ui.View):
    def __init__(self, bot_instance):
        super().__init__(timeout=180) # 3 minutes timeout
        self.bot_instance = bot_instance # Store bot instance

    async def on_timeout(self):
        # Disable all buttons when the view times out
        for item in self.children:
            item.disabled = True
        # Original message can be edited to show timeout
        # No need to edit message here, as it's handled by bot if needed.

    async def _send_url_prompt(self, interaction: discord.Interaction, method: str):
        """Helper to send a prompt for the URL."""
        await interaction.response.send_message(
            f"You selected **{method}**. Please paste the URL of the obfuscated Lua/Luau code:",
            ephemeral=True
        )
        # Store context for next message
        self.bot_instance.waiting_for_url[interaction.user.id] = {"method": method, "channel_id": interaction.channel_id}


    @discord.ui.button(label="Deobf Moonsecv3", style=discord.ButtonStyle.primary)
    async def moonsec_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self._send_url_prompt(interaction, "Moonsecv3")

    @discord.ui.button(label="Deobf Jayfuscator", style=discord.ButtonStyle.primary)
    async def jayfuscator_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self._send_url_prompt(interaction, "Jayfuscator")

    @discord.ui.button(label="Deobf Luraph", style=discord.ButtonStyle.primary)
    async def luraph_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self._send_url_prompt(interaction, "Luraph")

    @discord.ui.button(label="Constant Dump", style=discord.ButtonStyle.secondary)
    async def constant_dump_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self._send_url_prompt(interaction, "Constant Dump")

    @discord.ui.button(label="Custom Deobf", style=discord.ButtonStyle.success)
    async def custom_deobf_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Instead of asking for URL directly, show a modal for custom options
        await interaction.response.send_modal(CustomDeobfModal(self.bot_instance, interaction.channel_id))



# Create bot instance
bot = commands.Bot(command_prefix="!", intents=intents)
bot.waiting_for_url = {} # Dictionary to store user's deobfuscation choice

@bot.event
async def on_ready():
    """Event handler for when the bot has connected to Discord."""
    print(f'Logged in as {bot.user.name}')
    print('Bot is ready to deobfuscate!')

@bot.command(name="deobf", help="Starts the Lua/Luau deobfuscation process.")
async def deobf_command(ctx: commands.Context):
    """Sends a menu with deobfuscation options."""
    view = DeobfView(bot)
    await ctx.send("What kind of deobfuscation do you want to perform?", view=view)

@bot.event
async def on_message(message: discord.Message):
    if message.author == bot.user:
        return

    user_id = message.author.id
    if user_id in bot.waiting_for_url and message.channel.id == bot.waiting_for_url[user_id]["channel_id"]:
        url = message.content.strip()
        method = bot.waiting_for_url[user_id]["method"]
        keywords = bot.waiting_for_url[user_id].get("keywords")
        techniques = bot.waiting_for_url[user_id].get("techniques")
        del bot.waiting_for_url[user_id] # Clear the waiting state

        if not (url.startswith("http://") or url.startswith("https://")):
            await message.channel.send("That doesn\'t look like a valid URL. Please try again with a valid URL.", ephemeral=True)
            return

        await message.channel.send(f"Fetching code from {url} for {method} deobfuscation...")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        source_code = await resp.text()

                        deobfuscated_code = await deobfuscate_code(source_code, method, keywords=keywords, techniques=techniques)

                        if len(deobfuscated_code) > 1900: # Discord message limit is 2000 chars
                            # Ensure the directory for temporary files exists or use a more robust temp file method
                            temp_dir = "/tmp" # Or use the project\'s temp directory if available
                            temp_file_path = os.path.join(temp_dir, f"{message.author.id}_deobf_output.lua")

                            with open(temp_file_path, "w", encoding="utf-8") as f:
                                f.write(deobfuscated_code)
                            await message.channel.send(
                                f"Deobfuscated code for {method} (too long for message):",
                                file=discord.File(temp_file_path)
                            )
                            os.remove(temp_file_path)
                        else:
                            await message.channel.send(f"```lua\n{deobfuscated_code}\n```")
                    else:
                        await message.channel.send(f"Failed to fetch code from {url}. Status: {resp.status}")
        except aiohttp.ClientError as e:
            await message.channel.send(f"An error occurred while fetching the URL: {e}")
        except Exception as e:
            await message.channel.send(f"An unexpected error occurred: {e}")

    await bot.process_commands(message) # Process other commands

if __name__ == "__main__":
    if not DISCORD_TOKEN:
        print("Error: DISCORD_TOKEN not found. Please set it as an environment variable (e.g., in Render).")
    else:
        # Start the health check server in a background thread
        http_thread = threading.Thread(target=run_http_server, daemon=True)
        http_thread.start()

        bot.run(DISCORD_TOKEN)
