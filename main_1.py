import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv
import os

# Import security module
from sec_1 import (
    security_manager, 
    require_security_check, 
    validate_poll_input,
    SecurityCommands
)

load_dotenv("file.env")

# Bot setup with secure intents
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

# Initialize Super Admin from environment variable
SUPER_ADMIN_ID = os.getenv('SUPER_ADMIN_ID')
if SUPER_ADMIN_ID:
    try:
        SecurityCommands.initialize_admins(int(SUPER_ADMIN_ID))
    except ValueError:
        try:
            print("⚠️ Warning: Invalid SUPER_ADMIN_ID in environment variables!")
        except UnicodeEncodeError:
            print("[!] Warning: Invalid SUPER_ADMIN_ID in environment variables!")
else:
    try:
        print("⚠️ Warning: SUPER_ADMIN_ID not set! Admin commands will not work.")
    except UnicodeEncodeError:
        print("[!] Warning: SUPER_ADMIN_ID not set! Admin commands will not work.")
    print("Add SUPER_ADMIN_ID=your_discord_user_id to your .env file")

@bot.event
async def on_ready():
    """Event triggered when bot is ready"""
    print(f"{bot.user} has connected to Discord!")
    try:
        print("🔒 Security features enabled!")
    except UnicodeEncodeError:
        print("[LOCK] Security features enabled!")
    
    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} command(s)")
    except Exception as e:
        print(f"Failed to sync commands: {e}")

@bot.event
async def on_error(event, *args, **kwargs):
    """Global error handler for security logging"""
    try:
        print(f"⚠️ Error in {event}: {args}, {kwargs}")
    except UnicodeEncodeError:
        print(f"[!] Error in {event}: {args}, {kwargs}")

@bot.tree.command(name="poll", description="Create a poll with multiple options")
@app_commands.describe(
    question="The poll question",
    options="Poll options separated by semi-colons (e.g., Option1; Option2; Option3)"
)
@require_security_check  # Rate limiting and user blocking
@validate_poll_input      # Input validation and sanitization
async def poll(interaction: discord.Interaction, question: str, options: str):
    """
    Create a secure poll with custom options
    Note: All inputs are automatically sanitized and validated
    """
    # Parse options (already validated by decorator)
    option_list = [opt.strip() for opt in options.split(';') if opt.strip()]
    
    # Discord's maximum is 20 options (already checked by validator)
    number_emojis = [
        "1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣",
        "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟",
        "🇦", "🇧", "🇨", "🇩", "🇪",
        "🇫", "🇬", "🇭", "🇮", "🇯"
    ]
    
    # Create secure embed
    embed = discord.Embed(
        title="📊 " + question,
        description="React with the corresponding emoji to vote!",
        color=discord.Color.blue()
    )
    
    # Build poll options text
    poll_text = ""
    for i, option in enumerate(option_list):
        poll_text += f"{number_emojis[i]} {option}\n"
    
    embed.add_field(name="Options", value=poll_text, inline=False)
    embed.set_footer(text=f"Poll created by {interaction.user.display_name}")
    
    # Send poll
    try:
        await interaction.response.send_message(embed=embed)
        
        # Add reactions
        message = await interaction.original_response()
        for i in range(len(option_list)):
            await message.add_reaction(number_emojis[i])
            
    except discord.errors.Forbidden:
        await interaction.response.send_message(
            "❌ I don't have permission to send messages or add reactions!",
            ephemeral=True
        )
    except Exception as e:
        print(f"Error in poll command: {e}")
        if not interaction.response.is_done():
            await interaction.response.send_message(
                "❌ An error occurred while creating the poll.",
                ephemeral=True
            )

@bot.tree.command(name="quickpoll", description="Create a yes/no poll")
@app_commands.describe(question="The poll question")
@require_security_check  # Rate limiting and user blocking
@validate_poll_input      # Input validation and sanitization
async def quickpoll(interaction: discord.Interaction, question: str):
    """
    Create a secure quick yes/no poll
    Note: All inputs are automatically sanitized and validated
    """
    # Create secure embed
    embed = discord.Embed(
        title="📊 " + question,
        description="React to vote!",
        color=discord.Color.green()
    )
    
    embed.add_field(name="Options", value="✅ Yes\n❌ No", inline=False)
    embed.set_footer(text=f"Poll created by {interaction.user.display_name}")
    
    # Send poll
    try:
        await interaction.response.send_message(embed=embed)
        
        # Add reactions
        message = await interaction.original_response()
        await message.add_reaction("✅")
        await message.add_reaction("❌")
        
    except discord.errors.Forbidden:
        await interaction.response.send_message(
            "❌ I don't have permission to send messages or add reactions!",
            ephemeral=True
        )
    except Exception as e:
        print(f"Error in quickpoll command: {e}")
        if not interaction.response.is_done():
            await interaction.response.send_message(
                "❌ An error occurred while creating the poll.",
                ephemeral=True
            )

# Admin Commands (Optional - for managing security)
@bot.tree.command(name="blockuser", description="[ADMIN] Block a user from using the bot")
@app_commands.describe(user_id="The Discord user ID to block")
async def block_user(interaction: discord.Interaction, user_id: str):
    """Admin command to block users"""
    try:
        user_id_int = int(user_id)
        await SecurityCommands.block_user_command(interaction, user_id_int)
    except ValueError:
        await interaction.response.send_message("❌ Invalid user ID!", ephemeral=True)

@bot.tree.command(name="unblockuser", description="[ADMIN] Unblock a user")
@app_commands.describe(user_id="The Discord user ID to unblock")
async def unblock_user(interaction: discord.Interaction, user_id: str):
    """Admin command to unblock users"""
    try:
        user_id_int = int(user_id)
        await SecurityCommands.unblock_user_command(interaction, user_id_int)
    except ValueError:
        await interaction.response.send_message("❌ Invalid user ID!", ephemeral=True)

@bot.tree.command(name="securitystats", description="[ADMIN] View security statistics")
async def security_stats(interaction: discord.Interaction):
    """Admin command to view security stats"""
    await SecurityCommands.security_stats(interaction)

@bot.tree.command(name="addadmin", description="[SUPER ADMIN] Add a new admin")
@app_commands.describe(user_id="The Discord user ID to make admin")
async def add_admin(interaction: discord.Interaction, user_id: str):
    """Super admin command to add new admins"""
    try:
        user_id_int = int(user_id)
        await SecurityCommands.add_admin_command(interaction, user_id_int)
    except ValueError:
        await interaction.response.send_message("❌ Invalid user ID!", ephemeral=True)

@bot.tree.command(name="removeadmin", description="[SUPER ADMIN] Remove an admin")
@app_commands.describe(user_id="The Discord user ID to remove from admins")
async def remove_admin(interaction: discord.Interaction, user_id: str):
    """Super admin command to remove admins"""
    try:
        user_id_int = int(user_id)
        await SecurityCommands.remove_admin_command(interaction, user_id_int)
    except ValueError:
        await interaction.response.send_message("❌ Invalid user ID!", ephemeral=True)

@bot.tree.command(name="listadmins", description="[ADMIN] List all admins")
async def list_admins(interaction: discord.Interaction):
    """Admin command to list all admins"""
    await SecurityCommands.list_admins_command(interaction)

@bot.tree.command(name="userinfo", description="[ADMIN] Look up user information by ID")
@app_commands.describe(user_id="The Discord user ID to look up")
async def user_info(interaction: discord.Interaction, user_id: str):
    """Admin command to look up user info"""
    try:
        user_id_int = int(user_id)
        await SecurityCommands.user_info_command(interaction, user_id_int)
    except ValueError:
        await interaction.response.send_message("❌ Invalid user ID!", ephemeral=True)

# Run the bot
if __name__ == "__main__":
    TOKEN = os.getenv('DISCORD_BOT_TOKEN')
    
    if not TOKEN:
        try:
            print("⚠️ Warning: DISCORD_BOT_TOKEN not found in environment!")
        except UnicodeEncodeError:
            print("[!] Warning: DISCORD_BOT_TOKEN not found in environment!")
        print("Please set DISCORD_BOT_TOKEN in your .env file")
        exit(1)
    else:
        try:
            print("🚀 Starting secure Discord Poll Bot...")
        except UnicodeEncodeError:
            print("[*] Starting secure Discord Poll Bot...")
        try:
            bot.run(TOKEN)
        except discord.errors.LoginFailure:
            try:
                print("❌ Invalid bot token! Please check your DISCORD_BOT_TOKEN")
            except UnicodeEncodeError:
                print("[X] Invalid bot token! Please check your DISCORD_BOT_TOKEN")
        except Exception as e:
            try:
                print(f"❌ Failed to start bot: {e}")
            except UnicodeEncodeError:
                print(f"[X] Failed to start bot: {e}")