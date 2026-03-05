import re
import time
from collections import defaultdict
from typing import Optional, List, Tuple
import discord
from functools import wraps
import hashlib
import secrets

class SecurityManager:
    """Manages security features for the Discord bot"""
    
    def __init__(self):
        # Rate limiting: user_id -> list of timestamps
        self.rate_limit_data = defaultdict(list)
        
        # Command usage tracking
        self.command_usage = defaultdict(int)
        
        # Blocked users (can be extended to use database)
        self.blocked_users = set()
        
        # Suspicious activity tracking
        self.suspicious_activity = defaultdict(int)
        
        # Maximum lengths
        self.MAX_QUESTION_LENGTH = float('inf')
        self.MAX_OPTION_LENGTH = float('inf')
        self.MAX_OPTIONS_COUNT = float('inf')
        
        # Rate limits (requests per time window)
        self.RATE_LIMIT_WINDOW = 60  # seconds
        self.RATE_LIMIT_MAX_REQUESTS = 5  # max requests per window
        
        # Spam detection
        self.SPAM_THRESHOLD = 3  # identical requests in short time
        self.spam_detection = defaultdict(list)

    def check_rate_limit(self, user_id: int) -> Tuple[bool, Optional[str]]:
        """
        Check if user has exceeded rate limit
        Returns: (is_allowed, error_message)
        """
        current_time = time.time()
        user_requests = self.rate_limit_data[user_id]
        
        # Remove old timestamps outside the window
        user_requests = [
            timestamp for timestamp in user_requests 
            if current_time - timestamp < self.RATE_LIMIT_WINDOW
        ]
        self.rate_limit_data[user_id] = user_requests
        
        # Check if limit exceeded
        if len(user_requests) >= self.RATE_LIMIT_MAX_REQUESTS:
            wait_time = int(self.RATE_LIMIT_WINDOW - (current_time - user_requests[0]))
            return False, f"⚠️ Rate limit exceeded! Please wait {wait_time} seconds."
        
        # Add current request
        self.rate_limit_data[user_id].append(current_time)
        return True, None

    def is_user_blocked(self, user_id: int) -> bool:
        """Check if user is blocked"""
        return user_id in self.blocked_users

    def block_user(self, user_id: int):
        """Block a user from using the bot"""
        self.blocked_users.add(user_id)

    def unblock_user(self, user_id: int):
        """Unblock a user"""
        self.blocked_users.discard(user_id)

    def sanitize_input(self, text: str) -> str:
        """
        Sanitize user input to prevent injection attacks
        Removes potentially dangerous characters and patterns
        """
        if not text:
            return ""
        
        # Remove null bytes
        text = text.replace('\x00', '')
        
        # Remove control characters except newlines and tabs
        text = ''.join(char for char in text if char.isprintable() or char in '\n\t')
        
        # Remove multiple consecutive special characters that might indicate attack
        text = re.sub(r'[<>]{3,}', '', text)
        text = re.sub(r'[{}]{3,}', '', text)
        text = re.sub(r'[\[\]]{3,}', '', text)
        
        # Remove SQL-like patterns (even though Discord bots don't use SQL directly)
        sql_patterns = [
            r'(\bUNION\b.*\bSELECT\b)',
            r'(\bDROP\b.*\bTABLE\b)',
            r'(\bINSERT\b.*\bINTO\b)',
            r'(\bDELETE\b.*\bFROM\b)',
            r'(\bUPDATE\b.*\bSET\b)',
            r'(--\s*$)',
            r'(/\*.*\*/)',
        ]
        for pattern in sql_patterns:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE)
        
        # Remove JavaScript-like patterns
        js_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
        ]
        for pattern in js_patterns:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE)
        
        return text.strip()

    def validate_question(self, question: str) -> Tuple[bool, Optional[str]]:
        """
        Validate poll question
        Returns: (is_valid, error_message)
        """
        if not question or not question.strip():
            return False, "❌ Question cannot be empty!"
        
        if len(question) > self.MAX_QUESTION_LENGTH:
            return False, f"❌ Question too long! Maximum {self.MAX_QUESTION_LENGTH} characters."
        
        # Check for excessive repetition (spam indicator)
        if self._has_excessive_repetition(question):
            return False, "❌ Question contains suspicious repetitive patterns!"
        
        return True, None

    def validate_options(self, options: str) -> Tuple[bool, Optional[str], List[str]]:
        """
        Validate and parse poll options
        Returns: (is_valid, error_message, parsed_options)
        """
        if not options or not options.strip():
            return False, "❌ Options cannot be empty!", []
        
        # Parse options
        option_list = [opt.strip() for opt in options.split(';') if opt.strip()]
        
        # Check number of options
        if len(option_list) > self.MAX_OPTIONS_COUNT:
            return False, f"❌ Too many options! Maximum {self.MAX_OPTIONS_COUNT} allowed.", []
        
        # Validate each option
        for option in option_list:
            if len(option) > self.MAX_OPTION_LENGTH:
                return False, f"❌ Option too long! Maximum {self.MAX_OPTION_LENGTH} characters per option.", []
            
            if self._has_excessive_repetition(option):
                return False, "❌ Options contain suspicious repetitive patterns!", []
        
        # Check for duplicate options
        if len(option_list) != len(set(option_list)):
            return False, "❌ Duplicate options detected!", []
        
        return True, None, option_list

    def _has_excessive_repetition(self, text: str) -> bool:
        """Check if text has excessive character or word repetition"""
        # Check for same character repeated many times
        if re.search(r'(.)\1{10,}', text):
            return True
        
        # Check for same word repeated many times
        words = text.split()
        if len(words) > 5:
            word_counts = {}
            for word in words:
                word_counts[word] = word_counts.get(word, 0) + 1
                if word_counts[word] > len(words) * 0.5:  # More than 50% same word
                    return True
        
        return False

    def detect_spam(self, user_id: int, content_hash: str) -> Tuple[bool, Optional[str]]:
        """
        Detect if user is spamming identical content
        Returns: (is_spam, error_message)
        """
        current_time = time.time()
        user_spam = self.spam_detection[user_id]
        
        # Remove old entries (older than 30 seconds)
        user_spam = [
            (timestamp, hash_val) for timestamp, hash_val in user_spam 
            if current_time - timestamp < 30
        ]
        self.spam_detection[user_id] = user_spam
        
        # Count identical content
        identical_count = sum(1 for _, hash_val in user_spam if hash_val == content_hash)
        
        if identical_count >= self.SPAM_THRESHOLD:
            self.report_suspicious_activity(user_id)
            return True, "⚠️ Spam detected! You're sending identical requests too quickly."
        
        # Add current content
        self.spam_detection[user_id].append((current_time, content_hash))
        return False, None

    def report_suspicious_activity(self, user_id: int):
        """Track suspicious activity"""
        self.suspicious_activity[user_id] += 1
        
        # Auto-block after multiple suspicious activities
        if self.suspicious_activity[user_id] >= 5:
            self.block_user(user_id)
            try:
                print(f"⚠️ User {user_id} auto-blocked due to suspicious activity")
            except UnicodeEncodeError:
                print(f"[!] User {user_id} auto-blocked due to suspicious activity")

    def get_content_hash(self, question: str, options: str) -> str:
        """Generate hash of content for spam detection"""
        content = f"{question}:{options}"
        return hashlib.sha256(content.encode()).hexdigest()

    def log_command_usage(self, user_id: int, command_name: str):
        """Log command usage for analytics"""
        self.command_usage[f"{user_id}:{command_name}"] += 1


# Global security manager instance
security_manager = SecurityManager()


def require_security_check(func):
    """
    Decorator to add security checks to Discord commands
    """
    @wraps(func)
    async def wrapper(interaction: discord.Interaction, *args, **kwargs):
        user_id = interaction.user.id
        
        # Check if user is blocked
        if security_manager.is_user_blocked(user_id):
            await interaction.response.send_message(
                "🚫 You have been blocked from using this bot due to policy violations.",
                ephemeral=True
            )
            return
        
        # Check rate limit
        is_allowed, error_message = security_manager.check_rate_limit(user_id)
        if not is_allowed:
            await interaction.response.send_message(error_message, ephemeral=True)
            return
        
        # Log command usage
        security_manager.log_command_usage(user_id, func.__name__)
        
        # Call the original function
        return await func(interaction, *args, **kwargs)
    
    return wrapper


def validate_poll_input(func):
    """
    Decorator to validate poll inputs
    """
    @wraps(func)
    async def wrapper(interaction: discord.Interaction, question: str, options: str = None):
        user_id = interaction.user.id
        
        # Sanitize inputs
        question = security_manager.sanitize_input(question)
        if options:
            options = security_manager.sanitize_input(options)
        
        # Validate question
        is_valid, error_message = security_manager.validate_question(question)
        if not is_valid:
            await interaction.response.send_message(error_message, ephemeral=True)
            return
        
        # Validate options if provided
        if options:
            is_valid, error_message, option_list = security_manager.validate_options(options)
            if not is_valid:
                await interaction.response.send_message(error_message, ephemeral=True)
                return
            
            # Spam detection
            content_hash = security_manager.get_content_hash(question, options)
            is_spam, spam_message = security_manager.detect_spam(user_id, content_hash)
            if is_spam:
                await interaction.response.send_message(spam_message, ephemeral=True)
                return
        else:
            # For quickpoll
            content_hash = security_manager.get_content_hash(question, "yes/no")
            is_spam, spam_message = security_manager.detect_spam(user_id, content_hash)
            if is_spam:
                await interaction.response.send_message(spam_message, ephemeral=True)
                return
        
        # Call the original function with sanitized inputs
        if options:
            return await func(interaction, question, options)
        else:
            return await func(interaction, question)
    
    return wrapper


# Admin commands for security management
class SecurityCommands:
    """Admin commands for managing security"""
    
    # Store admin IDs (can be extended to use database)
    ADMIN_IDS = set()  # Will be populated from environment variable
    SUPER_ADMIN_ID = None  # The first/main admin who can manage other admins
    
    @classmethod
    def initialize_admins(cls, super_admin_id: int):
        """Initialize the super admin (only called once at startup)"""
        cls.SUPER_ADMIN_ID = super_admin_id
        cls.ADMIN_IDS.add(super_admin_id)
        try:
            print(f"🔑 Super Admin initialized: {super_admin_id}")
        except UnicodeEncodeError:
            print(f"[KEY] Super Admin initialized: {super_admin_id}")
    
    @classmethod
    def is_admin(cls, user: discord.User) -> bool:
        """Check if user is admin"""
        return user.id in cls.ADMIN_IDS
    
    @classmethod
    def is_super_admin(cls, user: discord.User) -> bool:
        """Check if user is the super admin"""
        return user.id == cls.SUPER_ADMIN_ID
    
    @staticmethod
    async def add_admin_command(interaction: discord.Interaction, user_id: int):
        """Super admin command to add a new admin"""
        if not SecurityCommands.is_super_admin(interaction.user):
            await interaction.response.send_message(
                "❌ Only the Super Admin can add new admins!",
                ephemeral=True
            )
            return
        
        if user_id in SecurityCommands.ADMIN_IDS:
            # Try to fetch user info
            try:
                user = await interaction.client.fetch_user(user_id)
                user_display = user.display_name
            except Exception:
                user_display = "Unknown User"
            
            await interaction.response.send_message(
                f"⚠️ {user_display} is already an admin!",
                ephemeral=True
            )
            return
        
        # Try to fetch user info
        try:
            user = await interaction.client.fetch_user(user_id)
            user_display = user.display_name
        except discord.NotFound:
            await interaction.response.send_message(
                f"❌ User not found! Please check the user ID.",
                ephemeral=True
            )
            return
        except Exception:
            user_display = "Unknown User"
        
        SecurityCommands.ADMIN_IDS.add(user_id)
        await interaction.response.send_message(
            f"✅ {user_display} has been added as an admin!\n"
            f"Total admins: {len(SecurityCommands.ADMIN_IDS)}",
            ephemeral=True
        )
        try:
            print(f"➕ New admin added: {user_display} by {interaction.user.display_name}")
        except UnicodeEncodeError:
            print(f"[+] New admin added: {user_display} by {interaction.user.display_name}")
    
    @staticmethod
    async def remove_admin_command(interaction: discord.Interaction, user_id: int):
        """Super admin command to remove an admin"""
        if not SecurityCommands.is_super_admin(interaction.user):
            await interaction.response.send_message(
                "❌ Only the Super Admin can remove admins!",
                ephemeral=True
            )
            return
        
        if user_id == SecurityCommands.SUPER_ADMIN_ID:
            await interaction.response.send_message(
                "❌ Cannot remove the Super Admin!",
                ephemeral=True
            )
            return
        
        if user_id not in SecurityCommands.ADMIN_IDS:
            # Try to fetch user info
            try:
                user = await interaction.client.fetch_user(user_id)
                user_display = user.display_name
            except Exception:
                user_display = "Unknown User"
            
            await interaction.response.send_message(
                f"⚠️ {user_display} is not an admin!",
                ephemeral=True
            )
            return
        
        # Try to fetch user info
        try:
            user = await interaction.client.fetch_user(user_id)
            user_display = user.display_name
        except Exception:
            user_display = "Unknown User"
        
        SecurityCommands.ADMIN_IDS.discard(user_id)
        await interaction.response.send_message(
            f"✅ {user_display} has been removed as an admin!\n"
            f"Total admins: {len(SecurityCommands.ADMIN_IDS)}",
            ephemeral=True
        )
        try:
            print(f"➖ Admin removed: {user_display} by {interaction.user.display_name}")
        except UnicodeEncodeError:
            print(f"[-] Admin removed: {user_display} by {interaction.user.display_name}")
    
    @staticmethod
    async def list_admins_command(interaction: discord.Interaction):
        """Admin command to list all admins"""
        if not SecurityCommands.is_admin(interaction.user):
            await interaction.response.send_message("❌ Admin only!", ephemeral=True)
            return
        
        if not SecurityCommands.ADMIN_IDS:
            await interaction.response.send_message(
                "📋 No admins configured yet!",
                ephemeral=True
            )
            return
        
        # Fetch user info for each admin
        admin_list = []
        for uid in SecurityCommands.ADMIN_IDS:
            try:
                user = await interaction.client.fetch_user(uid)
                is_super = " 👑 (Super Admin)" if uid == SecurityCommands.SUPER_ADMIN_ID else ""
                admin_list.append(f"• **{user.display_name}**{is_super}")
            except discord.NotFound:
                is_super = " 👑 (Super Admin)" if uid == SecurityCommands.SUPER_ADMIN_ID else ""
                admin_list.append(f"• Unknown User{is_super}")
            except Exception:
                is_super = " 👑 (Super Admin)" if uid == SecurityCommands.SUPER_ADMIN_ID else ""
                admin_list.append(f"• Unknown User{is_super}")
        
        embed = discord.Embed(
            title="👥 Admin List",
            description="\n".join(admin_list),
            color=discord.Color.gold()
        )
        embed.set_footer(text=f"Total: {len(SecurityCommands.ADMIN_IDS)} admin(s)")
        
        await interaction.response.send_message(embed=embed, ephemeral=True)
    
    @staticmethod
    async def user_info_command(interaction: discord.Interaction, user_id: int):
        """Admin command to look up user information"""
        if not SecurityCommands.is_admin(interaction.user):
            await interaction.response.send_message("❌ Admin only!", ephemeral=True)
            return
        
        try:
            # Fetch user from Discord
            user = await interaction.client.fetch_user(user_id)
            
            # Check if user is blocked
            is_blocked = user_id in security_manager.blocked_users
            
            # Check suspicious activity
            suspicious_count = security_manager.suspicious_activity.get(user_id, 0)
            
            # Check if user is admin
            is_admin = user_id in SecurityCommands.ADMIN_IDS
            is_super = user_id == SecurityCommands.SUPER_ADMIN_ID
            
            # Create embed with user info
            embed = discord.Embed(
                title="👤 User Information",
                color=discord.Color.blue()
            )
            
            # Add user avatar
            if user.avatar:
                embed.set_thumbnail(url=user.avatar.url)
            
            # Basic info
            embed.add_field(
                name="Username",
                value=f"**{user.display_name}**",
                inline=True
            )
            embed.add_field(
                name="User ID",
                value=f"`{user_id}`",
                inline=True
            )
            embed.add_field(
                name="Account Created",
                value=f"<t:{int(user.created_at.timestamp())}:R>",
                inline=True
            )
            
            # Status indicators
            status_icons = []
            if is_super:
                status_icons.append("👑 Super Admin")
            elif is_admin:
                status_icons.append("🛡️ Admin")
            if is_blocked:
                status_icons.append("🚫 Blocked")
            if suspicious_count > 0:
                status_icons.append(f"⚠️ {suspicious_count} Suspicious Activities")
            
            if status_icons:
                embed.add_field(
                    name="Status",
                    value="\n".join(status_icons),
                    inline=False
                )
            else:
                embed.add_field(
                    name="Status",
                    value="✅ Regular User",
                    inline=False
                )
            
            # Bot check
            embed.add_field(
                name="Bot Account",
                value="🤖 Yes" if user.bot else "👤 No",
                inline=True
            )
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
            
        except discord.NotFound:
            await interaction.response.send_message(
                "❌ User not found! Please check the user ID.",
                ephemeral=True
            )
        except Exception as e:
            await interaction.response.send_message(
                f"❌ An error occurred while fetching user info: {str(e)}",
                ephemeral=True
            )
    
    @staticmethod
    async def block_user_command(interaction: discord.Interaction, user_id: int):
        """Admin command to block a user"""
        if not SecurityCommands.is_admin(interaction.user):
            await interaction.response.send_message("❌ Admin only!", ephemeral=True)
            return
        
        security_manager.block_user(user_id)
        await interaction.response.send_message(f"✅ User {user_id} has been blocked.", ephemeral=True)
    
    @staticmethod
    async def unblock_user_command(interaction: discord.Interaction, user_id: int):
        """Admin command to unblock a user"""
        if not SecurityCommands.is_admin(interaction.user):
            await interaction.response.send_message("❌ Admin only!", ephemeral=True)
            return
        
        security_manager.unblock_user(user_id)
        await interaction.response.send_message(f"✅ User {user_id} has been unblocked.", ephemeral=True)
    
    @staticmethod
    async def security_stats(interaction: discord.Interaction):
        """Admin command to view security statistics"""
        if not SecurityCommands.is_admin(interaction.user):
            await interaction.response.send_message("❌ Admin only!", ephemeral=True)
            return
        
        # Fetch blocked users info
        blocked_users_info = []
        for user_id in security_manager.blocked_users:
            try:
                user = await interaction.client.fetch_user(user_id)
                blocked_users_info.append(f"• {user.display_name}")
            except Exception:
                blocked_users_info.append(f"• Unknown User")
        
        blocked_list = "\n".join(blocked_users_info) if blocked_users_info else "None"
        
        # Fetch suspicious users info
        suspicious_users_info = []
        for user_id, count in security_manager.suspicious_activity.items():
            try:
                user = await interaction.client.fetch_user(user_id)
                suspicious_users_info.append(f"• {user.display_name}: {count} incidents")
            except Exception:
                suspicious_users_info.append(f"• Unknown User: {count} incidents")
        
        suspicious_list = "\n".join(suspicious_users_info) if suspicious_users_info else "None"
        
        embed = discord.Embed(
            title="📊 Security Statistics",
            color=discord.Color.red()
        )
        embed.add_field(
            name="🚫 Blocked Users",
            value=blocked_list,
            inline=False
        )
        embed.add_field(
            name="⚠️ Suspicious Activity",
            value=suspicious_list,
            inline=False
        )
        embed.add_field(
            name="📈 Total Command Uses",
            value=str(sum(security_manager.command_usage.values())),
            inline=False
        )
        
        await interaction.response.send_message(embed=embed, ephemeral=True)