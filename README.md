# 🔒 Discord Poll Bot
---
A Discord bot for creating polls with security features including rate limiting, spam detection, input sanitization, and admin controls. It allows users to create custom polls and quick yes/no polls while protecting against abuse and malicious inputs. It is solely created using python programming language.

# ⚠️DISCLAIMER
---
This Discord Poll Bot was created for educational and project purposes only. It is intended to demonstrate secure coding practices, including rate limiting, input sanitization, spam detection, and basic access control.

This bot is **NOT** designed to be **LIVE PUBLIC/PRODUCTION-GRADE PROGRAM**.

#### LIMITATIONS
- Security data (rate limits, blocked users, suspicious activity) is stored in memory and resets when the bot restarts.
- The bot does not include persistent storage by default.
- The bot has not undergone professional security auditing.
- The bot may not protect against advanced attacks, coordinated abuse, or large-scale malicious activity.

If you deploy this bot in a public or production environment, you are responsible for:
- Implementing persistent storage (database)
- Configuring proper permissions
- Monitoring usage and abuse
- Applying additional security measures

The author is not responsible for any misuse, abuse, or damages resulting from deployment of this software.

## 📌 Features of Discord Poll Bot
---
The following are the features of the poll bot.

#### 🗳️ Poll Features
- Custom polls with multiple options
- Quick yes/no polls
- Emoji-based voting
- Clean embedded poll display

### 🔐 Security Features
- Rate limiting (prevents spam)
- Input sanitization and validation
- Spam detection using content hashing
- Automatic suspicious activity detection
- User blocking system and the blocked users are stored in memory only
- Admin and Super Admin controls
 
### 👮 Admin Features
- Block / unblock users
- View security statistics
- Add / remove admins
- View admin list
- View user security information

### Additional features and highlights:
- Provides secure slash commands for creating interactive polls within Discord servers
- Implements decorator-based security layers for modular and maintainable protection
- Uses hash-based duplicate detection to prevent repeated spam poll submissions
- Includes automatic suspicious activity monitoring and auto-blocking capability
- Supports role-based privilege system with Super Admin and Admin levels


# ⚙️ Requirements
---
- Python 3.9+
- Discord Bot Token
- Discord User ID (For assigning Super Admin)
- Discord Developer Account


# 🐍 Python Libraries Used
---
External libraries:
- discord.py
- python-dotenv

Standard library modules:
- os
- re
- time
- collections
- typing
- functools
- hashlib
- secrets


## Setup
- Install all the above python library modules above, using ```pip install <python module name>```. For example, ```pip install discord.py```


- Create a `.env` file (**THIS** file must not be committed to GitHub) containing:
DISCORD_BOT_TOKEN=your_token_here
SUPER_ADMIN_ID=your_user_id_here


- Insert the required values in the '.env' file
- Run ```main_1.py``` file
- Run the commands in the discord server, in which you invited the bot to.


# Processes Involved
---

#### Two-file Structure
- ```sec_1.py```
Security layer, ```SecurityManager```, decorators, and other admin command implementations are created. All validation, rate-limiting, spam-detection takes place here.


- ```main_1.py```
Here the main bot is setup and command implementations are created, so that it build embeds, add reactions, and forward admin commands to ```SecurityCommands```. The file uses the discord.py app command tree and runs the bot.


- ```file.env```
Sensitive values, such as, ```DISCORD_BOT_TOKEN```, ```SUPER_ADMIN_ID``` of a user in discord, are stored and loaded at runtime. Without these values, functioning of the bot would not happen at all.


#### Step-by-step creation process
1. Define requirements & safety goals. 
Decide the minimum security features to demonstrate: rate limiting, input sanitization, duplicate-spam detection, and simple admin controls.


2. Implement a central ```SecurityManager```.
Implement rate limiting (timestamps per user), spam detection (time-windowed hash list), sanity checks (lengths, repetition), and blocking mechanics. Keep configuration values (rate window, thresholds) as attributes so they can be tuned.


3. Create reusable decorators.
Write ```require_security_check``` to (a) block users, (b) enforce rate limits, and (c) log usage, and ```validate_poll_input``` to sanitize and validate inputs before the command runs.


4. Build Discord interactions.
In ```main_1.py```, use ```discord.Client```/```commands.Bot``` with ```app_commands``` to register slash commands (```/poll```, ```/quickpoll```) and admin commands. The command handlers build ```discord.Embed``` objects and add emoji reactions for voting. Add permission checks and handle Forbidden and generic exceptions for nicer error messages.


5. Admin UX and safety.
Implement admin flows (block/unblock, list admins, user info, security stats) that check admin/super-admin status before performing actions and return ephemeral responses for sensitive info. ```SecurityCommands``` centralizes these.


6. Configure with environment variables.
Keep secrets out of source control: read ```DISCORD_BOT_TOKEN``` and ```SUPER_ADMIN_ID``` from an ```.env``` file and it refuses to run if the bot token is missing.


7. Document limitations and run instructions.
The README notes that state is memory-only, that the bot is demo/educational, and lists required permissions and libraries.


# 🤖 Commands
---
#### • Poll Commands
| Commands | Description |
|:-----------:|:------------:|
| ```/poll```| Create a poll with up to 20 custom options (separated by ;)|
| ```/quickpoll```| Create a Yes/No poll|


#### • Admin Commands
| Commands | Permission | Description |
|:-----------:|:------------:|:------------:|
| ```/blockuser```| Admin|Block a user from using the bot|
| ```/unblockuser```| Admin|Unblock a previously blocked user|
| ```/securitystats```| Admin|View blocked users, suspicious activity, and usage stats|
| ```/listadmins```| Admin|List all current admins|
| ```/userinfo```| Admin|Look up a user by their Discord ID|
| ```/addadmin```| Super Admin|Grant admin privileges to a user|
| ```/removeadmin```| Super Admin|Revoke admin privileges from a user|


# 🔒 Security
---
Security is handled by ```sec_1.py``` via the SecurityManager class and two decorators applied to all poll commands:
- @require_security_check —> Checks if the user is blocked and enforces rate limits
Blocked users are stored in memory only. When the bot is restarted, it resets the blocked users
- @validate_poll_input —> Sanitizes and validates all user input before processing

Input sanitization removes:
- Null bytes and non-printable control characters
- SQL injection patterns (UNION SELECT, DROP TABLE, etc.)
- JavaScript/XSS patterns (<script>, javascript:, on*= event handlers)
- Suspicious repetitive character sequences


# 🛠 Configuration
---
| Settings | Default | Description |
|:-----------:|:------------:|:------------:|
| MAX_QUESTION_LENGTH| unlimited         | Max characters for poll question|
| MAX_OPTION_LENGTH| unlimited         | Max characters per option|
| MAX_OPTIONS_COUNT| unlimited         | Max number of poll options|
| RATE_LIMIT_WINDOW| 60s       | Time window for rate limiting|
| RATE_LIMIT_MAX_REQUESTS| 5         | Max requests per window|
| SPAM_THRESHOLD| 3         | Identical requests before spam block|


# 📋 Permissions
---
The bot requires the following Discord permissions:
- Send Messages
- Embed Links
- Add Reactions
- Read Message History
 

# Learnings from creating this project
---
- Security-first design matters.
Building the bot around a dedicated SecurityManager made it easy to centralize rate limits, spam detection, blocking, and input sanitization instead of scattering checks across commands — this reduces duplication and makes future audits simpler.


- Decorators give clear separation of concerns.
Using ```@require_security_check``` and ```@validate_poll_input``` keeps the command handlers focused on Discord logic (embeds, reactions) while security and validation live in ```sec_1.py```. That pattern made the code easier to test and reason about.


- Hash-based spam detection is practical and lightweight. 
Generating a SHA-256 hash of the ```question:options``` payload and tracking recent hashes lets the bot detect repeated identical submissions quickly without persistent storage.


- Graceful error handling matters in bots.
Central ```on_error``` logging, and handling ```discord.errors.Forbidden``` around message/reaction operations, prevents silent failures in servers with restricted permissions. This improves user experience and troubleshooting.


- Memory-only state is fine for demos but not production. 

Storing blocked users, rate-limit data, and stats in memory keeps the example compact, but it means all state is lost on restart — a persistent DB is required for real deployments. The README warns about these limitations.
