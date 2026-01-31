#!/usr/bin/env python3
with open("/Users/m/Zen/Code/ChatFilter/src/chatfilter/web/routers/sessions.py", "r") as f:
    content = f.read()

# Test pattern
pattern = """    except FloodWaitError as e:
        if "client" in dir() and client.is_connected():
            await client.disconnect()
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _(
                    "Too many requests. Please wait {seconds} seconds before trying again."
                ).format(seconds=e.seconds),
            },
        )
    except (OSError, ConnectionError, ConnectionRefusedError) as e:"""

print(f"Pattern found: {pattern in content}")
print(f"Pattern occurrences: {content.count(pattern)}")

# Check what we have
import re
flood_matches = re.findall(r"except FloodWaitError.*?\n.*?except \(OSError", content, re.DOTALL)
print(f"\nFound {len(flood_matches)} FloodWaitError blocks")
if flood_matches:
    print("First match preview (first 200 chars):")
    print(flood_matches[0][:200])
