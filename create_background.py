from PIL import Image
import os

# Create a white background image
width = 800
height = 400
background = Image.new('RGB', (width, height), 'white')

# Ensure the data directory exists
os.makedirs("network_security_tool/data", exist_ok=True)

# Save the background image
background.save("network_security_tool/data/dmg_background.png", "PNG") 