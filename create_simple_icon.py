from PIL import Image, ImageDraw, ImageFont
import os

# Create a new image with a size of 1024x1024 pixels
size = 1024
image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
draw = ImageDraw.Draw(image)

# Draw a blue circle background
circle_radius = size // 2 - 10
circle_center = (size // 2, size // 2)
draw.ellipse(
    [
        circle_center[0] - circle_radius,
        circle_center[1] - circle_radius,
        circle_center[0] + circle_radius,
        circle_center[1] + circle_radius
    ],
    fill=(30, 144, 255)  # Dodger Blue
)

# Add text
text = "NST"
font_size = size // 3
try:
    font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", font_size)
except:
    font = ImageFont.load_default()

# Get text size
text_bbox = draw.textbbox((0, 0), text, font=font)
text_width = text_bbox[2] - text_bbox[0]
text_height = text_bbox[3] - text_bbox[1]

# Calculate text position to center it
text_x = (size - text_width) // 2
text_y = (size - text_height) // 2

# Draw text in white
draw.text((text_x, text_y), text, fill=(255, 255, 255), font=font)

# Ensure the data directory exists
os.makedirs("network_security_tool/data", exist_ok=True)

# Save the image
image.save("network_security_tool/data/app_icon.png", "PNG")
print("Icon created successfully") 