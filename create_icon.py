from PIL import Image
import os

# Create the iconset directory if it doesn't exist
iconset_dir = "network_security_tool/data/icon.iconset"
os.makedirs(iconset_dir, exist_ok=True)

# Open the source image
img = Image.open("network_security_tool/data/app_icon.png")

# Define the required sizes for macOS icons
icon_sizes = [
    (16, 16),
    (32, 32),
    (64, 64),
    (128, 128),
    (256, 256),
    (512, 512),
    (1024, 1024)
]

# Generate icons for each size
for size in icon_sizes:
    resized = img.resize(size, Image.Resampling.LANCZOS)
    filename = f"icon_{size[0]}x{size[0]}.png"
    resized.save(os.path.join(iconset_dir, filename))
    
    # Generate @2x version if needed
    if size[0] <= 512:
        filename = f"icon_{size[0]}x{size[0]}@2x.png"
        double_size = (size[0] * 2, size[0] * 2)
        resized = img.resize(double_size, Image.Resampling.LANCZOS)
        resized.save(os.path.join(iconset_dir, filename))

print("Icon files generated successfully") 