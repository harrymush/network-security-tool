from PIL import Image, ImageDraw, ImageFont
import os
import shutil
import subprocess

def create_base_icon():
    print("Creating base icon...")
    # Create a 1024x1024 image with a blue background (largest required size)
    size = 1024
    image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    
    # Draw a blue circle
    draw.ellipse([0, 0, size, size], fill=(0, 120, 215, 255))
    
    # Add NST text
    try:
        # Try to use system font
        font = ImageFont.truetype("Arial", int(size * 0.4))
    except:
        # Fallback to default font
        print("Falling back to default font...")
        font = ImageFont.load_default()
    
    # Calculate text position to center it
    text = "NST"
    text_bbox = draw.textbbox((0, 0), text, font=font)
    text_width = text_bbox[2] - text_bbox[0]
    text_height = text_bbox[3] - text_bbox[1]
    x = (size - text_width) // 2
    y = (size - text_height) // 2
    
    # Draw white text
    draw.text((x, y), text, fill=(255, 255, 255, 255), font=font)
    
    return image

def create_icon():
    # Create base icon
    base_icon = create_base_icon()
    
    # Save the largest size as PNG first
    print("Saving base icon...")
    base_icon.save('icon_1024.png')
    
    print("Converting to ICNS format using sips...")
    try:
        subprocess.run(['sips', '-s', 'format', 'icns', 'icon_1024.png', '--out', 'icon.icns'], 
                      check=True, capture_output=True, text=True)
        print("Successfully created icon.icns")
    except subprocess.CalledProcessError as e:
        print(f"Failed to create ICNS file: {e.stderr}")
    finally:
        # Clean up the temporary PNG
        if os.path.exists('icon_1024.png'):
            os.remove('icon_1024.png')

if __name__ == '__main__':
    create_icon() 