# Encoding enable and disable usb icon to base64

import base64

with open(r"path", "rb") as ifile: # Replace 'path' with the actual path to your image file
    encoded = base64.b64encode(ifile.read()).decode('utf-8')
    print(" "* 50)
    print("Encoded image data:")
    #print(encoded)

usb_connect_icon = "Encoded image data here"  # Replace with the actual encoded string

import base64

with open(r"path", "rb") as ifile: # Replace 'path' with the actual path to your image file
    encoded = base64.b64encode(ifile.read()).decode('utf-8')
    print(" "* 50)
    print("Encoded image data:")
    #print(encoded)

usb_disconnect_icon = "Encoded image data here"  # Replace with the actual encoded string


# Convert an image to .ico format using PIL to pack with pyinstaller

from PIL import Image

img = Image.open("icon.jpg")
img.save("icon.ico")