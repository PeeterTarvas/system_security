from ppmcrypt import PPMImage

image = PPMImage.load_from_file(open('write_au.ppm', 'rb'))
print(f'image width: {image.width} px')
print(f'image height: {image.height} px')
print(f'first 16 bytes of that data: {image.data[:16].hex()}')
# make the first 1000 pixel blue
image.write_to_file(open('new_write_au.ppm', 'wb'))
