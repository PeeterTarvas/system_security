from ppmcrypt import PPMImage

key = b'sixteenbytekey1!'

image = PPMImage.load_from_file(open('au.ppm', 'rb'))
image.encrypt(key, 'cbc')
image.write_to_file(open('new_au.ppm', 'wb'))
image.decrypt(key)
image.write_to_file(open('decrypt_new_au.ppm', 'wb'))