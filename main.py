from utils.CharHelper import CharHelper
from utils.UHCAESHelper import UHCAESHelper

menu_options = {
	1: 'Encryption',
	2: 'Decryption',
	3: 'Original Text Histogram and Frequency Analysis',
	4: 'Encrypted Text Histogram and Frequency Analysis',
	5: 'Exit'
}
print("="*70)
print("Enkripsi Teks menggunakan unimodular hill cipher dan AES-CBC")
print("-"*70)
def print_menu():
	for key in menu_options.keys():
		print (key, '--', menu_options[key] )

if __name__ == '__main__':
	while (True):
		print_menu()
		option = ''
		try:
			option = int(input('Enter your choice: '))
		except:
			print('Wrong input. Please enter a number ...')
		# Check what choice was entered and act accordingly
		if option == 1:
			UHCAESHelper.main_encrypt('sources/original.txt')
		elif option == 2:
			UHCAESHelper.main_decrypt('results/uhcAES_encrypted.txt')
		elif option == 3:
			CharHelper.main('sources/original.txt')
		elif option == 4:
			CharHelper.main('results/uhcAES_encrypted.txt')
		elif option == 5:
			print('Thank you for using this program. Please press enter')
			exit()
		else:
			print('Invalid option. Please enter a number between 1 and 5.')



