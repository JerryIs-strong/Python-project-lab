import random
import time

try:
    aka_num = int(input("How many passwords do you want to generate: "))
    aka_length = int(input("How long do you need a password: "))
    aka_strong = int(input("Get a strong password ['0' = No, '1' = Yes]: "))
    start_time = time.time()

    chars = [
        "qwertyuiopasdfghjklzxcvbnm",
        "QWERTYUIOPASDFGHJKLZXCVBNM",
        "1234567890",
        "!@#$%&*?|+/*-=,."
    ]

    def get_new(value): #generate for more difficult pws
        pwds_list = [] #store a pws generated as cache
        for time in range(value):
            pwds = '' 
            for val in range(value):
                pwds += random.choice(chars[val % len(chars)]) # ? select a character from the chars list based on the index val % len(chars)
            pwds_list.append(pwds)
        return pwds_list

    print('\nWait for process: ')
    for pwd in range(aka_num):
        password = ''
        if aka_strong == 0:
            for i in range(aka_length):
                password += random.choice(chars[0] + chars[1] + chars[2])
        else:
            password = random.choice(get_new(aka_length))
        print(password)
    print("\n--- %s seconds ---" % (time.time() - start_time))
    print("All tasks run successfully without any errors") #print the state
except Exception as e: #catch if an error occurs
    print("An error occurred:", str(e))
