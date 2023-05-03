import random
aka_num = int(input("How many password do you want to generate: "))
aka_length = int(input("How long do you need a password: "))
chars = ["qwertyuiopasdfghjklzxcvbnm","QWERTYUIOPASDFGHJKLZXCVBNM","1234567890","!@#$%&*?|+/*-=,."]

def getNew(value):
  val=0
  time=0
  pwds=''
  pwds_list=[]
  while time<value:
    pwds+=random.choice(chars[val])
    pwds_list.append(pwds)
    pwds=''
    time+=1
    val+=1
    if val>3:
      val=0
  return pwds_list

aka_strong = int(input("Get a strong password['0'=No '1'=Yes]: "))
print('\nWait for process: ')
for pwd in range(aka_num):
  password = ''
  if aka_strong == 0:
    for i in range(aka_length):
     password += random.choice(chars[0]+chars[1]+chars[2])
  else:
    for i in range(aka_length):
     password += random.choice(getNew(aka_length))
  print(password)
print("All tasks run successfully without any errors")
