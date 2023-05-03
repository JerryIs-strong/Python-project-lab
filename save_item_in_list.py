import time
new_list = []
while(True):
  ac = input("Action: ")
  if ac == "check":
    print(new_list)
  elif ac == "save":
    ask = int(input("How many item would you want to save: "))
    i = 0
    if ask != 0 & i < ask:
      while i < ask:
        acs = input("Input: ")
        time.sleep(1)
        new_list.append(acs)
        i+=1
    else:
      print("Error")
  elif ac == "remove":
    print("Your list: ",new_list)
    acm = input("Item name: ")
    new_list.remove(acm)
    time.sleep(1)
    print("Done")
  elif ac == "break":
    break
  else:
    print("We could not found",'"{}"'.format(ac),"command")
