import random
import time
print("Guess the maximum number around 1~100!")
time.sleep(1)
actually_num = random.randrange(0, 100)
max_num = 100
min_num = 0
try_num = 1
grade = ["A", "B", "C"]
win_check = False
while win_check == False:
    guess_aka = int(input("Guess a number you think🤔: "))
    # possibility 1
    if guess_aka < 0 or guess_aka > 100 or guess_aka < min_num or guess_aka > max_num:
        print("Error")
    elif guess_aka < actually_num:
        min_num = guess_aka
        print("Opps,it is around", min_num, "to", max_num)
        try_num = try_num + 1
    elif guess_aka > actually_num:
        max_num = guess_aka
        print("Opps,it is around", min_num, "to", max_num)
        try_num = try_num + 1
    elif guess_aka == actually_num:
        print("Win!", "You have tried for", try_num, "times")
        if try_num <= 11:
            print("Good work!you got a ", grade[0], " grade")
        elif try_num <= 28:
            print("Nice!you got a", grade[1], "grade")
        else:
            print("Never mind that you got a ",
                  grade[2], " grade", ",but you can try again!")
        win_check = True
