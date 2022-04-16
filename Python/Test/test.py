import random
days = 365
people = 60
i = 0
p = 1
same = 0
not_same = 0

arr = []
arr = [0 for i in range(people)]

for i, v in enumerate(arr):
    arr[i] = random.randrange(1, 365, 1)

for i, v in enumerate(arr):
    for k,v in enumerate(arr):
        if arr[i] == arr[k] & k > i:
            same += 1


print(arr)
print("same: {0:d}".format(same))
print("NOT same: {0:d}".format(people-same))
print("Empirical Probability: {0:f}".format((same/people*100)))


for i in range(people):
    p = p * (days-i)/(days)
print("Calculated Probability: {0:f}". format(((1 - p)*100)))
