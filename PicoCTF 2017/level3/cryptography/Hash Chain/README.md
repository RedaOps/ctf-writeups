# Description
We found a service hiding a flag! It seems to be using some kind of MD5 Hash Chain authentication to identify who is allowed to see the flag. Maybe there is a flaw you can exploit? hcexample.py has some example code on how to calculate iterations of the MD5 hash chain. Connect to it at shell2017.picoctf.com:46290!

# Hints
* Connect from the shell with nc. Read up on how Hash Chains work and try to identify what could make this cryptosystem weak.

# Writeup
Let's open hcexample.py to see what they refer to when talking about hash chains:

```python
import md5 #Must be run in python 2.7.x

#code used to calculate successive hashes in a hashchain.
seed = "seedhash"

#this will find the 5th hash in the hashchain. This would be the correct response if prompted with the 6th hash in the hashchain
hashc = seed
for _ in xrange(5):
  hashc = md5.new(hashc).hexdigest()

print hashc
```

So it's just a seed that gets MD5'd a couple of times. That means, if we know the seed, we can find out any hash in the hash chain.

Let's connect to the service and see what the program does:

![image](https://i.imgur.com/GU3k4Fg.png)

We notice 2 very important things:
1. The hashchain seed is usually the user's MD5 encrypted id.
2. The register/authentication algorithm works by submitting the hash in the hashchain that is before the given one. Interesting.

Let's see what happens if we choose to get flag instead of registering:

![image](https://i.imgur.com/VSQbccY.png)

Well, we know the seed (user 7224 MD5 encrypted), therefore we can find the hash in the chain before `b1806314d4b7bd1d999fb9c30aa324c2`.

Awesome! Let's write a script that will exploit this service automatically! You have it attached as `hashchain_exploit.py` here in this repository. Here's the explanation:

```python
#!/usr/bin/env python2.7
import md5;
import sys;
import socket;

HOST = 'shell2017.picoctf.com';
PORT = 46290;

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
s.connect((HOST, PORT)); #Connect to server

s.recv(4096); #Receive the "Would you like to..." part
s.send('f\n'); #We would like to get flag
data = s.recv(4096); #Get data
user = data.split('\n')[0].split(' ')[5]; #get user id
data = s.recv(4096);
tkn = data.split('\n')[0]; #Get token

print("User: "+user+"\nToken: "+tkn);
seed = md5.new(user).hexdigest(); #Calculate seed
print("Seed: "+seed);
found = False;
hashc = seed; #Starting point of hashchain is the seed

while(found == False):
	if (md5.new(hashc).hexdigest() == tkn): #If the next hash is the token, we found the hash we are looking for
		print("Hash found: "+hashc);
		found = True;
	else:
		hashc = md5.new(hashc).hexdigest();
#s.recv(4096)
print("Sending hash...");
s.send(hashc+'\n'); #Send the hash
print(s.recv(4096)); #Get the flag

```

Let's try it out:

![image](https://i.imgur.com/7pt0f4b.png)

Great!

**FLAG**: `50b5200b4013f421cbb6defa6a8ff8bb`
