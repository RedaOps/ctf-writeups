# Challenge
```
3:371781196966866977144706219746579136461491261

Person1: applepearblue

Person2: darkhorseai

What is their secret key?
(Submit like RITSEC{KEY_GOES_HERE})

Hint 1: Hopefully you can get the flag in a diffie jiffy!

Hint 2: If you can type at a decent pace this challenge can be completed in under 30 seconds

Author: Cictrone
```
# Solve
At first, I was very confused, but if I knew what I was looking for, I would've figured it out immediately.

We are looking at the public parameters of a Diffie-Hellman Key Exchange. You can find a video explenation [here](https://youtu.be/NmM9HA2MQGI). This is the math behind it:

![](https://i.imgur.com/OI7fMQi.png)
*Source: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange*

Here, the values in red are private, and the values in blue are public.

After looking at the challenge, we can figure out the following public parameters:

* g(generator) = 3
* p(modulus prime number) = 371781196966866977144706219746579136461491261
* Person1's public key = 97112112108101112101097114098108117101 (applepearblue in integer form)
* Person2's public key = 100097114107104111114115101097105 (darkhorseai in integer form)

After researching the Logjam attack (you can find more information about it and read the research paper [here](https://weakdh.org/)) I concluded that a DF algorithm with a modulus that is lower than 512 bits is easy to crack using a Discrete Logarithm. Our prime number is 138 bits, so I used a [discrete logarithm calculator](https://www.alpertron.com.ar/DILOG.HTM) to calculate Person1's private key which was `111761499505149392512529118729824425120464044`.

After that, calculating the shared secret key was easy. We just use the following line of code:

`shared_key = pow(publickey_pers1, privatekey_pers1, n)`

In our case:

```
publickey_pers1 = 97112112108101112101097114098108117101
privatekey_pers1 = 111761499505149392512529118729824425120464044
n = 371781196966866977144706219746579136461491261
```

The result is `342060940412689854597111481732886330798298027`. Our flag is `RITSEC{342060940412689854597111481732886330798298027}`
