# Challenge
```
fun.ritsec.club:8007

Author: jok3r

```
Same page as TangledWeb

# Solve
After solving Tangled Web, we get a hint:
```

<!-- REMOVE THIS NOTE LATER -->
<!-- Getting remote access is so much work. Just do fancy things on devsrule.php -->
```

Going to `http://fun.ritsec.club:8007/devsrule.php` and get the following message:
```
Not what you input eh?
This param is 'magic' man.
```

The 2 keyswords here are **input** and **magic**.

Fiddling with the `?magic=` parameter, I tried different LFI. The one that worked was `php://input`.

If you do a POST request to `http://fun.ritsec.club:8007/devsrule.php?magic=php://input` with PHP code as the POST payload, we have PHP Code Execution.

![](https://i.imgur.com/jl2Z6x3.png)

There is an interesting file called `JokersSomeSortaHack`. Inside, there is an RSA key. This hinted me to a user we can connect to with that RSA key. I got the `/etc/passwd` file.

![](https://i.imgur.com/VcSWjSt.png)

The `joker` user looks interesting. After looking inside its directory, we find a `flag.txt` file which we can read:

![](https://i.imgur.com/Ep3RBsa.png)

Flag: `RITSEC{WOW_THAT_WAS_A_PAIN_IN_THE_INPUT}`
