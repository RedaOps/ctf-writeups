# Challenge
```
The Space Force has created a portal for the public to learn about and be in awe of our most elite Space Force Fighters. Check it out at fun.ritsec.club:8005!

Author: neon_spandex

```

# Solve

Going to the page, we are greeted with this search form:

![](https://i.imgur.com/Yp7GkR0.png)

This is a basic SQL Injection. We input `test' OR 1=1 #`

We get the following table:

![](https://i.imgur.com/ffkvN7I.png)

Flag is `RITSEC{hey_there_h4v3_s0me_point$_3ny2Lx}`
