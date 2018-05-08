# Description
Identify the data contained within wigle and determine how to visualize it. Update 16:26 EST 1 Apr If you feel that you are close, make a private piazza post with what you have, and an admin will help out.
# Hints
* Perhaps they've been storing data in a database. How do we access the information?
* How can we visualize this data? Maybe we just need to take a step back to get the big picture?
* Try zero in the first word of the flag, if you think it's an O.
* If you think you're super close, make a private piazza post with what you think it is.

# Writeup
Hmm...an unknown file. Let's use the `file` command in order to learn more about it.

![image](https://i.imgur.com/8crohPx.png)

Aha! So it's an SQLite file. Let's use an online interpreter to open it.

![image](https://i.imgur.com/wshDW39.png)

So we have 3 tables:
* android_metadata
* location
* network

After going through each table multiple times, I found the **location** table interesting, since it contains a set of coordinates.

Let's use a basic SQL Query to compile a list of locations in the following format: `<lat>, <long>` so we can visualize them on a map.

We will use the following query:
```SQL
SELECT `lat`, `lon` from `location`
```

And we will get the following data (after replacing empty spaces with `,`):
```
-48,-96.96
-47.99,-96.96
-47.98,-96.96
...
-47.983,-94.74300000000012
```

Now, we can open an online visualizer. I found a good one [here](https://www.darrinward.com/lat-long)

If we input our data, we will see a pattern:

![image](https://i.imgur.com/uhggsHZ.png)

There we go! We found our flag!

**FLAG**: `FLAG{F0UND_M3_A20E177F}`
