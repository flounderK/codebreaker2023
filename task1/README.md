
# Task 1 - Find the Unknown Object - (General programming, database retrieval)

```
The US Coast Guard (USCG) recorded an unregistered signal over 30 nautical miles away from the continental US (OCONUS). NSA is contacted to see if we have a record of a similar signal in our databases. The Coast guard provides a copy of the signal data. Your job is to provide the USCG any colluding records from NSA databases that could hint at the object’s location. Per instructions from the USCG, to raise the likelihood of discovering the source of the signal, they need multiple corresponding entries from the NSA database whose geographic coordinates are within 1/100th of a degree. Additionally, record timestamps should be no greater than 10 minutes apart.


Downloads:

file provided by the USCG that contains metadata about the unknown signal (USCG.log)
NSA database of signals (database.db)
Provide database record IDs, one per line, that fit within the parameters specified above.
```


This task was pretty straight forward. We were given a json file containing coordinates and a time stamp (`USCG.log`) and a database (`database.db`) containing a bunch of data. I had to find the entries in the database that were within 10 minutes of the signal where the geographic coordinates were within 1/100th of a degree of the location in the log.

So I just dumped the whole database with python to avoid having to come up with any genuinely complex database queries.

```
SELECT a.transcript,
       a.contentUrl,
       a.description,
       a.name,
       a.encodingFormat,
       l.latitude,
       l.longitude,
       l.elevation,
       t.recTime,
       t.recDate,
       e.id,
       e.name
FROM   event e, location l, timestamp t, audio_object a
WHERE  e.location_id = l.id AND
       t.id = e.timestamp_id AND
       e.audio_object_id = a.id;
```

If you would like to see the code that solved this task, it can be found in [`solve.py`](solve.py)
