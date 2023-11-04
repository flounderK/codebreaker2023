#!/usr/bin/env python3

import sqlite3
import json
import datetime

with open("USCG.log", "r") as f:
    log_data = json.load(f)

log_timestamp = datetime.datetime.strptime(log_data['timestamp'],
                                           "%m/%d/%Y, %H:%M:%S")
coords = log_data['coordinates'][0]
log_longitude = float(coords['longitude'])
log_latitude = float(coords['latitude'])


def group_by_increment(iterable, group_incr, field_access=None):
    """
    Identify series of values that increment/decrement
    by the same amount, grouping them into lists.
    """
    if field_access is None:
        field_access = lambda a: a
    grouped = []
    current = [iterable[0]]
    for i in range(1, len(iterable)):
        curr_val = field_access(iterable[i])
        prev_val = field_access(current[-1])
        if (prev_val + group_incr) <= curr_val:
            current.append(iterable[i])
        else:
            grouped.append(current)
            current = [iterable[i]]
    if current:
        grouped.append(current)
    return grouped


cursor = sqlite3.connect("database.db")

keys = [
    "transcript",
    "contentUrl",
    "description",
    "audio_name",
    "encodingFormat",
    "latitude",
    "longitude",
    "elevation",
    "recTime",
    "recDate",
    "id",
    "event_name",
]


query = """SELECT
        a.transcript,
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
FROM event e, location l, timestamp t, audio_object a
WHERE
    e.location_id = l.id AND
    t.id = e.timestamp_id AND
    e.audio_object_id = a.id;"""

c = cursor.execute(query)

result = c.fetchall()
# dict_records = [dict(zip(keys, i)) for i in result]
dict_records = []
for i in result:
    rec = dict(zip(keys, i))
    time_str = rec['recDate'] + ' ' + rec['recTime']
    rec['datetime'] = datetime.datetime.strptime(time_str,
                                                 "%m/%d/%Y %H:%M:%S")
    rec['longitude_f'] = float(rec['longitude'])
    rec['latitude_f'] = float(rec['latitude'])
    # rec['elevation_i'] = int(rec['elevation'])
    dict_records.append(rec)


# time boundary set by prompt
TIME_BOUNDS_SEC = 60*10
# sort so that group by time works
dict_records.sort(key=lambda a: a['datetime'])
# group every record by time so that any records within 10 minutes of eachother
# end up in the same group
grouped_by_time = group_by_increment(dict_records,
                                     datetime.timedelta(seconds=TIME_BOUNDS_SEC),
                                     lambda a: a['datetime'])

# identify the record group that the logged time fits into
found_rec_group = None
for rec_group in grouped_by_time:
    for rec in rec_group:
        timedelt = rec['datetime'] - log_timestamp
        total_sec = abs(timedelt.total_seconds())
        if total_sec <= TIME_BOUNDS_SEC:
            found_rec_group = rec_group
            break
    if found_rec_group:
        break

# now all records in found_rec_group meet the time criteria


DIST_BOUNDS = 1/100

records_within_bounds = []
for rec in dict_records:
    long_diff = abs(rec['longitude_f'] - log_longitude)
    lat_diff = abs(rec['latitude_f'] - log_latitude)
    if long_diff <= DIST_BOUNDS and lat_diff <= DIST_BOUNDS:
        print("long diff %s" % str(long_diff))
        print("lat diff %s" % str(lat_diff))
        print("")
        records_within_bounds.append(rec)


