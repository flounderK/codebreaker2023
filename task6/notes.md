```
ssh -vvvv -o "IdentitiesOnly=yes" -i ~/.ssh/jumpbox.key -L 27017:100.107.142.158:27017  user@external-support.bluehorizonmobile.com
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
        { role: 'readWrite', db: 'snapshot-f2852ce48e77' }
      ],
      mechanisms: [ 'SCRAM-SHA-1', 'SCRAM-SHA-256' ]
    }
  ],
  ok: 1
}

db.grantRolesToUser("maintenance", [{role: "dbAdmin", db: "snapshot-f2852ce48e77"}, {role: "dbOwner", db: "snapshot-f2852ce48e77"}])

db.setProfilingLevel(2)

db.getCollection('system.profile').find()

db.files.insertOne({"blah":"blah"})

use admin
db.runCommand({ aggregate: 1, pipeline: [{ $currentOp: { allUsers: false, idleConnections: true, truncateOps: false } }, { $match: {} }], cursor: {},  $db: "snapshot-f2852ce48e77" })



use config
db.system.sessions.aggregate( [ { $listSessions: { } } ] )

100.90.12.106
