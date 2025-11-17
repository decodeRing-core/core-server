# Build tests

## Building a new version
This builds both the server, client and agent (not yet implemented)
```
make build
```

## Cleaning up the database

```
stop the dcdr-server instance if running
make drop
make init
```

## Cleaning up the back-ends

```
make clean-backends
```

## Seed the database with test data
```
start the dcdr-server instance
make seed (one or more times to generate 1 or more applications)
```

## Run the following tests

### Check that the help feature works
```
dcdr -h
```

### Verify auth is working
```
dcdr auth
Enter token: <token>
Authentication successful.
```

### Verify that app identity is working
```
dcdr ident
{"instance_id":"dummy-instance-id"}
```

### List registered apps (apps were registered when you ran ```make seed```)
```
dcdr list-apps --table
```

### List secrets for app (secrets were generated when you ran ```make seed```)
```
dcdr list-secrets --appid <appid>
```

### Test secret tainting feature
```
dcdr taint --appid <appid> --name <name>
```

### Verify secret is tainted - this is also output when you list secrets
```
dcdr istainted --appid <appid> --name <name>
```

### Make sure we can destroy a secret
```
dcdr destroy --appid <appid> --name <name>
{"status":"ok"}
```