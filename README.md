![alt text](https://github.com/Bjond/jwtutils/blob/master/images/bjondhealthlogo-whitegrey.png "Bjönd Inc.")

[![][travis img]][travis]

# jwtutils

Jason Web Token Utilities that encapsulate jose4j. Used across the application. Free to use for the community 
although it is centered on our needs. Sorry.


## Build

Build jar file within ./build/libs/jwtutil.jar

```shell
$ gradle all
```

## Tests

Test report will be inserted into ./build/reports/tests/index.html

```shell
$ gradle test
```


## Publish Maven locally for testing

This will generate the default Maven POM file within ./build/publications/maven/jwtutil.pom

```shell
$ gradle publishToMavenLocal
```



## Documentation

To generate the javadoc that will appear in ./build/docs/javadoc/index.html

```shell
$ gradle javadoc
```


