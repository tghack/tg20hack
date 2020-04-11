# To run this one:

1. Add submodule `git submodule update -- init`
2. Run `build_docker.sh`
3. Run `run.sh`
4. Go into container: `docker exec -it nonograms /bin/bash`
5. Patch:
```
diff --git a/include/logger.h b/include/logger.h
index 181906f..2de807f 100644
--- a/include/logger.h
+++ b/include/logger.h
@@ -5,7 +5,7 @@
 #ifndef NONOGRAMS_LOGGER_H_
 #define NONOGRAMS_LOGGER_H_

-#include <spdlog/sinks/stdout_color_sinks.h>
+#include <spdlog/spdlog.h>

 // Logs everything if necessary, uses pseudo-singleton structure
 // Init() should be called before using
 ```
6. Run `build.sh`

Then everything is ready to be run. So run the challenge and solve script like
this:
1. Go to `nonogram/server/`.
2. Run `run.sh`
3. Go back to the other terminal in the `nonogram/src/` folder.
4. Run `python3 solve.py`

