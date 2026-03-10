package li.power.app.sslunpinner.xposed

import io.github.libxposed.api.XposedInterface
import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface.ModuleLoadedParam
import io.github.libxposed.api.XposedModuleInterface.PackageLoadedParam
import java.lang.reflect.Constructor
import java.lang.reflect.Member
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.util.ArrayList
import java.util.Collections
import java.util.LinkedHashMap
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import android.util.Log
import io.github.libxposed.api.annotations.BeforeInvocation
import io.github.libxposed.api.annotations.XposedHooker
import java.io.File

class SslUnpinModule(base: XposedInterface, param: ModuleLoadedParam) : XposedModule(base, param) {

    private fun logMessage(msg: String) {
        log(msg)
        Log.d("SSLUnpinner", msg)
    }

    init {
        module = this
        logMessage("SSLUnpinner loaded in process: ${param.processName}")
    }

    override fun onPackageLoaded(param: PackageLoadedParam) {
        super.onPackageLoaded(param)
        if (!param.isFirstPackage) {
            return
        }

        appClassLoader = param.classLoader
        var installed = 0
        for (spec in HOOK_SPECS) {
            installed += installHookSpec(param.classLoader, spec)
        }
        installSslPeerUnverifiedConstructorHooks(param.classLoader)
        logMessage("Installed $installed SSL bypass hooks for ${param.packageName}")

        // Flutter native SSL bypass
        installFlutterBypassHook(param.classLoader, param.packageName)
    }

    private fun installHookSpec(classLoader: ClassLoader, spec: HookSpec): Int {
        val targetClass = findClass(spec.className, classLoader) ?: return 0
        val candidates = collectMethods(targetClass, spec.methodName).filter { method ->
            methodMatchesSpec(method, spec)
        }
        var installed = 0
        for (method in candidates) {
            if (!installMethodHook(method, spec.action)) {
                continue
            }
            installed++
        }
        return installed
    }

    private fun installMethodHook(method: Method, action: HookAction): Boolean {
        if (Modifier.isAbstract(method.modifiers)) {
            return false
        }
        val key = method.toGenericString()
        if (!hookedMembers.add(key)) {
            return false
        }
        runCatching {
            methodActions[method] = action
            hook(method, GenericBypassHooker::class.java)
        }.onFailure {
            methodActions.remove(method)
            hookedMembers.remove(key)
            logMessage("Failed to hook ${method.declaringClass.name}.${method.name}: ${it.message}")
            return false
        }
        return true
    }

    private fun installSslPeerUnverifiedConstructorHooks(classLoader: ClassLoader) {
        val exceptionClass = findClass(SSLPeerUnverifiedException::class.java.name, classLoader) ?: return
        for (constructor in exceptionClass.declaredConstructors) {
            installConstructorHook(constructor)
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun installConstructorHook(constructor: Constructor<*>) {
        val key = constructor.toGenericString()
        if (!hookedMembers.add(key)) {
            return
        }
        runCatching {
            hook(constructor as Constructor<Any>, SslPeerUnverifiedHooker::class.java)
        }.onFailure {
            hookedMembers.remove(key)
            logMessage("Failed to hook constructor ${constructor.declaringClass.name}: ${it.message}")
        }
    }

    private fun handleGenericHookBefore(callback: XposedInterface.BeforeHookCallback) {
        val action = methodActions[callback.member] ?: return
        when (action) {
            HookAction.SKIP_VOID -> callback.returnAndSkip(null)
            HookAction.RETURN_TRUE -> callback.returnAndSkip(true)
            HookAction.RETURN_FALSE -> callback.returnAndSkip(false)
            HookAction.RETURN_NULL -> callback.returnAndSkip(null)
            HookAction.RETURN_ARG0 -> callback.returnAndSkip(callback.args.firstOrNull())
            HookAction.RETURN_EMPTY_LIST -> callback.returnAndSkip(ArrayList<Any>())
            HookAction.RETURN_SAFE_DEFAULT -> callback.returnAndSkip(defaultResultForMember(callback.member))
            HookAction.PROCEED_SSL_ERROR_HANDLER -> {
                proceedSslErrorHandler(callback.args)
                callback.returnAndSkip(null)
            }
            HookAction.PROCEED_INTERCEPTOR_CHAIN -> {
                callback.returnAndSkip(proceedInterceptorChain(callback.args.firstOrNull()))
            }
            HookAction.FORCE_ARG0_TRUE -> {
                if (callback.args.isNotEmpty()) {
                    callback.args[0] = true
                }
            }
            HookAction.REPLACE_TRUST_MANAGERS -> {
                if (callback.args.size > 1) {
                    callback.args[1] = TRUST_ALL_MANAGERS
                }
            }
        }
    }

    private fun handleSslPeerUnverified() {
        val stack = Thread.currentThread().stackTrace
        val index = stack.indexOfFirst { it.className == SSLPeerUnverifiedException::class.java.name }
        if (index < 0 || index + 1 >= stack.size) {
            return
        }

        val caller = stack[index + 1]
        val className = caller.className
        if (
            className == "com.android.org.conscrypt.ActiveSession" ||
            className == "com.google.android.gms.org.conscrypt.ActiveSession"
        ) {
            return
        }

        val dynamicKey = "$className#${caller.methodName}"
        if (!dynamicHooks.add(dynamicKey)) {
            return
        }

        val classLoader = appClassLoader ?: return
        val targetClass = findClass(className, classLoader) ?: return
        val methods = collectMethods(targetClass, caller.methodName)
        var installed = 0
        for (method in methods) {
            if (installMethodHook(method, HookAction.RETURN_SAFE_DEFAULT)) {
                installed++
            }
        }
        if (installed > 0) {
            logMessage("Dynamic SSLPeerUnverifiedException bypass patched $className.${caller.methodName} ($installed overloads)")
        }
    }

    private fun defaultResultForMember(member: Member): Any? {
        val method = member as? Method ?: return null
        return defaultResultForReturnType(method.returnType)
    }

    private fun defaultResultForReturnType(type: Class<*>): Any? {
        return when (type) {
            Void.TYPE -> null
            Boolean::class.javaPrimitiveType,
            java.lang.Boolean::class.java -> true
            Integer::class.javaPrimitiveType,
            java.lang.Integer::class.java -> 0
            Long::class.javaPrimitiveType,
            java.lang.Long::class.java -> 0L
            Float::class.javaPrimitiveType,
            java.lang.Float::class.java -> 0f
            Double::class.javaPrimitiveType,
            java.lang.Double::class.java -> 0.0
            Short::class.javaPrimitiveType,
            java.lang.Short::class.java -> 0.toShort()
            Byte::class.javaPrimitiveType,
            java.lang.Byte::class.java -> 0.toByte()
            Char::class.javaPrimitiveType,
            java.lang.Character::class.java -> '\u0000'
            else -> null
        }
    }

    private fun proceedSslErrorHandler(args: Array<Any?>) {
        val handler = args.getOrNull(1) ?: return
        runCatching {
            val proceed = handler.javaClass.methods.firstOrNull {
                it.name == "proceed" && it.parameterCount == 0
            } ?: return
            proceed.invoke(handler)
        }
    }

    private fun proceedInterceptorChain(chain: Any?): Any? {
        if (chain == null) {
            return null
        }
        return runCatching {
            val requestMethod = chain.javaClass.methods.firstOrNull {
                it.name == "request" && it.parameterCount == 0
            } ?: return null
            val proceedMethod = chain.javaClass.methods.firstOrNull {
                it.name == "proceed" && it.parameterCount == 1
            } ?: return null
            val request = requestMethod.invoke(chain)
            proceedMethod.invoke(chain, request)
        }.getOrNull()
    }

    private fun findClass(className: String, classLoader: ClassLoader?): Class<*>? {
        return runCatching {
            Class.forName(className, false, classLoader)
        }.recoverCatching {
            Class.forName(className, false, null)
        }.getOrNull()
    }

    private fun collectMethods(targetClass: Class<*>, methodName: String): List<Method> {
        val methods = LinkedHashMap<String, Method>()

        var current: Class<*>? = targetClass
        while (current != null) {
            for (method in current.declaredMethods) {
                if (method.name == methodName) {
                    methods.putIfAbsent(method.toGenericString(), method)
                }
            }
            current = current.superclass
        }

        for (method in targetClass.methods) {
            if (method.name == methodName) {
                methods.putIfAbsent(method.toGenericString(), method)
            }
        }
        return methods.values.toList()
    }

    private fun methodMatchesSpec(method: Method, spec: HookSpec): Boolean {
        val expected = spec.parameterTypes ?: return true
        val actual = method.parameterTypes.map { normalizeTypeName(it.typeName) }
        return actual == expected.map(::normalizeTypeName)
    }

    private fun normalizeTypeName(typeName: String): String {
        val value = typeName.trim()
        if (!value.startsWith("[")) {
            return value
        }

        var depth = 0
        var index = 0
        while (index < value.length && value[index] == '[') {
            depth++
            index++
        }

        val descriptor = value.substring(index)
        val base = when (descriptor) {
            "V" -> "void"
            "Z" -> "boolean"
            "B" -> "byte"
            "C" -> "char"
            "S" -> "short"
            "I" -> "int"
            "J" -> "long"
            "F" -> "float"
            "D" -> "double"
            else -> if (descriptor.startsWith("L") && descriptor.endsWith(";")) {
                descriptor.substring(1, descriptor.length - 1).replace('/', '.')
            } else {
                descriptor
            }
        }

        return buildString {
            append(base)
            repeat(depth) {
                append("[]")
            }
        }
    }

    private data class HookSpec(
        val className: String,
        val methodName: String,
        val parameterTypes: List<String>? = null,
        val action: HookAction,
    )

    private enum class HookAction {
        SKIP_VOID,
        RETURN_TRUE,
        RETURN_FALSE,
        RETURN_NULL,
        RETURN_ARG0,
        RETURN_EMPTY_LIST,
        RETURN_SAFE_DEFAULT,
        PROCEED_SSL_ERROR_HANDLER,
        PROCEED_INTERCEPTOR_CHAIN,
        FORCE_ARG0_TRUE,
        REPLACE_TRUST_MANAGERS,
    }

    private class TrustAllManager : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {
        }

        override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {
        }

        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> {
            return emptyArray()
        }
    }

    @XposedHooker
    class GenericBypassHooker : XposedInterface.Hooker {
        companion object {
            @JvmStatic
            @BeforeInvocation
            fun beforeInvocation(callback: XposedInterface.BeforeHookCallback) {
                module.handleGenericHookBefore(callback)
            }
        }
    }

    @XposedHooker
    class SslPeerUnverifiedHooker : XposedInterface.Hooker {
        companion object {
            @JvmStatic
            @BeforeInvocation
            @Suppress("UNUSED_PARAMETER")
            fun beforeInvocation(callback: XposedInterface.BeforeHookCallback) {
                module.handleSslPeerUnverified()
            }
        }
    }

    private fun installFlutterBypassHook(classLoader: ClassLoader, packageName: String) {
        logMessage("Flutter: installFlutterBypassHook called for $packageName")

        val runtimeClass = findClass("java.lang.Runtime", classLoader)
        if (runtimeClass == null) {
            logMessage("Flutter: Runtime class not found!")
            return
        }
        logMessage("Flutter: Runtime class found: $runtimeClass")

        // List all methods that contain "load" in name for debugging
        val loadMethods = runtimeClass.declaredMethods.filter { it.name.contains("load", ignoreCase = true) }
        logMessage("Flutter: Runtime load-related methods: ${loadMethods.map { "${it.name}(${it.parameterTypes.map { p -> p.simpleName }.joinToString(",")})" }}")

        val loadLibrary0 = runtimeClass.declaredMethods.firstOrNull {
            it.name == "loadLibrary0" && it.parameterTypes.size == 2
        }

        if (loadLibrary0 != null) {
            logMessage("Flutter: found Runtime.loadLibrary0: ${loadLibrary0.toGenericString()}")
            currentPackageName = packageName
            runCatching {
                hook(loadLibrary0, LoadLibraryHooker::class.java)
                logMessage("Flutter: hooked Runtime.loadLibrary0 successfully")
            }.onFailure {
                logMessage("Flutter: failed to hook Runtime.loadLibrary0: ${it.message}")
                logMessage("Flutter: exception: ${it.javaClass.name}: ${it.stackTraceToString().take(500)}")
            }
            return
        }

        logMessage("Flutter: Runtime.loadLibrary0(2 params) not found, checking other overloads...")
        val loadLibrary0Any = runtimeClass.declaredMethods.filter { it.name == "loadLibrary0" }
        logMessage("Flutter: loadLibrary0 overloads: ${loadLibrary0Any.map { "${it.name}(${it.parameterTypes.size} params: ${it.parameterTypes.map { p -> p.name }.joinToString(",")})" }}")

        // Fallback: try hooking System.loadLibrary
        logMessage("Flutter: trying System.loadLibrary fallback")
        val systemClass = findClass("java.lang.System", classLoader)
        if (systemClass == null) {
            logMessage("Flutter: System class not found!")
            return
        }

        val loadLibraryMethod = systemClass.declaredMethods.firstOrNull {
            it.name == "loadLibrary" && it.parameterTypes.size == 1 &&
                it.parameterTypes[0] == String::class.java
        }

        if (loadLibraryMethod == null) {
            logMessage("Flutter: System.loadLibrary(String) not found!")
            val systemLoadMethods = systemClass.declaredMethods.filter { it.name.contains("load", ignoreCase = true) }
            logMessage("Flutter: System load-related methods: ${systemLoadMethods.map { "${it.name}(${it.parameterTypes.map { p -> p.simpleName }.joinToString(",")})" }}")
            return
        }

        logMessage("Flutter: found System.loadLibrary: ${loadLibraryMethod.toGenericString()}")
        currentPackageName = packageName
        runCatching {
            hook(loadLibraryMethod, LoadLibraryHooker::class.java)
            logMessage("Flutter: hooked System.loadLibrary successfully")
        }.onFailure {
            logMessage("Flutter: failed to hook System.loadLibrary: ${it.message}")
            logMessage("Flutter: exception: ${it.javaClass.name}: ${it.stackTraceToString().take(500)}")
        }
    }

    private fun handleLoadLibrary(callback: XposedInterface.BeforeHookCallback) {
        // Log every call to loadLibrary
        val allArgs = callback.args.mapIndexed { i, a -> "arg$i=${a?.javaClass?.simpleName}:$a" }.joinToString(", ")
        logMessage("Flutter: handleLoadLibrary called, args=[$allArgs]")

        // Find the library name argument (last String param)
        val libName = callback.args.filterIsInstance<String>().lastOrNull()
        if (libName == null) {
            logMessage("Flutter: no String argument found in loadLibrary call")
            return
        }
        logMessage("Flutter: loadLibrary called with name=\"$libName\"")

        if (libName != "flutter") return
        if (flutterPatched) {
            logMessage("Flutter: already patched, skipping")
            return
        }

        logMessage("Flutter: intercepted loadLibrary(\"flutter\")!")

        val arch = FlutterSslPatcher.detectArch()
        logMessage("Flutter: detected architecture: $arch")

        // Find original libflutter.so via ApplicationInfo
        val pkg = currentPackageName ?: run {
            logMessage("Flutter: currentPackageName is null!")
            return
        }

        // Strategy 1: Use ClassLoader.findLibrary() to resolve the exact path
        logMessage("Flutter: trying ClassLoader.findLibrary...")
        var srcFile: File? = null
        try {
            val cl = appClassLoader
            if (cl != null) {
                val findLibraryMethod = cl.javaClass.getMethod("findLibrary", String::class.java)
                val libPath = findLibraryMethod.invoke(cl, "flutter") as? String
                logMessage("Flutter: ClassLoader.findLibrary returned: $libPath")
                if (libPath != null) {
                    val f = File(libPath)
                    if (f.exists()) srcFile = f
                }
            } else {
                logMessage("Flutter: appClassLoader is null")
            }
        } catch (e: Exception) {
            logMessage("Flutter: ClassLoader.findLibrary failed: ${e.message}")
        }

        // Strategy 2: Use ApplicationInfo.nativeLibraryDir
        if (srcFile == null) {
            logMessage("Flutter: trying ApplicationInfo.nativeLibraryDir...")
            try {
                val activityThreadClass = Class.forName("android.app.ActivityThread")
                val currentApp = activityThreadClass.getMethod("currentApplication").invoke(null)
                if (currentApp != null) {
                    val appInfo = currentApp.javaClass.getMethod("getApplicationInfo").invoke(currentApp)
                    val nativeLibDir = appInfo.javaClass.getField("nativeLibraryDir").get(appInfo) as? String
                    logMessage("Flutter: nativeLibraryDir = $nativeLibDir")
                    if (nativeLibDir != null) {
                        val candidate = File(nativeLibDir, "libflutter.so")
                        logMessage("Flutter: checking ${candidate.absolutePath} exists=${candidate.exists()}")
                        if (candidate.exists()) srcFile = candidate
                    }
                }
            } catch (e: Exception) {
                logMessage("Flutter: ApplicationInfo approach failed: ${e.message}")
            }
        }

        // Strategy 3: search /proc/self/maps (won't work in before-hook, but try anyway)
        if (srcFile == null) {
            logMessage("Flutter: trying /proc/self/maps...")
            srcFile = findLibFlutterFromMaps()
        }

        if (srcFile == null || !srcFile!!.exists()) {
            logMessage("Flutter: libflutter.so not found for package $pkg")
            // Don't skip the original load - the library hasn't been loaded yet
            // After it loads, we might find it via maps
            return
        }

        logMessage("Flutter: found libflutter.so at ${srcFile!!.absolutePath} (size=${srcFile!!.length()} bytes)")

        // Create patched copy in the app's cache directory
        val cacheDir = File("/data/data/$pkg/cache")
        if (!cacheDir.exists()) {
            logMessage("Flutter: creating cache dir: ${cacheDir.absolutePath}")
            cacheDir.mkdirs()
        }
        val dstFile = File(cacheDir, "libflutter_patched.so")

        logMessage("Flutter: patching ${srcFile!!.absolutePath} -> ${dstFile.absolutePath}")
        val success = FlutterSslPatcher.patchLibrary(srcFile!!, dstFile, arch)
        if (!success) {
            logMessage("Flutter: patching failed — no pattern matched")
            return
        }

        logMessage("Flutter: patch succeeded, loading patched library...")
        // Load the patched library instead of the original
        try {
            val runtime = Runtime.getRuntime()
            val callerClass: Class<*>? = callback.args.firstOrNull { it is Class<*> } as? Class<*>
                ?: appClassLoader?.let { findClass("io.flutter.embedding.engine.FlutterJNI", it) }
            
            var loaded = false

            // Try load0(Class, String) (Android 14/15/some older)
            if (!loaded && callerClass != null) {
                try {
                    val load0 = runtime.javaClass.declaredMethods.firstOrNull {
                        it.name == "load0" && it.parameterTypes.size == 2 &&
                            it.parameterTypes[0] == Class::class.java &&
                            it.parameterTypes[1] == String::class.java
                    }
                    if (load0 != null) {
                        load0.isAccessible = true
                        load0.invoke(runtime, callerClass, dstFile.absolutePath)
                        loaded = true
                        logMessage("Flutter: loaded via Runtime.load0(Class, String)")
                    }
                } catch (e: Exception) {
                    logMessage("Flutter: load0 failed: ${e.message}")
                }
            }

            // Try load0(ClassLoader, String)
            if (!loaded && appClassLoader != null) {
                try {
                    val load0Cl = runtime.javaClass.declaredMethods.firstOrNull {
                        it.name == "load0" && it.parameterTypes.size == 2 &&
                            it.parameterTypes[0] == ClassLoader::class.java &&
                            it.parameterTypes[1] == String::class.java
                    }
                    if (load0Cl != null) {
                        load0Cl.isAccessible = true
                        load0Cl.invoke(runtime, appClassLoader, dstFile.absolutePath)
                        loaded = true
                        logMessage("Flutter: loaded via Runtime.load0(ClassLoader, String)")
                    }
                } catch (e: Exception) {
                    logMessage("Flutter: load0Cl failed: ${e.message}")
                }
            }

            // Try load(String, ClassLoader)
            if (!loaded && appClassLoader != null) {
                try {
                    val loadCl = runtime.javaClass.declaredMethods.firstOrNull {
                        it.name == "load" && it.parameterTypes.size == 2 &&
                            it.parameterTypes[0] == String::class.java &&
                            it.parameterTypes[1] == ClassLoader::class.java
                    }
                    if (loadCl != null) {
                        loadCl.isAccessible = true
                        loadCl.invoke(runtime, dstFile.absolutePath, appClassLoader)
                        loaded = true
                        logMessage("Flutter: loaded via Runtime.load(String, ClassLoader)")
                    }
                } catch (e: Exception) {
                    logMessage("Flutter: load(String, ClassLoader) failed: ${e.message}")
                }
            }

            // Try nativeLoad(String, ClassLoader)
            if (!loaded && appClassLoader != null) {
                try {
                    val nativeLoad = runtime.javaClass.declaredMethods.firstOrNull {
                        it.name == "nativeLoad" && it.parameterTypes.size == 2 &&
                            it.parameterTypes[0] == String::class.java &&
                            it.parameterTypes[1] == ClassLoader::class.java
                    }
                    if (nativeLoad != null) {
                        nativeLoad.isAccessible = true
                        val error = nativeLoad.invoke(runtime, dstFile.absolutePath, appClassLoader) as? String
                        if (error == null) {
                            loaded = true
                            logMessage("Flutter: loaded via Runtime.nativeLoad(String, ClassLoader)")
                        } else {
                            logMessage("Flutter: nativeLoad returned error: $error")
                        }
                    }
                } catch (e: Exception) {
                    logMessage("Flutter: nativeLoad failed: ${e.message}")
                }
            }

            if (!loaded) {
                logMessage("Flutter: fallback to System.load(absolutePath) - MAY CRASH IF CLASSLOADER MISMATCHES!")
                System.load(dstFile.absolutePath)
            }

            flutterPatched = true
            logMessage("Flutter: loaded patched libflutter.so successfully!")
            // Skip the original loadLibrary call
            callback.returnAndSkip(null)
        } catch (e: Exception) {
            logMessage("Flutter: failed to load patched library: ${e.javaClass.name}: ${e.message}")
            logMessage("Flutter: stack: ${e.stackTraceToString().take(500)}")
            // Let the original load proceed
        }
    }

    private fun findLibFlutter(dir: File, arch: String): File? {
        if (!dir.exists() || !dir.isDirectory) return null
        // Check common native lib paths
        val archDirs = when (arch) {
            "arm64" -> listOf("arm64-v8a", "arm64")
            "arm" -> listOf("armeabi-v7a", "armeabi", "arm")
            "x64" -> listOf("x86_64", "x64")
            "x86" -> listOf("x86")
            else -> listOf(arch)
        }

        // Direct check: dir/lib/<archDir>/libflutter.so
        for (archDir in archDirs) {
            val candidate = File(dir, "lib/$archDir/libflutter.so")
            if (candidate.exists()) return candidate
        }

        // Recursive search
        dir.listFiles()?.forEach { child ->
            if (child.isDirectory) {
                findLibFlutter(child, arch)?.let { return it }
            } else if (child.name == "libflutter.so") {
                return child
            }
        }
        return null
    }

    private fun findLibFlutterFromMaps(): File? {
        return try {
            File("/proc/self/maps").readLines()
                .filter { it.contains("libflutter.so") }
                .mapNotNull { line ->
                    val path = line.substringAfterLast(" ").trim()
                    if (path.startsWith("/") && File(path).exists()) File(path) else null
                }
                .firstOrNull()
        } catch (e: Exception) {
            null
        }
    }

    @XposedHooker
    class LoadLibraryHooker : XposedInterface.Hooker {
        companion object {
            @JvmStatic
            @BeforeInvocation
            fun beforeInvocation(callback: XposedInterface.BeforeHookCallback) {
                module.handleLoadLibrary(callback)
            }
        }
    }

    companion object {
        private lateinit var module: SslUnpinModule
        private val methodActions = ConcurrentHashMap<Member, HookAction>()
        private val hookedMembers = Collections.newSetFromMap(ConcurrentHashMap<String, Boolean>())
        private val dynamicHooks = Collections.newSetFromMap(ConcurrentHashMap<String, Boolean>())
        private val TRUST_ALL_MANAGERS: Array<TrustManager> = arrayOf(TrustAllManager())
        @Volatile private var appClassLoader: ClassLoader? = null
        @Volatile private var flutterPatched = false
        @Volatile private var currentPackageName: String? = null

        private val HOOK_SPECS = listOf(
            HookSpec(
                className = "javax.net.ssl.HttpsURLConnection",
                methodName = "setDefaultHostnameVerifier",
                parameterTypes = listOf("javax.net.ssl.HostnameVerifier"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "javax.net.ssl.HttpsURLConnection",
                methodName = "setSSLSocketFactory",
                parameterTypes = listOf("javax.net.ssl.SSLSocketFactory"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "javax.net.ssl.HttpsURLConnection",
                methodName = "setHostnameVerifier",
                parameterTypes = listOf("javax.net.ssl.HostnameVerifier"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "javax.net.ssl.SSLContext",
                methodName = "init",
                parameterTypes = listOf(
                    "javax.net.ssl.KeyManager[]",
                    "javax.net.ssl.TrustManager[]",
                    "java.security.SecureRandom",
                ),
                action = HookAction.REPLACE_TRUST_MANAGERS,
            ),
            HookSpec(
                className = "com.android.org.conscrypt.TrustManagerImpl",
                methodName = "checkTrustedRecursive",
                action = HookAction.RETURN_EMPTY_LIST,
            ),
            HookSpec(
                className = "com.android.org.conscrypt.TrustManagerImpl",
                methodName = "verifyChain",
                action = HookAction.RETURN_ARG0,
            ),
            HookSpec(
                className = "okhttp3.CertificatePinner",
                methodName = "check",
                parameterTypes = listOf("java.lang.String", "java.util.List"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "okhttp3.CertificatePinner",
                methodName = "check",
                parameterTypes = listOf("java.lang.String", "java.security.cert.Certificate"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "okhttp3.CertificatePinner",
                methodName = "check",
                parameterTypes = listOf("java.lang.String", "java.security.cert.Certificate[]"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "okhttp3.CertificatePinner",
                methodName = "check\$okhttp",
                parameterTypes = listOf("java.lang.String", "kotlin.jvm.functions.Function0"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier",
                methodName = "verify",
                parameterTypes = listOf("java.lang.String", "javax.net.ssl.SSLSession"),
                action = HookAction.RETURN_TRUE,
            ),
            HookSpec(
                className = "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier",
                methodName = "verify",
                parameterTypes = listOf("java.lang.String", "java.security.cert.X509Certificate"),
                action = HookAction.RETURN_TRUE,
            ),
            HookSpec(
                className = "com.datatheorem.android.trustkit.pinning.PinningTrustManager",
                methodName = "checkServerTrusted",
                parameterTypes = listOf("java.security.cert.X509Certificate[]", "java.lang.String"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "appcelerator.https.PinningTrustManager",
                methodName = "checkServerTrusted",
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "io.fabric.sdk.android.services.network.PinningTrustManager",
                methodName = "checkServerTrusted",
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "com.android.org.conscrypt.OpenSSLSocketImpl",
                methodName = "verifyCertificateChain",
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "com.android.org.conscrypt.OpenSSLEngineSocketImpl",
                methodName = "verifyCertificateChain",
                parameterTypes = listOf("java.lang.Long[]", "java.lang.String"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl",
                methodName = "verifyCertificateChain",
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "nl.xservices.plugins.sslCertificateChecker",
                methodName = "execute",
                parameterTypes = listOf("java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext"),
                action = HookAction.RETURN_TRUE,
            ),
            HookSpec(
                className = "com.worklight.wlclient.api.WLClient",
                methodName = "pinTrustedCertificatePublicKey",
                parameterTypes = listOf("java.lang.String"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "com.worklight.wlclient.api.WLClient",
                methodName = "pinTrustedCertificatePublicKey",
                parameterTypes = listOf("java.lang.String[]"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning",
                methodName = "verify",
                parameterTypes = listOf("java.lang.String", "javax.net.ssl.SSLSocket"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning",
                methodName = "verify",
                parameterTypes = listOf("java.lang.String", "java.security.cert.X509Certificate"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning",
                methodName = "verify",
                parameterTypes = listOf("java.lang.String", "java.lang.String[]", "java.lang.String[]"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning",
                methodName = "verify",
                parameterTypes = listOf("java.lang.String", "javax.net.ssl.SSLSession"),
                action = HookAction.RETURN_TRUE,
            ),
            HookSpec(
                className = "com.android.org.conscrypt.CertPinManager",
                methodName = "checkChainPinning",
                parameterTypes = listOf("java.lang.String", "java.util.List"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "com.android.org.conscrypt.CertPinManager",
                methodName = "isChainValid",
                parameterTypes = listOf("java.lang.String", "java.util.List"),
                action = HookAction.RETURN_TRUE,
            ),
            HookSpec(
                className = "com.commonsware.cwac.netsecurity.conscrypt.CertPinManager",
                methodName = "isChainValid",
                parameterTypes = listOf("java.lang.String", "java.util.List"),
                action = HookAction.RETURN_TRUE,
            ),
            HookSpec(
                className = "com.worklight.androidgap.plugin.WLCertificatePinningPlugin",
                methodName = "execute",
                parameterTypes = listOf("java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext"),
                action = HookAction.RETURN_TRUE,
            ),
            HookSpec(
                className = "io.netty.handler.ssl.util.FingerprintTrustManagerFactory",
                methodName = "checkTrusted",
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "org.jboss.netty.handler.ssl.util.FingerprintTrustManagerFactory",
                methodName = "checkTrusted",
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "com.squareup.okhttp.CertificatePinner",
                methodName = "check",
                parameterTypes = listOf("java.lang.String", "java.security.cert.Certificate"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "com.squareup.okhttp.CertificatePinner",
                methodName = "check",
                parameterTypes = listOf("java.lang.String", "java.util.List"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "com.squareup.okhttp.internal.tls.OkHostnameVerifier",
                methodName = "verify",
                parameterTypes = listOf("java.lang.String", "java.security.cert.X509Certificate"),
                action = HookAction.RETURN_TRUE,
            ),
            HookSpec(
                className = "com.squareup.okhttp.internal.tls.OkHostnameVerifier",
                methodName = "verify",
                parameterTypes = listOf("java.lang.String", "javax.net.ssl.SSLSession"),
                action = HookAction.RETURN_TRUE,
            ),
            HookSpec(
                className = "android.webkit.WebViewClient",
                methodName = "onReceivedSslError",
                parameterTypes = listOf("android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError"),
                action = HookAction.PROCEED_SSL_ERROR_HANDLER,
            ),
            HookSpec(
                className = "android.webkit.WebViewClient",
                methodName = "onReceivedError",
                parameterTypes = listOf("android.webkit.WebView", "int", "java.lang.String", "java.lang.String"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "android.webkit.WebViewClient",
                methodName = "onReceivedError",
                parameterTypes = listOf("android.webkit.WebView", "android.webkit.WebResourceRequest", "android.webkit.WebResourceError"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "org.apache.cordova.CordovaWebViewClient",
                methodName = "onReceivedSslError",
                parameterTypes = listOf("android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError"),
                action = HookAction.PROCEED_SSL_ERROR_HANDLER,
            ),
            HookSpec(
                className = "ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier",
                methodName = "verify",
                action = HookAction.RETURN_SAFE_DEFAULT,
            ),
            HookSpec(
                className = "org.apache.http.conn.ssl.AbstractVerifier",
                methodName = "verify",
                parameterTypes = listOf("java.lang.String", "java.security.cert.X509Certificate"),
                action = HookAction.RETURN_SAFE_DEFAULT,
            ),
            HookSpec(
                className = "org.apache.http.conn.ssl.AbstractVerifier",
                methodName = "verify",
                parameterTypes = listOf("java.lang.String", "javax.net.ssl.SSLSocket"),
                action = HookAction.RETURN_SAFE_DEFAULT,
            ),
            HookSpec(
                className = "org.apache.http.conn.ssl.AbstractVerifier",
                methodName = "verify",
                parameterTypes = listOf("java.lang.String", "javax.net.ssl.SSLSession"),
                action = HookAction.RETURN_TRUE,
            ),
            HookSpec(
                className = "org.apache.http.conn.ssl.AbstractVerifier",
                methodName = "verify",
                parameterTypes = listOf("java.lang.String", "java.lang.String[]", "java.lang.String[]", "boolean"),
                action = HookAction.RETURN_SAFE_DEFAULT,
            ),
            HookSpec(
                className = "org.chromium.net.impl.CronetEngineBuilderImpl",
                methodName = "enablePublicKeyPinningBypassForLocalTrustAnchors",
                parameterTypes = listOf("boolean"),
                action = HookAction.FORCE_ARG0_TRUE,
            ),
            HookSpec(
                className = "diefferson.http_certificate_pinning.HttpCertificatePinning",
                methodName = "checkConnexion",
                parameterTypes = listOf("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String"),
                action = HookAction.RETURN_TRUE,
            ),
            HookSpec(
                className = "com.macif.plugin.sslpinningplugin.SslPinningPlugin",
                methodName = "checkConnexion",
                parameterTypes = listOf("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String"),
                action = HookAction.RETURN_TRUE,
            ),
            HookSpec(
                className = "com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor",
                methodName = "intercept",
                action = HookAction.PROCEED_INTERCEPTOR_CHAIN,
            ),
            HookSpec(
                className = "com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager",
                methodName = "checkServerTrusted",
                parameterTypes = listOf("java.security.cert.X509Certificate[]", "java.lang.String"),
                action = HookAction.SKIP_VOID,
            ),
            HookSpec(
                className = "com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager",
                methodName = "checkServerTrusted",
                parameterTypes = listOf("java.security.cert.X509Certificate[]", "java.lang.String", "java.lang.String"),
                action = HookAction.RETURN_EMPTY_LIST,
            ),
        )
    }
}
