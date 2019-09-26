/**
 * Copyright (C) 2019 Cuckoo Foundation.
 * This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
 * See the file 'docs/LICENSE' for copying permission.
 */

'use strict';

/**
 * Exported methods for the Frida RPC client.
 */
class Api {
    constructor () {
        this.getCurrentProcessInfo = function () {
            const getppid = new NativeFunction(
                Module.findExportByName(null, "getppid"), "int", []
            );
            const getuid = new NativeFunction(
                Module.findExportByName(null, "getuid"), "int", []
            );

            return {
                "ppid": getppid(),
                "uid": getuid()
            };
        };
    }
}

/**
 * Replace the implementation of a Java method in order to monitor calls
 * made to the Android API. Needs to be called from a thread attached 
 * to the VM.
 * 
 * @param {JavaHookConfig} hookConfig Configuration object for the hook.
 */
function monitorJavaMethod (hookConfig) {
    const className = hookConfig.class;
    const methodName = hookConfig.method;
    const onMethodExited = makeJavaMethodImplCallback(hookConfig);

    try {
        const klass = Java.use(className);
        const overloads = klass[methodName].overloads;

        overloads.forEach(overload => {
            if (overload.implementation === null) {
                overload.implementation = function () {
                    const returnValue = overload.apply(this, arguments);

                    try {
                        onMethodExited(this, arguments, returnValue);
                    } catch (e) {
                        LOG("error", e);
                    }
                    return returnValue;
                };
            }
        });
    } catch (e) {
        LOG("error", e);
    }
}

/**
 * Create a hookData object for a Java method.
 * 
 * @param {JavaHookConfig} hookConfig
 * @param {Array} args
 * @param {Object} thisObject
 * @param {Object} returnValue
 */
function makeJavaMethodHookData (hookConfig, args, thisObject, returnValue) {
    let unwrappedArguments;
    if (args !== null && args !== undefined) {
        unwrappedArguments = Array.from(args).map(unboxGenericObjectValue);
    }

    const unwrappedSelf = unboxGenericObjectValue(thisObject);
    const unwrappedReturnValue = unboxGenericObjectValue(returnValue);

    return new JavaHookData(
        hookConfig, unwrappedArguments, unwrappedSelf, unwrappedReturnValue
    );
}

/**
 * Make generic implementation callback function for a Java method.
 * 
 * @param {JavaHookConfig} hookConfig
 */
function makeJavaMethodImplCallback (hookConfig) {
    return function (thisObject, args, returnValue) {
        const hookData = makeJavaMethodHookData(hookConfig, args, thisObject, returnValue);
        const methodName = hookConfig.method;

        const Thread = Java.use("java.lang.Thread");
        const stackElements = Thread.currentThread().getStackTrace();
        const callStack = stackElements.map((elem) => elem.getMethodName());
        const currentCallIdx = callStack.findIndex((call) => call === methodName);
        const isCalledFromOverload = callStack[currentCallIdx] === callStack[currentCallIdx-1];

        if (!isCalledFromOverload) {
            LOG("jvmHook", hookData);
        }
    }
}

/** 
 * Extracts the value of an object obtained from the runtime.
 */
function unboxGenericObjectValue (obj) {
    if (obj === null || obj === undefined) {
        return null;
    }

    if (obj.$className !== undefined) {
        /* java type */
        if (!obj.hasOwnProperty("$handle")) {
            return null;
        }

        let objKlass;
        const contextClassLoader = Java.classFactory.loader;
        for (const loader of cachedClassLoaders) {
            Java.classFactory.loader = loader;

            try {
                objKlass = Java.use(obj.$className);
            } catch (e) {
                /* class not found exception - try another class loader */
            }
        }
        Java.classFactory.loader = contextClassLoader;

        if (!objKlass) {
            return null;
        }

        const jObject = Java.cast(obj, objKlass);
        const typesParser = new JavaTypesParser();
        return typesParser.parse(jObject);
    } else if (Array.isArray(obj)) {
        /* non-primitive array */
        return obj.map(elem => unboxGenericObjectValue(elem));
    } else if (obj.type === "byte") {
        /* primitive byte array */
        if (isAsciiString(obj)) {
            const String = Java.use("java.lang.String");
            return String.$new(obj).toString();
        } else {
            return Array.from(obj, function(b) {
                return ("0" + (b & 0xFF).toString(16)).slice(-2);
            }).join("");
        }
    } else {
        return obj;
    }
}

class JavaTypesParser {
    constructor () {
        const parseableAbstractClasses = [
            "java.util.Set",
            "java.util.Map",
            "java.util.List",
            "android.net.Uri",
        ]
        .map(type => Java.use(type));

        const primitiveTypes = {
            "Z": "boolean",
            "B": "byte",
            "C": "char",
            "D": "double",
            "F": "float",
            "I": "int",
            "J": "long",
            "S": "short",
        };

        const javaLangReflectArray = Java.use("java.lang.reflect.Array");
        const javaLangClass = Java.use("java.lang.Class");

        this.parse = function (obj) {
            const className = obj.$className;
            if (className.indexOf("[") === 0) { /* unwrapped array object */
                const result = [];
                const elementType = className.substring(1);
                const length = javaLangReflectArray.getLength(obj);

                let getFromArray = "get";
                if (elementType[elementType.length - 1] !== ";" && elementType[0] !== "[") {
                    if (primitiveTypes.hasOwnProperty(elementType)) {
                        getFromArray += capitalizeTypeName(primitiveTypes[elementType]);
                    }
                }
                for (let i = 0; i < length; i++) {
                    const element = javaLangReflectArray[getFromArray](obj, i);
                    result.push(unboxGenericObjectValue(element));
                }
                return result
            } else {
                let handler = "unbox" + capitalizeTypeName(className);
                if (!this.hasOwnProperty(handler)) {
                    handler = null;
                    for (const klass of parseableAbstractClasses) {
                        if (klass.class.isInstance(obj)) {
                            handler = "unbox" + capitalizeTypeName(klass.$className);
                            break
                        }
                    }
                }

                let result = obj.toString();
                if (handler !== null) {
                    result = this[handler](obj);
                }
                return result;
            }
        };

        this.unboxJavaLangClass = function (classObj) {
            return {
                "class_name": classObj.getName() 
            };
        };

        this.unboxJavaLangReflectMethod = function (methodObj) {
            const class_name = Java.cast(methodObj.getDeclaringClass(), javaLangClass).getName();
            return {
                "class_name": class_name,
                "method_name": methodObj.getName()
            };
        };

        this.unboxJavaLangReflectField = function (fieldObj) {
            const class_name = Java.cast(fieldObj.getDeclaringClass(), javaLangClass).getName();
            return {
                "class_name": class_name,
                "field_name": fieldObj.getName()
            };
        };

        this.unboxJavaIoFile = function (fileObj) {
            return {
                "path": fileObj.getAbsolutePath()
            };
        };

        this.unboxAndroidAppSharedPreferencesImplEditorImpl = function (editorObj) {
            return {
                "filepath": unboxGenericObjectValue(editorObj.this$0.value.mFile.value)
            };
        };

        this.unboxAndroidDatabaseSqliteSQLiteDatabase = function (sqliteObj) {
            return {
                "filepath": sqliteObj.getPath()
            };
        };

        this.unboxJavaLangProcessBuilder = function (builderObj) {
            const command = unboxGenericObjectValue(builderObj.command).join(" ");
            return { command };
        };

        this.unboxAndroidContentIntentFilter = function (filterObj) {
            const actions = unboxGenericObjectValue(filterObj.actionsIterator());
            return { actions };
        };

        this.unboxJavaNetURL = function (urlObj) {
            return urlObj.toString();
        };

        this.unboxAndroidNetUri = function (uriObj) {
            return uriObj.toString();
        };

        this.unboxJavaNetURI = function (uriObj) {
            return uriObj.toString();
        };

        this.unboxAndroidContentIntent = function (intentObj) {
            let componentToString = null;
            if (intentObj.getComponent() !== null) {
                componentToString = intentObj.getComponent().flattenToString();
            }

            return {
                "action": intentObj.getAction(),
                "data": intentObj.getDataString(),
                "package": intentObj.getPackage(),
                "type": intentObj.getType(),
                "component": componentToString,
                "extras": unboxGenericObjectValue(intentObj.getExtras())
            };
        };

        this.unboxAndroidAppActivityThreadReceiverData = function (rcvDataObj) {
            return {
                "intent": unboxGenericObjectValue(rcvDataObj.intent.value),
                "package": rcvDataObj.info.value.packageName.value,
                "result_data": rcvDataObj.getResultData(),
                "result_code": rcvDataObj.getResultCode()
            };
        };

        this.unboxJavaUtilSet = function (setObj) {
            return unboxGenericObjectValue(setObj.iterator());
        };

        this.unboxAndroidOsBundle = function (bundleObj) {
            return this.unboxJavaUtilMap(bundleObj);
        };

        this.unboxAndroidContentContentValues = function (valuesObj) {
            return this.unboxJavaUtilMap(valuesObj);
        };

        this.unboxJavaUtilIterator = function (iteratorObj) {
            const result = [];
            while (iteratorObj.hasNext()) {
                result.push(unboxGenericObjectValue(iteratorObj.next()));
            }
            return result;
        };

        this.unboxJavaUtilList = function (listObj) { 
            const result = [];
            for (let i = 0; i < listObj.size(); i++) {
                result.push(unboxGenericObjectValue(listObj.get(i)));
            }
            return result;
        };

        this.unboxJavaUtilMap = function (mapObj) {
            const keys = [];
            const iterator = mapObj.keySet().iterator();
            while (iterator.hasNext()) {
                keys.push(iterator.next())
            }

            const result = {};
            keys.forEach(aKey => {
                const key = unboxGenericObjectValue(aKey);
                const value = unboxGenericObjectValue(mapObj.get(aKey));
                result[key] = value;
            });
            return result;
        };
    }
}

function loadOkHttpHook () {
    const httpUrlConnectionImplClassName = "com.android.okhttp.internal.huc.HttpURLConnectionImpl";
    try {
        Java.use(httpUrlConnectionImplClassName);
    } catch (e) {
        return;  /* class not found. */
    }

    const RetryableSink = Java.use("com.android.okhttp.internal.http.RetryableSink");
    const HttpUrlConnectionImpl = Java.use(httpUrlConnectionImplClassName);

    const hookConfig = new JavaHookConfig(httpUrlConnectionImplClassName, "execute", "network");
    HttpUrlConnectionImpl.execute.implementation = function (readResponse) {
        this.httpEngine.value.bufferRequestBody.value = true;
        const returnValue = this.execute(readResponse);
        const originalRequest = this.httpEngine.value.networkRequest(this.httpEngine.value.getRequest());
        const body = Java.cast(this.httpEngine.value.getRequestBody(), RetryableSink);

        const self = {};
        self["url"] = unboxGenericObjectValue(this.getURL());
        self["request_method"] = this.getRequestMethod();
        self["request_headers"] = originalRequest.headers().toString();
        self["request_body"] = unboxGenericObjectValue(body.content.value.readByteArray());
        self["response_headers"] = unboxGenericObjectValue(this.getHeaderFields());
        self["response_code"] = this.getResponseCode();
        self["response_message"] = this.getResponseMessage();

        const hookData = makeJavaMethodHookData(hookConfig, arguments, null, returnValue);
        hookData.thisObject = self;
        LOG("jvmHook", hookData);

        return returnValue;
    };
}

function loadOkHttp3Hook () {
    const builderClassName = "okhttp3.OkHttpClient$Builder";
    try {
        Java.use(builderClassName);
    } catch (e) {
        return;  /* class not found. */
    }

    const Buffer = Java.use("com.android.okhttp.okio.Buffer");
    const Interceptor = Java.use("okhttp3.Interceptor");

    const hookConfig = new JavaHookConfig(okhttpClientClassName, "", "network");
    const TrafficLoggerInterceptor = Java.registerClass({
        name: "okhttp3.TrafficLoggerInterceptor",
        implements: [Interceptor],
        methods: {
            intercept: function(chain) {
                const request = chain.request();
                const requestBody = request.body();
                if (requestBody) {
                    const buffer = Buffer.$new();
                    try {
                        requestBody.writeTo(buffer);
                        self["request_body"] = unboxGenericObjectValue(buffer.readByteArray());
                    } catch (e) {
                        LOG("error", e);
                    }
                }

                const self = {};
                self["url"] = unboxGenericObjectValue(request.url().url());
                self["request_method"] = request.method();
                self["request_headers"] = request.headers().toString();

                const response = chain.proceed(request);

                self["response_code"] = response.code();
                self["response_headers"] = response.headers().toString();
                self["response_message"] = response.message();

                const hookData = makeJavaMethodHookData(hookConfig, null, null, null);
                hookData.thisObject = self;
                LOG("jvmHook", hookData);

                return response;
            }
        }
    });

    const Builder = Java.use(builderClassName);
    Builder.build.implementation = function() {
        this.interceptors().add(TrafficLoggerInterceptor.$new());
        return this.build();
    };
}

class JavaHookConfig {
    constructor (className, methodName, category) {
        this.class = className;
        this.method = methodName;
        this.category = category;
    }
}

class JavaHookData {
    constructor (hookConfig, args, thisObject, returnValue) {
        this.class = hookConfig.class;
        this.method = hookConfig.method;
        this.category = hookConfig.category;

        this.args = args;
        this.thisObject = thisObject;
        this.returnValue = returnValue;
        this.time = new Date().toString();
    }
}

function capitalizeTypeName (typeName) {
    return typeName
            .split(/[.$]/)
            .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
            .join("");
}

function isAsciiString (byteArray) {
    for (let i = 0; i < byteArray.length; i++) {
        const byte = byteArray[i];
        if (!(byte > 31 && byte < 127)) {
            return false;
        }
    }
    return true;
}

function pick (iterable) {
    let result;
    if (Array.isArray(iterable)) {
        result = iterable[Math.floor(Math.random() * iterable.length)];
    } else if (typeof iterable === "string") {
        result = iterable.charAt(Math.floor(Math.random() * iterable.length))
    }
    return result;
}

function generateRandomNumber(length, isHex=false) {
    let characters = "0123456789";
    if (isHex) {
        characters += "abcdef";
    }

    let result = "";
    for (let i = 0; i < length; i++) {
        result += pick(characters);
    }
    return result;
}

/** 
 * Utility method for forwarding messages/ events to Frida's client.
 * All messages to the client are sent via this.
 * 
 * @param eventType Type of message/ event.
 * @param message The payload.
 */
function LOG (eventType, message) {
    if (eventType === "error") {
        setTimeout(() => { throw message; }, 0);
    } else {
        if (typeof message === "object") {
            message = JSON.stringify(message);
        }

        send(eventType + "\n" + Process.id + "\n" + message);
    }
}

function applyPostAppLoadingInstrumentation () {
    loadOkHttp3Hook();
}

/**
 * Bootstrapping procedure for java runtime analysis.
 */
function applyPreAppLoadingInstrumentation (jvmHooksConfig) {
    setupEnv();
    hookDexClassLoaders();
    bypassCertificatePinning();

    loadOkHttpHook();

    /* Load hooks from configuration object */
    jvmHooksConfig.forEach(hookConfig => {
        const javaHookConfig = new JavaHookConfig(
            hookConfig.class, hookConfig.method, hookConfig.category
        );
        monitorJavaMethod(javaHookConfig);
    });
}

function bypassCertificatePinning() {
    const CertificateFactory = Java.use("java.security.cert.CertificateFactory");
    const FileInputStream = Java.use("java.io.FileInputStream");
    const BufferedInputStream = Java.use("java.io.BufferedInputStream");
    const KeyStore = Java.use("java.security.KeyStore");
    const TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
    const SSLContext = Java.use("javax.net.ssl.SSLContext");

    /* Load the certificate authority */
    let fis;
    try {
        fis = FileInputStream.$new("/data/local/tmp/cert.crt");
    } catch (e) {
        /* File not found exception */
        return;
    }
    const bis = BufferedInputStream.$new(fis);
    bis.close();

    const ca = CertificateFactory.getInstance("X.509").generateCertificate(bis);

    /* Create a KeyStore with the certificate */
    const keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    keyStore.setCertificateEntry("ca", ca);

    /* Create a TrustManagerFactory for the KeyStore */
    const tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.$init(keyStore);

    SSLContext.$init.implementation = function(keyMgr, trustMgrs, secureRandom) {
        SSLContext.$init(keyMgr, tmf.getTrustManagers(), secureRandom);
    };
}

function hookDexClassLoaders () {
    const loaders = [
        "dalvik.system.PathClassLoader",
        "dalvik.system.DexClassLoader",
        "dalvik.system.InMemoryDexClassLoader"
    ];

    loaders.forEach(loaderClassName => {
        const loaderKlass = Java.use(loaderClassName);
        const hookConfig = new JavaHookConfig(loaderClassName, "$init", "dynload");
        loaderKlass.$init.overloads.forEach(overload => {
            overload.implementation = function () {
                cachedClassLoaders.push(Java.retain(this));

                const returnValue = overload.apply(this, arguments);
                LOG("jvmHook", makeJavaMethodHookData(hookConfig, arguments, this, returnValue));
                return returnValue;
            };
        });
    });
}

/**
 * Setup the emulated environment to hinder emulation detection.
 */
function setupEnv () {
    const patchMethodCall = function (hookConfig, returnValuePatch) {
        const klass = Java.use(hookConfig.class);
        if (!klass.hasOwnProperty(hookConfig.method)) {
            return;
        }

        klass[methodName].overloads[0].implementation = function () {
            let returnValue;
            if (typeof returnValuePatch === "function") {
                returnValue = returnValuePatch(arguments, this);
            } else {
                returnValue = returnValuePatch;
            }
            LOG("jvmHook", makeJavaMethodHookData(hookConfig, arguments, this, returnValue));
            return returnValue;
        };
    };

    const insertCheckDigit = function(number) {
        /* Luhn algorithm */
        let checksum = 0;
        for (let i = 1; i < 15; i++) {
            if (i % 2 === 0) {
                let digitValue = (2 * number[i-1]).toString();
                if (digitValue.length === 2) {
                    checksum += parseInt(digitValue[0]) + parseInt(digitValue[1]);
                } else {
                    checksum += parseInt(digitValue);
                }
            } else {
                checksum += parseInt(number[i-1]);
            }
        }

        let checkdigit = 0; 
        if ((checksum % 10) > 0) {
            checkdigit = 10 - (checksum % 10);
        }
        return number + checkdigit.toString();
    };

    const mcc = "310";
    const mncs = ["170", "150", "680", "070", "560", "410", "380", "980"];
    const areaCodes = [
        "518", "410", "404", "207", "512", "225", "701", "208", "617",
        "775", "843", "307", "803", "614", "603", "303", "515", "302",
        "502", "717", "860", "406", "808", "317", "601", "904", "573",
        "385", "505", "417", "850", "785", "609", "202"
    ];

    const mnc = pick(mncs);
    const areaCode = pick(areaCodes);
    const randomImei = insertCheckDigit(generateRandomNumber(14));
    const randomPhoneNumber = "1" + areaCode + generateRandomNumber(7);
    const randomSubscriberId = mcc + mnc + generateRandomNumber(9);
    const randomSimSerialNumber = insertCheckDigit("89" + mcc + mnc + generateRandomNumber(11));

    const qemuProps = [
        "init.svc.qemu-props", "init.svc.qemud", "qemu.hw.mainkeys",
        "qemu.sf.fake_camera", "qemu.sf.lcd_density", "ro.kernel.android.qemud",
        "ro.kernel.qemu.gles", "ro.kernel.qemu", "qemu.adbd", "qemu.cmdline",
        "qemu.gles", "qemu.logcat", "qemu.timezone", "ro.boottime.qemu-props",
        "ro.kernel.qemu.wifi", "ro.kernel.qemu.settings.system.screen_off_timeout",
        "ro.kernel.qemu.opengles.version", "ro.kernel.qemu.encrypt", 
        "ro.kernel.qemu.dalvik.vm.heapsize"
    ];
    const serialnoProps = [
        "ro.serialno", "ro.boot.serialno", "ro.kernel.androidboot.serialno"
    ];
    const productProps = [
        "ro.product.name", "ro.product.device", "ro.build.product", "ro.product.board"
    ];

    const knownQemuFiles = [
        "/dev/qemu_pipe", "/dev/socket/qemud", "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace", "/system/bin/qemu-props", "/init.goldfish.rc",
        "/vendor/bin/qemu-props", "/dev/__properties__/u:object_r:qemu_cmdline:s0",
        "/dev/__properties__/u:object_r:qemu_prop:s0"  
    ];

    const Location = Java.use("android.location.Location");
    const fakeLocation = Location.$new("gps");
    fakeLocation.setLatitude(37.09);
    fakeLocation.setLongitude(95.71);

    const fakeMacAddress = generateRandomNumber(12, true)
                            .toUpperCase()
                            .split(/(?=(?:..)*$)/)
                            .join(":");

    /* Modify android.os.Build fields */
    const Build = Java.use("android.os.Build");
    Build.BOARD.value = "taimen";
    Build.MODEL.value = "Pixel 2 XL";
    Build.BOOTLOADER.value = "TMZ20j";
    Build.DEVICE.value = "taimen";
    Build.PRODUCT.value = "taimen";
    Build.HARDWARE.value = "taimen";
    Build.FINGERPRINT.value = "google/taimen/taimen:9/PPR1.180610.011/4904810:user/release-keys";
    Build.HOST.value = "wphl1.hot.corp.google.com";
    Build.ID.value = "PPR1.180610.011";
    Build.MANUFACTURER.value = "Google";
    Build.TAGS.value = "release-keys";
    Build.SERIAL.value = Build.UNKNOWN.value;

    const spoofSystemProperties = function (args, self) {
        const key = args[0];

        let result;
        if (qemuProps.indexOf(key) !== -1) {
            result = null;
        } else if (serialnoProps.indexOf(key) !== -1) {
            result = Build.SERIAL.value;
        } else if (productProps.indexOf(key) !== -1) {
            result = Build.PRODUCT.value;
        } else if (key === "ro.hardware") {
            result = Build.HARDWARE.value;
        } else if (key === "ro.product.model") {
            result = Build.MODEL.value;
        } else if (key === "ro.bootloader") {
            result = Build.BOOTLOADER.value;
        } else if (key === "ro.build.fingerprint" || 
                   key === "ro.bootimage.build.fingerprint") {
            result = Build.FINGERPRINT.value;
        } else if (key === "ro.product.manufacturer") {
            result = Build.MANUFACTURER.value;
        } else if (key === "ro.build.id" || key === "ro.build.display.id") {
            result = Build.ID.value;
        } else if (key === "ro.product.model") {
            result = Build.MODEL.value;
        } else if (key === "ro.build.tags") {
            result = Build.TAGS.value;
        } else if (key === "ro.build.host") {
            result = Build.HOST.value;
        } else {
            result = self.get(key);
        }
        return result;
    };

    const spoofFileCheck = function (args, self) {
        const filepath = self.getAbsolutePath();
        if (knownQemuFiles.indexOf(filepath) !== -1) {
            return false;
        } else {
            return self.exists();
        }
    };

    /* Patch framework APIs */
    const patches = [
        [new JavaHookConfig("android.telephony.TelephonyManager", "getLine1Number", "service"), randomPhoneNumber],
        [new JavaHookConfig("android.telephony.TelephonyManager", "getDeviceId", "service"), randomImei],
        [new JavaHookConfig("android.telephony.TelephonyManager", "getSubscriberId", "service"), randomSubscriberId],
        [new JavaHookConfig("android.telephony.TelephonyManager", "getImei", "service"), randomImei],
        [new JavaHookConfig("android.telephony.TelephonyManager", "getMeid", "service"), null],
        [new JavaHookConfig("android.telephony.TelephonyManager", "getNetworkOperatorName", "service"), "AT&T"],
        [new JavaHookConfig("android.telephony.TelephonyManager", "getSimOperatorName", "service"), "AT&T"],
        [new JavaHookConfig("android.telephony.TelephonyManager", "getNetworkCountryIso", "service"), "us"],
        [new JavaHookConfig("android.telephony.TelephonyManager", "getSimCountryIso", "service"), "us"],
        [new JavaHookConfig("android.telephony.TelephonyManager", "getPhoneType", "service"), 1],
        [new JavaHookConfig("android.telephony.TelephonyManager", "getNetworkOperator", "service"), mcc + mnc],
        [new JavaHookConfig("android.telephony.TelephonyManager", "getSimSerialNumber", "service"), randomSimSerialNumber],
        [new JavaHookConfig("android.telephony.TelephonyManager", "getVoiceMailNumber", "service"), randomPhoneNumber],
        [new JavaHookConfig("android.app.ActivityManager", "isUserAMonkey", "service"), false],
        [new JavaHookConfig("android.os.Build", "getSerial", "content"), Build.SERIAL.value],
        [new JavaHookConfig("android.os.SystemProperties", "get", "content"), spoofSystemProperties],
        [new JavaHookConfig("java.io.File", "exists", "file"), spoofFileCheck],
        [new JavaHookConfig("android.location.LocationManager", "getLastKnownLocation", "service"), fakeLocation],
        [new JavaHookConfig("android.net.wifi.WifiInfo", "getMacAddress", "network"), fakeMacAddress]
    ];
    patches.forEach((patch) => patchMethodCall.apply(this, patch));
}

/**
 * Bootstrapping procedure for the analysis.
 */
function init () {
    /* Exported symbols */
    const unlinkPtr = Module.findExportByName(null, "unlink");
    const unlinkatPtr = Module.findExportByName(null, "unlinkat");
    const openPtr = Module.findExportByName(null, "open");
    const openatPtr = Module.findExportByName(null, "openat");
    const creatPtr = Module.findExportByName(null, "creat");
    const lstatPtr = Module.findExportByName(null, "lstat");
    const renamePtr = Module.findExportByName(null, "rename");
    const renameatPtr = Module.findExportByName(null, "renameat");

    /* Native functions */
    const lstat = new NativeFunction(lstatPtr, "int", ["pointer", "pointer"]);

    /* lstat() wrapper */
    const fileExists = function (filepathPtr) {
        const maxStatStructSize = 20 * 8;
        const statStruct = Memory.alloc(maxStatStructSize);

        return lstat(filepathPtr, statStruct) === 0;
    };

    /* Neutralize unlink[at]() calls */
    const unlinkImplCallback = function (filepath) {
        LOG("fileDelete", ptr(filepath).readUtf8String());
    };
    Interceptor.replace(unlinkPtr, new NativeCallback(
        function (pathname) { unlinkImplCallback(pathname); return 0; },
        "int",
        ["pointer"]
    ));
    Interceptor.replace(unlinkatPtr, new NativeCallback(
        function (dirfd, pathname, flags) { unlinkImplCallback(pathname); return 0; },
        "int",
        ["int", "pointer", "int"]
    ));

    /* Intercept open[at]() calls */
    const openInterceptCallback = function (filepathParam, flagsParam) {
        const flags = flagsParam.toInt32();
        const filepath = filepathParam.readUtf8String();

        if (!fileExists(filepathParam) && (flags & 0o100) !== 0) {
            LOG("fileCreate", filepath);
        }

        if (!filepath.includes("frida")) {
            if ((flags & 0o3) === 0 || (flags & 0o2) !== 0) {
                LOG("fileRead", filepath);
            }

            if ((flags & 0o1) !== 0 || (flags & 0o2) !== 0) {
                LOG("fileWrite", filepath);
            }
        }
    };
    Interceptor.attach(openPtr, {
        onEnter: function (args) { openInterceptCallback(args[0], args[1]); }
    });
    Interceptor.attach(openatPtr, { 
        onEnter: function (args) { openInterceptCallback(args[1], args[2]); }
    });

    /* Intercept creat() calls */
    Interceptor.attach(creatPtr, {
        onEnter: function (args) {
            if (!fileExists(args[0])) {
                LOG("fileCreate", args[0].readUtf8String());
            }
        }
    });

    /* Intercept rename[at]() calls */
    const renameInterceptCallback = function (oldfilepathParam, newfilepathParam) {
        const oldfilepath = oldfilepathParam.readUtf8String();
        const newfilepath = newfilepathParam.readUtf8String();

        LOG("fileMoved", oldfilepath + "," + newfilepath);
    };
    Interceptor.attach(renamePtr, {
        onEnter: function (args) { renameInterceptCallback(args[0], args[1]); }
    });
    Interceptor.attach(renameatPtr, {
        onEnter: function (args) { renameInterceptCallback(args[1], args[3]); }
    });
}

var api = new Api();
var cachedClassLoaders = [];

rpc.exports = {
    api: function (api_method, args) {
        return api[api_method].apply(this, args);
    },
    start: function (configs) {
        init();

        if (Java.available) {
            cachedClassLoaders.push(Java.classFactory.loader);

            Java.performNow(function () {
                applyPreAppLoadingInstrumentation(configs["jvm_hooks"]);
            });

            Java.perform(function () {
                cachedClassLoaders.push(Java.classFactory.loader);
                applyPostAppLoadingInstrumentation();
            });
        }
    }
};
