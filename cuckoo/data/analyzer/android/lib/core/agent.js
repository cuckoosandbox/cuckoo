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
    const category = hookConfig.category;
    const onMethodExited = makeJavaMethodImplCallback(className, methodName, category);

    try {
        const klass = Java.use(className);
        const overloads = klass[methodName].overloads;

        overloads.forEach(method => {
            if (method.implementation === null) {
                method.implementation = function () {
                    const returnValue = method.apply(this, arguments);

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
 * Make generic implementation callback function for a Java method.
 * 
 * @param className Method's class name.
 * @param methodName Method name.
 * @param category Category of API call.
 */
function makeJavaMethodImplCallback (className, methodName, category) {
    return function (thisObject, args, returnValue) {
        const hookData = {
            "class": className,
            "method": methodName,
            "category": category,
            "time": new Date().toString(),
            "args": Array.from(args).map(unboxGenericObjectValue),
            "this": unboxGenericObjectValue(thisObject),
            "returnValue": unboxGenericObjectValue(returnValue),
        };

        const Thread = Java.use("java.lang.Thread");
        const stackElements = Thread.currentThread().getStackTrace();
        const callStack = stackElements.map((elem) => elem.getMethodName());
        const currentCallIdx = callStack.findIndex((call) => call === methodName);
        const isCalledFromOverload = callStack[currentCallIdx] === callStack[currentCallIdx-1];

        if (!isCalledFromOverload) {
            LOG("jvmHook", hookData, true);
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

        const jObject = Java.cast(obj, Java.use(obj.$className));
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
            return hexdump(new Int8Array(obj).buffer);
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
            "java.net.HttpURLConnection",
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
            }
        };

        this.unboxJavaLangReflectMethod = function (methodObj) {
            const class_name = Java.cast(methodObj.getDeclaringClass(), javaLangClass).getName();
            return {
                "class_name": class_name,
                "method_name": methodObj.getName()
            }
        };

        this.unboxJavaLangReflectField = function (fieldObj) {
            const class_name = Java.cast(fieldObj.getDeclaringClass(), javaLangClass).getName();
            return {
                "class_name": class_name,
                "field_name": fieldObj.getName()
            }
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

        this.unboxJavaNetHttpURLConnection = function (httpObj) {
            return {
                "url": unboxGenericObjectValue(httpObj.getURL()),
                "request_method": httpObj.getRequestMethod(),
                "header_fields": unboxGenericObjectValue(httpObj.getHeaderFields()),
                "response_code": httpObj.getResponseCode(),
                "response": httpObj.getResponseMessage()
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
            return {
                "action": intentObj.getAction(),
                "data": intentObj.getDataString(),
                "package": intentObj.getPackage(),
                "type": intentObj.getType(),
                "component": intentObj.getComponent().flattenToString(),
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
            return unboxGenericObjectValue(bundleObj);
        };

        this.unboxAndroidContentContentValues = function (valuesObj) {
            return unboxGenericObjectValue(valuesObj);
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

class JavaHookConfig {
    constructor (className, methodName, category) {
        this.class = className;
        this.method = methodName;
        this.category = category;
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

/** 
 * Utility method for forwarding messages/ events to Frida's client.
 * All messages to the client are sent via this.
 * 
 * @param eventType Type of message/ event.
 * @param message The payload.
 * @param sendPid Send process id as source of event.
 */
function LOG (eventType, message, sendPid=false) {
    if (eventType === "error") {
        setTimeout(() => { throw message; }, 0);
    } else {
        if (typeof message === "object") {
            message = JSON.stringify(message);
        }

        if (sendPid) {
            send(eventType + "\n" + Process.id + "\n" + message);
        } else {
            send(eventType + "\n" + message);
        }
    }
}

/**
 * Bootstrapping procedure for java runtime analysis.
 */
function init_jvm (jvmHooksConfig) {
    Java.performNow(function () {
        // Load hooks from configuration object.
        jvmHooksConfig.forEach(hookConfig => {
            const javaHookConfig = new JavaHookConfig(
                hookConfig.class,
                hookConfig.method,
                hookConfig.category
            );
            monitorJavaMethod(javaHookConfig);
        });
    });
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

    /* Check if file exists */
    const exists = function (fpathPtr) {
        const maxStatStructSize = 20 * 8;
        const statStruct = Memory.alloc(maxStatStructSize);
        return lstat(fpathPtr, statStruct) === 0;
    };

    /* Neutralize unlink calls */
    Interceptor.replace(unlinkPtr, new NativeCallback(
        function (pathnamePtr) {
            LOG("fileDelete", ptr(pathnamePtr).readUtf8String());
        },
        "int",
        ["pointer"]
    ));
    Interceptor.replace(unlinkatPtr, new NativeCallback(
        function (dirfd, pathnamePtr, flags) {
            LOG("fileDelete", ptr(pathnamePtr).readUtf8String());
        },
        "int",
        ["int", "pointer", "int"]
    ));

    /* Notify when a file is about to be created */
    Interceptor.attach(openPtr, {
        onEnter: function (args) {
            const createIfNotFound = args[1].toInt32() & 0o100 !== 0;

            if (!exists(args[0]) && createIfNotFound) {
                LOG("fileDrop", args[0].readUtf8String());
            }
        }
    });
    Interceptor.attach(openatPtr, {
        onEnter: function (args) {
            const createIfNotFound = args[2].toInt32() & 0o100 !== 0;

            if (!exists(args[1]) && createIfNotFound) {
                LOG("fileDrop", args[1].readUtf8String());
            }
        }
    });
    Interceptor.attach(creatPtr, {
        onEnter: function (args) {
            if (!exists(args[0])) {
                LOG("fileDrop", args[0].readUtf8String());
            }
        }
    });

    /* Notify when a file is about to get relocated */
    Interceptor.attach(renamePtr, {
        onEnter: function (args) {
            const message = args[0].readUtf8String() + "," +
                            args[1].readUtf8String();
            LOG("fileMoved", message);
        }
    });
    Interceptor.attach(renameatPtr, {
        onEnter: function (args) {
            const message = args[1].readUtf8String() + "," +
                            args[3].readUtf8String();
            LOG("fileMoved", message);
        }
    });
}

var api = new Api();

rpc.exports = {
    api: function (api_method, args) {
        return api[api_method].apply(this, args);
    },
    start: function (configs) {
        init();

        if (Java.available) {
            init_jvm(configs["jvm_hooks"]);
        }
    }
};
