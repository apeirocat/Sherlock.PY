import os,sys
import threading
import hashlib,hmac
import functools 
import time
import ctypes
"""
SHERLOCK BY APEIROCAT

Utility for generating hardware specific hashes, doing automatic integrity checks and more.

THANK YOU FOR USING SHERLOCK!
"""



SETTINGS_LOCKED = "SHERLOCK_SETTINGS_NOT_LOCKED"

CHECKS = []
checks_hash = ""
CONSTANT_LIST = {}
__autochkthread = None
HASH_LIST = {}
hashlist_hash = ""
AUTOCHECK_CONFIG = []

AUDITHOOK_LIST = []
audithook_hash = ""


_SECRET = hashlib.sha256(
    f"{id(object)}{time.perf_counter_ns()}".encode()
).hexdigest()


_REAL_EXIT = os._exit
_REAL_COMPARE = hmac.compare_digest

class AUDIT_HOOK_FUNCTIONS():
    def LOCK_IMPORTS(event,args):
        if "import" in event:
                print("imports")
                raise RuntimeError("Imports locked by sherlock.")
    def LOCK_TRACE(event,args):
        if "settrace" in event:
                print("trace")
                raise RuntimeError("settrace locked by sherlock.")
    def LOCK_INPUT(event,args):
        if "input" in event:
                print("input")
                raise RuntimeError("Inputs locked by sherlock.")
    def LOCK_EXEC(event,args):
        if "exec" in event:
                print("exec")
                raise RuntimeError("EXEC locked by sherlock.")
    def LOCK_COMPILE(event,args):
        if "compile" in event:
                print("compile")
                raise RuntimeError("Compile locked by sherlock.")
class AUTO_CHECK_FUNCTIONS:
    def CRITICAL_HASHCHECK():
        """not a real function, just a name. PLEASE DO NOT USE!"""
        pass
    def HASHLIST_COMPROMISE():
        """not a real function, just a name. PLEASE DO NOT USE!"""
        pass
    def CHECKSLIST_COMPROMISE():
        """not a real function, just a name. PLEASE DO NOT USE!"""
        pass
    def AUDITLIST_COMPROMISE():
        """not a real function, just a name. PLEASE DO NOT USE!"""
        pass
    def FUNCTION_INTEGRITY(call):
        main_globals = sys.modules["__main__"].__dict__
        hl_copy = HASH_LIST.copy()
        for func in hl_copy:
            if func in CRITICAL:
                continue
            func = unwrap(func)
            stat = rt_integrity_chk(func)
            qualname = unwrap(resolve_qualname(main_globals,func.__qualname__))
            global_stat = True
            if not qualname is None:
                global_stat = rt_integrity_chk(qualname)  #main files globals
                if hasattr(func,"__code__") is True:
                    if not func.__code__ == qualname.__code__:
                        stat = False
                        global_stat = False
                else:
                    if (not func.__module__ == qualname.__module__):
                        stat = False
                        global_stat = False
            if not stat or not global_stat :
                print("> AUTO RTI INTEGRITY COMPROMISED")
                if func == call:
                    print("> CALLBACK FUNCTION COMPROMISED. KILLING PYTHON")
                    os._exit(0xDEAD)
                else:
                    call(AUTO_CHECK_FUNCTIONS.FUNCTION_INTEGRITY)
    def STACK_BEHAVIOR_ANOMALIES(call):
        try:
            original = sys.getrecursionlimit()
            sys.setrecursionlimit(69420)
            if not sys.getrecursionlimit() == 69420:
                print("> STACK BEHAVIOR ANOMALIES DETECTED")
                call(AUTO_CHECK_FUNCTIONS.STACK_BEHAVIOR_ANOMALIES)
            sys.setrecursionlimit(original)
        except:
            print("> STACK BEHAVIOR ANOMALIES DETECTED")
            call(AUTO_CHECK_FUNCTIONS.STACK_BEHAVIOR_ANOMALIES)
    def EXCEPTION_TIMING(call):
        start = time.perf_counter()
        try:
            raise Exception
        except:
            pass
        if time.perf_counter() - start > 0.01:
            print("> EXCEPTION TIMING FAILED")
            call(AUTO_CHECK_FUNCTIONS.EXCEPTION_TIMING)
    def DEBUG_CHECK(call):
        if sys.getprofile() is not None or sys.gettrace() is not None:
            print("> DEBUGGER DETECTED")
            call(AUTO_CHECK_FUNCTIONS.DEBUG_CHECK)
        
        f = sys._getframe
        for _ in range(10):
            if f().f_trace is not None:
                print("> DEBUGGER DETECTED")
                call(AUTO_CHECK_FUNCTIONS.DEBUG_CHECK)
        
        if os.name == "nt":
            if ctypes.windll.kernel32.IsDebuggerPresent():
                print("> DEBUGGER DETECTED")
                call(AUTO_CHECK_FUNCTIONS.DEBUG_CHECK)
            
        if os.name == "posix": 
            with open("/proc/self/status") as f:
                if "TracerPid:\t0" not in f.read():
                    print("> DEBUGGER DETECTED")
                    call(AUTO_CHECK_FUNCTIONS.DEBUG_CHECK)
def resolve_qualname(globalsdict,qualname):
    try:
        parts = qualname.split(".")
        if parts[0] == "<lambda>" or parts[0] == "<locals>":
            return None
        obj = globalsdict[parts[0]]
        if obj is None:
            return None
        for part in parts[1:]:
            if part == "<locals>" or part == "<lambda>":
                return None
            obj = getattr(obj,part,None)
            if obj is None:
                return None
        return obj
    except:
        return None
def fingerprint():
        info = [
            sys.version, 
            sys.implementation.name, # cpython pypy etc
            sys.platform, # win32,linux,darwin
            os.name, # nt /posix
            sys.byteorder, # little / big endian 
            sys.maxsize.bit_length(), # 32bit 64 bit
            sys.executable, # py path
            sys.base_prefix, # venv detection
            os.cpu_count(), #cpu count
            sys.getrecursionlimit(), #stack behavior (debugger shit)
        ]
        os_specific = []
        if os.name == "posix":
            u = os.uname()
            os_specific = [
                u.sysname,
                u.nodename,
                u.release,
                u.version,
                u.machine
            ]
            try:
                os_specific.append(os.getuid()) 
                os_specific.append(os.geteuid())
                os_specific.append(os.getgid())
            except:
                print("Failed to get privilege/sandbox info, might cause problems. Run with sudo!")
        if os.name == "nt":
            try:
                w = sys.getwindowsversion()
                os_specific = [
                    w.major,
                    w.minor,
                    w.build,
                    w.platform,
                    w.platform_version
                ]
            except:
                print("Failed to get win version, might cause problems. Run with admin!")
            
            envs = ["COMPUTERNAME","USERNAME","PROCESSOR_IDENTIFIER","PROCESSOR_ARCHITECTURE","NUMBER_OF_PROCESSORS","SystemRoot","WINDIR"]
            for env in envs:
                os_specific.append(os.environ.get(env))

        
        info.extend(os_specific)
        hash = hashlib.sha256(''.join(map(str, info)).encode()).hexdigest()

        return hash
def check_fingerprint(h):
        hash = fingerprint()
        return hmac.compare_digest(hash,h)
def hmachash(msg,key):
    if type(msg) == bytes and type(key) == bytes:
        return hmac.new(key,msg,hashlib.sha256).hexdigest()
    return hmac.new(key.encode(),msg.encode(),hashlib.sha256).hexdigest()
def unwrap(fn):
    while hasattr(fn,"__wrapped__"):
        fn = fn.__wrapped__
    return fn
def __fn_hash(func):

    try:
        c = func.__code__
        data = (
            c.co_code +
            repr(c.co_consts).encode() +
            repr(c.co_names).encode() +
            repr(c.co_varnames).encode()
        )
        output = hmachash(data,_SECRET.encode())
    except:
        data = (
            repr(func.__module__).encode()+
            repr(func.__name__).encode()
        )
        output = hmachash(data,_SECRET.encode())
    return output
def rt_integrity_chk(func):
    """
    SHERLOCK utility REALTIME FUNCTION BYTECODE INTEGRITY CHECK function.
    Usage: 
        rt_integrity_chk(function)
    Returns:
        True if successful or a new entry has been added to the hashlist
        False if detected integrity compromise.
    """
    global hashlist_hash
    func = unwrap(func)
    if func in HASH_LIST:
        hash_now = __fn_hash(func)
        if not hmac.compare_digest(hash_now,HASH_LIST[func]):
            print("BYTECODE INTEGRITY COMPROMISED.")
            return False
        return True
    else:
        HASH_LIST[func] = __fn_hash(func)
        hashlist_hash = hmachash(''.join(map((lambda x: x.__name__),HASH_LIST)),_SECRET)
        return True
def __autochkloop(call,interval):
    rt_integrity_chk(call)
    global HASH_LIST,__autochkthread,CRITICAL
    while True:
        if __autochkthread.stop:
            break
        
        #CRITICAL CONSTANT CHECK
        critical_hashcheck = constant_hashcheck("critical check list", CRITICAL)
        if not critical_hashcheck:
            print("> critical hashcheck failed")
            call(AUTO_CHECK_FUNCTIONS.CRITICAL_HASHCHECK)

        #HASHLIST AND USER FUNCTIONS HASH CHECK
        if len(HASH_LIST) > 0 and not hmac.compare_digest(hmachash(''.join(map((lambda x: x.__name__),HASH_LIST)),_SECRET), hashlist_hash):
            print("> hashlist compromised")
            call(AUTO_CHECK_FUNCTIONS.HASHLIST_COMPROMISE)
        if len(CHECKS) > 0 and not hmac.compare_digest(hmachash(''.join(map((lambda x: x.__name__),CHECKS)),_SECRET), checks_hash):
            print("> checks compromised")
            call(AUTO_CHECK_FUNCTIONS.CHECKSLIST_COMPROMISE)
        
        #AUDIT HOOK LIST HASHCHECK
        if len(AUDITHOOK_LIST) > 0 and not hmac.compare_digest(hmachash(''.join(map((lambda x: x.__name__),AUDITHOOK_LIST)),_SECRET), audithook_hash):
            print("> audithook compromised")
            call(AUTO_CHECK_FUNCTIONS.AUDITLIST_COMPROMISE)
        

        #CRITICAL FUNCTIONS
        for func in CRITICAL:
            func = unwrap(func)
            stat = rt_integrity_chk(func)
            qualname = unwrap(resolve_qualname(globals(),func.__qualname__))

            global_stat = True
            if not qualname is None:
                global_stat = rt_integrity_chk(qualname) #this files globals  
                if hasattr(func,"__code__") is True:
                    if not func.__code__ == qualname.__code__:
                        stat = False
                        global_stat = False
                else:
                    if (not func.__module__ == qualname.__module__):
                        stat = False
                        global_stat = False
            if not stat or not global_stat:
                print("> CRITICAL FUNCTION INTEGRITY COMPROMISED")
                if func == call:
                    print("> CALLBACK FUNCTION COMPROMISED. KILLING PYTHON")
                    os._exit(0xDEAD)
                else:
                    call(AUTO_CHECK_FUNCTIONS.FUNCTION_INTEGRITY)

        #Settings lock constant
        if "SETTINGS LOCKED FLAG" in CONSTANT_LIST:
            if not constant_hashcheck("SETTINGS LOCKED FLAG", SETTINGS_LOCKED):
                print("> SETTINGS LOCK IS BEING TAMPERED WITH")
                os._exit(0xDEAD)

        #builtins
        if os._exit is not _REAL_EXIT:
            print("> OS._EXIT != FROZEN OS._EXIT")
            _REAL_EXIT(0xDEAD) #hopefully realexit is real

            
            
        if hmac.compare_digest is not _REAL_COMPARE:
            print("> HMAC.COMPARE_DIGEST != FROZEN HMAC.COMPARE_DIGEST")
            os._exit(0xDEAD)

        checks_copy = CHECKS.copy()
        for func in checks_copy:
            func(call)
        time.sleep(interval)
def auto_chk_enable(func,interval = 30):
    if SETTINGS_LOCKED == "SHERLOCK_SETTINGS_LOCKED":
        print("> SETTINGS LOCKED")
        os._exit(0xDEAD)
    global __autochkthread,AUTOCHECK_CONFIG

    if not __autochkthread == None:
        print("CHECK ALREADY RUNNING")
        return False
    AUTOCHECK_CONFIG = []
    AUTOCHECK_CONFIG.append(func)
    AUTOCHECK_CONFIG.append(interval)
    __autochkthread = threading.Thread(target=__autochkloop,args=(func,interval,))
    __autochkthread.stop = False
    __autochkthread.start()
def auto_chk_disable():
    if SETTINGS_LOCKED == "SHERLOCK_SETTINGS_LOCKED":
        print("> SETTINGS LOCKED")
        os._exit(0xDEAD)
    global __autochkthread
    if __autochkthread == None:
        return False
    __autochkthread.stop = True
    __autochkthread.join()
    __autochkthread = None
    return True
def add_auto_check(func):
    if SETTINGS_LOCKED == "SHERLOCK_SETTINGS_LOCKED":
        print("> SETTINGS LOCKED")
        os._exit(0xDEAD)
    global checks_hash
    thread_state = False
    if __autochkthread is not None:
        thread_state = __autochkthread.is_alive()

    if thread_state == True:
        auto_chk_disable()
    CHECKS.append(func)
    checks_hash = hmachash(''.join(map((lambda x: x.__name__),CHECKS)),_SECRET)
    if thread_state == True:
        auto_chk_enable(AUTOCHECK_CONFIG[0],AUTOCHECK_CONFIG[1])
def remove_auto_check(func):
    if SETTINGS_LOCKED == "SHERLOCK_SETTINGS_LOCKED":
        print("> SETTINGS LOCKED")
        os._exit(0xDEAD)
    global checks_hash
    thread_state = False
    if __autochkthread is not None:
        thread_state = __autochkthread.is_alive()

    if thread_state == True:
        auto_chk_disable()
    CHECKS.remove(func)
    checks_hash = hmachash(''.join(map((lambda x: x.__name__),CHECKS)),_SECRET)
    if thread_state == True:
        auto_chk_enable(AUTOCHECK_CONFIG[0],AUTOCHECK_CONFIG[1])
def constant_hashcheck(name,constant):

    if type(constant) == list:
        constant = ''.join(map(str,constant))
    else:
        constant = str(constant)
    if name in CONSTANT_LIST:
        hash_now = hmachash(constant,_SECRET)
        if not hmac.compare_digest(hash_now,CONSTANT_LIST[name]):
            print("> constant compromised")
            return False
        return True
    else:
        CONSTANT_LIST[name] = hmachash(constant,_SECRET)
        return True
def sherlock_guard(fn,integrity_check):
    @functools.wraps(fn)
    def wrapper(*args,**kwargs):
        if not integrity_check(fn):
            print("SHERLOCK CALLSITE INTEGRITY COMPROMISED")
            os._exit(0xDEAD)
            while True:
                pass
        return fn(*args,**kwargs)

    wrapper.__wrapped__ = fn
    return wrapper
def protect_function(fn):
    guarded = sherlock_guard(fn,rt_integrity_chk)
    sys.modules["__main__"].__dict__[fn.__name__] = guarded
def protect_method(cls,name):
    fn = cls.__dict__[name]
    fn = getattr(fn,"__func__",fn)
    wrapped = sherlock_guard(fn,rt_integrity_chk)
    setattr(cls,name,wrapped)




def add_audit_hook(func):
    if SETTINGS_LOCKED == "SHERLOCK_SETTINGS_LOCKED":
        print("> SETTINGS LOCKED")
        os._exit(0xDEAD)
    global audithook_hash
    thread_state = False
    if __autochkthread is not None:
        thread_state = __autochkthread.is_alive()

    if thread_state == True:
        auto_chk_disable()
    AUDITHOOK_LIST.append(func)
    audithook_hash = hmachash(''.join(map((lambda x: x.__name__),AUDITHOOK_LIST)),_SECRET)
    if thread_state == True:
        auto_chk_enable(AUTOCHECK_CONFIG[0],AUTOCHECK_CONFIG[1])
def remove_audit_hook(func):
    if SETTINGS_LOCKED == "SHERLOCK_SETTINGS_LOCKED":
        print("> SETTINGS LOCKED")
        os._exit(0xDEAD)
    global audithook_hash,__autochkthread
    thread_state = False
    if __autochkthread is not None:
        thread_state = __autochkthread.is_alive()

    if thread_state == True:
        auto_chk_disable()
    AUDITHOOK_LIST.remove(func)
    audithook_hash = hmachash(''.join(map((lambda x: x.__name__),AUDITHOOK_LIST)),_SECRET)
    if thread_state == True:
        auto_chk_enable(AUTOCHECK_CONFIG[0],AUTOCHECK_CONFIG[1])

def audithook(event,args):
    ah_copy = AUDITHOOK_LIST.copy()
    for func in ah_copy:
        func(event,args)

def audit_hook_enable():
    if SETTINGS_LOCKED == "SHERLOCK_SETTINGS_LOCKED":
        print("> SETTINGS LOCKED")
        os._exit(0xDEAD)  
    __import__("sys").addaudithook(audithook)


def lock_settings():
    global SETTINGS_LOCKED
    SETTINGS_LOCKED = "SHERLOCK_SETTINGS_LOCKED"   
    constant_hashcheck("SETTINGS LOCKED FLAG", SETTINGS_LOCKED)



CRITICAL=[
          audit_hook_enable,
          audithook,
          __fn_hash,
          rt_integrity_chk,
          AUTO_CHECK_FUNCTIONS.DEBUG_CHECK,
          AUTO_CHECK_FUNCTIONS.EXCEPTION_TIMING,
          AUTO_CHECK_FUNCTIONS.FUNCTION_INTEGRITY,
          AUTO_CHECK_FUNCTIONS.STACK_BEHAVIOR_ANOMALIES,
          hmachash,
          __autochkloop,
          fingerprint,
          check_fingerprint,
          constant_hashcheck,
          protect_function,
          protect_method,
          sherlock_guard,
          auto_chk_enable,
          resolve_qualname,
          unwrap,
          AUDIT_HOOK_FUNCTIONS.LOCK_COMPILE,
          AUDIT_HOOK_FUNCTIONS.LOCK_EXEC,
          AUDIT_HOOK_FUNCTIONS.LOCK_IMPORTS,
          AUDIT_HOOK_FUNCTIONS.LOCK_INPUT,
          AUDIT_HOOK_FUNCTIONS.LOCK_TRACE,
          add_audit_hook,
          remove_audit_hook,
          lock_settings
        ]



print("This application is protected by Sherlock.")