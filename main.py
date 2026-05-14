import sherlock


def sherlock_callback(func):
    print("Callback called from function:", func.__name__)
    sherlock.os._exit(0xDEAD)


def do_shit(i):
    sherlock.time.sleep(1)
    print(i)


def main():
    global sherlock_callback,main,do_shit
    #register functions into rt auto check. VERY IMPORTANT! NOT DOING THIS WILL LET AN ATTACKER MODIFY YOUR CALLBACKS!
    sherlock.rt_integrity_chk(main) 
    sherlock.rt_integrity_chk(sherlock_callback)

    #wrap function with RT INTEGRITY CHECK to prevent specific attacs
    sherlock.protect_function(do_shit)
    
    #auto checks
    #automatic checks, starts a thread in background and runs specified tests. If failed, calls a callback function specified by the user.
    sherlock.add_auto_check(sherlock.AUTO_CHECK_FUNCTIONS.FUNCTION_INTEGRITY) # checks bytecodes of registered functions
    sherlock.add_auto_check(sherlock.AUTO_CHECK_FUNCTIONS.EXCEPTION_TIMING) # checks exception timing. If the exception takes long, it is proven that a debugger is attached. 
    sherlock.add_auto_check(sherlock.AUTO_CHECK_FUNCTIONS.STACK_BEHAVIOR_ANOMALIES) # checks if recursion limit can be changed, it is often that debuggers lock this.
    #sherlock.add_auto_check(sherlock.AUTO_CHECK_FUNCTIONS.DEBUG_CHECK) # checks for debuggers. might not see some debuggers.
    # you can also add custom auto check functions!
    def my_autocheck(callback): #callback here being a function from sherlock.AUTO_CHECK_FUNCTIONS
        pass
    sherlock.add_auto_check(my_autocheck)

    #audit hook
    #used for making python debuggers unstable, or prevent malicious code running by locking exec/compile.
    sherlock.add_audit_hook(sherlock.AUDIT_HOOK_FUNCTIONS.LOCK_IMPORTS) # locks the "import" functionality. After enabling, importing libraries will result in a runtimeerror exception
    #sherlock.add_audit_hook(sherlock.AUDIT_HOOK_FUNCTIONS.LOCK_EXEC) # locks the "exec" builtin function. After enabling, using exec function will result in a runtimeerror exception
    #sherlock.add_audit_hook(sherlock.AUDIT_HOOK_FUNCTIONS.LOCK_COMPILE) # locks the "compile" builtin function. After enabling, using compile function will result in a runtimeerror exception
    sherlock.add_audit_hook(sherlock.AUDIT_HOOK_FUNCTIONS.LOCK_INPUT)# locks the "input" builtin function. After enabling, using input function will result in a runtimeerror exception
    #sherlock.add_audit_hook(sherlock.AUDIT_HOOK_FUNCTIONS.LOCK_TRACE) # locks the "sys.settrace" function. After enabling, trying to settrace will result in a runtimeerror exception
    # you can also add custom audithook functions! below is an example of a PDB detector. But enabling the audithook features listed above already makes PDB unusable. (EXEC AND COMPILE IS ENOUGH!)
    def my_audithook(event,args):
        if "input" in event:
            if '(Pdb) ' in args:
                raise RuntimeError("Detected PDB(pythondebugger) !!!")
    sherlock.add_audit_hook(my_audithook)

    #dont forget to add to RTI check! Not required. It just adds them to the Real Time Integrity Check Loop.
    sherlock.rt_integrity_chk(my_audithook)
    sherlock.rt_integrity_chk(my_autocheck)

    #enable features
    sherlock.audit_hook_enable()
    sherlock.auto_chk_enable(sherlock_callback,interval=1)

    #Note it is recommended to NOT enable AUTO_CHK before all the features needed are added. Stopping the auto_chk thread takes time, and will make your app lag significantly while adding features.
    #But if you must enable AUTO_CHK before features are added, use the auto_chk_disable before and auto_chk_enable after the adding of features.

    #As a final step, we lock the settings, so attackers can not call disable functions or tamper with our settings.
    sherlock.lock_settings()
    #BUT, IF YOU USE THIS, YOU CAN NOT TOGGLE ANY SETTING LIKE:
    #RTI CHECKS,
    #AUDITHOOKS AFTER THIS LINE!

    #Sherlock provides a way to check if constants have been tampered with. 
    MY_CONSTANT = "Hello, world!"
    stat = sherlock.constant_hashcheck("myconstant",MY_CONSTANT)
    print(stat) #Prints true, as in constant is NOT compromised.

    MY_CONSTANT = "dawg" # Simulate compromising a constant
    stat = sherlock.constant_hashcheck("myconstant",MY_CONSTANT)
    print(stat) #Prints false, as in constant is compromised.


    i = 0
    while True:
        do_shit(i)
        i += 1


main()