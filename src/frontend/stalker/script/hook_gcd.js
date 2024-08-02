function hookNSLog(){
    if (ObjC.available) {
        // Hook NSLog function
        var NSLog = new NativeFunction(
            Module.findExportByName(null, 'NSLog'),
            'void',
            ['pointer']
        );

        Interceptor.attach(NSLog, {
            onEnter: function (args) {
                // Convert the first argument from a pointer to an NSString
                var message = new ObjC.Object(args[0]);
                console.log("NSLog message: " + message.toString());
                            // Print stack trace
                console.log("Backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join("\n"));
                // Optionally, modify the message
                // var newMessage = ObjC.classes.NSString.stringWithString_("Modified message");
                // args[0] = newMessage;
            }
        });
    } else {
        console.log("Objective-C Runtime is not available!");
}
    
}

function hookDispatch(){
    // hook_dispatch_async.js
    var GCDModule = Process.getModuleByName("GCDRev");
    console.log("GCDModule Base is :",GCDModule.base);
    var target_block_addr = GCDModule.base.add("0xC200");
    if (ObjC.available) {
        console.log("dispatch_async addr is :" ,Module.findExportByName("libdispatch.dylib", "dispatch_async") );
        // Hook dispatch_async function
        var dispatch_async = new NativeFunction(
            //Module.findExportByName("libdispatch.dylib", "_dispatch_async"),
            GCDModule.base.add(0x7F6C),
            'void',
            ['pointer', 'pointer']
        );
        Interceptor.attach(dispatch_async, {
            onEnter: function (args) {
                if(ptr(args[1]).equals(target_block_addr)){
                    console.log("dispatch_async called with queue: " + args[0] + ", block: " + args[1]);
                    console.log("Backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join("\n"));
                }
                console.log("dispatch_async called");
                    
                // Optionally, you can add more detailed information about the queue and block
                // if you have additional context or use other Frida APIs to inspect these objects
            }
        });

    } else {
        console.log("Objective-C Runtime is not available!");
    }

}

function my_stalkerTraceRange(module_start, module_end) {
    Stalker.follow(Process.getCurrentThreadId(), {
        transform: (iterator) => {
            let instruction = iterator.next();
            var startAddress = instruction.address;
            var is_module_code = startAddress.compare(module_start) >= 0 &&
                startAddress.compare(module_end) < 0;
            do {
                iterator.keep();
                if (is_module_code) {
                    // console.log(startAddress, instruction);
                    iterator.putCallout(function (context) {
                        var pc = context.pc;
                        //var regs_map = formatArm64Regs(context);
                        var module = Process.findModuleByAddress(pc);
                        if (module) {
                            var curInstruction = Instruction.parse(ptr(pc));
                            var instruction_json_object = JSON.parse(JSON.stringify(curInstruction));
                            instruction_json_object["context"] = context;
                            console.log(JSON.stringify(instruction_json_object));
                            //explore next insn
                            let next_pc = context.pc.add(4);
                            let nextInstruction = Instruction.parse(next_pc);
                            let mnemonic = nextInstruction.mnemonic;
                            if (mnemonic.startsWith("b.") || mnemonic === "b" || mnemonic === "bl" || mnemonic === "br" ||  mnemonic === "bx" || mnemonic.startsWith("bl") || mnemonic.startsWith("bx")) {
                                //处理跳转指令
                                instruction_json_object = JSON.parse(JSON.stringify(nextInstruction));
                                instruction_json_object["context"] = context;
                                var symbol = DebugSymbol.fromAddress(nextInstruction["operands"][""]);
                                instruction_json_object["extra"] = {"symbol":symbol}
                                console.log(JSON.stringify(instruction_json_object));
                            }

                            

                        }
                    });
                }
                
            } while ((instruction = iterator.next()) !== null);
        }
    }); 
}

function testTrace(){
        // hook_dispatch_async.js
        var GCDModule = Process.getModuleByName("GCDRev");
        console.log("GCDModule Base is :",GCDModule.base);

        var module_start = GCDModule.base.add(0x4054);
        var module_end = GCDModule.base.add(0x40F8);
        if (ObjC.available) {
            // Hook dispatch_async function
            var clickButton_func = new NativeFunction(
                //Module.findExportByName("libdispatch.dylib", "_dispatch_async"),
                module_start,
                'void',
                ['pointer', 'pointer']
            );
            Interceptor.attach(clickButton_func, {
                onEnter: function (args) {
                    my_stalkerTraceRange(module_start,module_end);
                },
                onLeave: function(retval){
                    Stalker.unfollow(Process.getCurrentThreadId());
                }
            });
    
        } else {
            console.log("Objective-C Runtime is not available!");
        }
}



//setImmediate(hookNSLog);
setImmediate(testTrace);