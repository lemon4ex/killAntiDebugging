# killAntiDebugging
一个过iOS应用简单反调试功能的CaptainHook Tweak

# 说明
设备需要越狱

编译后将killAntiDebugging.dylib 和 killAntiDebugging.plist 一起放到DynamicLibraries插件目录

插件被加载后，会hook掉以下方法：
* sysctl
* exit
* ptrace
