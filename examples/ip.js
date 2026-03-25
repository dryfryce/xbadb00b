const base = Process.getModuleByName("libg.so").base;
const target = base.add(14048240);
Interceptor.attach(target, {
  onEnter(args) {
this.a1 = args[0];
  },
  onLeave() {
a1 = this.a1;
port = a1.add(144).readS32();
ptr1 = a1.add(152).readPointer();
ptr2 = ptr1.add(8).readPointer();
ip = ptr2.readUtf8String();
console.log(ip + ":" + port);
  },
});
