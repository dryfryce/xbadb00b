const base = Process.getModuleByName("libg.so").base;
const malloc = new NativeFunction(Process.getModuleByName("libc.so").getExportByName("malloc"), "pointer", ["uint"]);
const stringCtor = new NativeFunction(base.add(13595784), "pointer", ["pointer", "pointer"]);
const GUI_getInstance = new NativeFunction(base.add(5540072), "pointer", []);
const generic_Popup = new NativeFunction(base.add(6658816), "pointer", ["pointer", "pointer", "char", "char", "pointer", "pointer", "pointer", "pointer", "pointer"]);
const GUI_addPopup = new NativeFunction(base.add(5545744), "pointer", ["pointer", "pointer", "char", "char", "char"]);
function scptr(str) {
  obj = malloc(16);
  stringCtor(obj, Memory.allocUtf8String(str));
  return obj;
}
function showGenericPopup() {
  popup = malloc(512);
  generic_Popup(popup, scptr(""), 0, 0, scptr(""), scptr(""), scptr(""), scptr(""), scptr(""));
  GUI_addPopup(GUI_getInstance(), popup, 1, 0, 1);
}
showGenericPopup();
