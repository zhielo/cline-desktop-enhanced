use emulator::{AndroidEmulator,UnicornArg};
use emulator::android::dvm::class_resolver::ClassResolver;
use std::{env,fs};
fn main(){
 let a:Vec<String>=env::args().skip(1).collect();if a.len()!=8 {panic!("fixed arguments required")}
 std::env::set_var("BASE_PATH", &a[1]);
 let e=AndroidEmulator::new(1000,1000,"cline.approved.native".to_string(),()).expect("emulator init");
 let count=std::rc::Rc::new(std::cell::Cell::new(0u64));
 let c=count.clone();let limit:u64=a[7].parse().expect("instruction bound");
 let emulator::Backend::Unicorn(u)=&e.backend;
 u.add_code_hook(1,0,move |u,address,_size| {
  c.set(c.get()+1);
  let x=u.mem_read_as_vec(address,4).expect("instruction read");let w=u32::from_le_bytes(x.try_into().unwrap());
  if c.get()>limit {std::process::exit(75);}
  if w==0xd4000001 {std::process::exit(76);}
 }).expect("fixed guard");
 let vm=e.get_dalvik_vm();vm.set_class_resolver(ClassResolver::new(vec![&a[3]]));
 let module=vm.load_library(e.clone(),&a[0],true).expect("library/dependency unsupported");
 let m=unsafe{&*module.get()};vm.call_jni_onload(e.clone(),m).expect("JNI_OnLoad unsupported");
 let value=if a[2]=="jni-int32" {
  let (class_id,_)=vm.resolve_class(&a[3]).expect("class unsupported");
  let symbol=format!("Java_{}_{}",a[3].replace('/',"_"),a[4]);
  let f=m.find_symbol_by_name(&symbol,false).expect("exact JNI export missing");
  let argument:i32=a[5].parse().expect("int32");
  Some(f.call(&e,vec![UnicornArg::Ptr(vm.java_env),UnicornArg::I64(class_id),UnicornArg::I32(argument)]).expect("JNI call incomplete") as i32)
 }else if a[2]=="initialize"{None}else{panic!("unsupported scenario")};
 let result=serde_json::json!({"initialized":true,"instructionCount":count.get(),"returnValue":value,"backend":"pinned-unicorn-fork"});
 let mut out=fs::OpenOptions::new().write(true).create_new(true).open(&a[6]).expect("new result only");
 use std::io::Write;out.write_all(result.to_string().as_bytes()).expect("write evidence");e.destroy();
}
