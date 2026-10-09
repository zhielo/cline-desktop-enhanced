// Deterministic project-owned ELF fixture. Static bytes only; never executed.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
const name = "owned_cline_fixture";
const names = Buffer.from("\0.text\0.shstrtab\0.strtab\0.symtab\0");
const strings = Buffer.from(`\0${name}\0`);
const codeOffset = 128, namesOffset = 136, stringsOffset = namesOffset + names.length;
const symbolsOffset = Math.ceil((stringsOffset + strings.length) / 8) * 8;
const sectionsOffset = symbolsOffset + 48;
const bytes = Buffer.alloc(sectionsOffset + 5 * 64);
const u16 = (o,v) => bytes.writeUInt16LE(v,o);
const u32 = (o,v) => bytes.writeUInt32LE(v,o);
const u64 = (o,v) => bytes.writeBigUInt64LE(BigInt(v),o);
bytes.set([0x7f,69,76,70,2,1,1],0);
u16(16,3);u16(18,183);u32(20,1);u64(24,0x1000);u64(32,64);u64(40,sectionsOffset);
u16(52,64);u16(54,56);u16(56,1);u16(58,64);u16(60,5);u16(62,2);
u32(64,1);u32(68,5);u64(72,0);u64(80,0xf80);u64(88,0xf80);u64(96,136);u64(104,136);u64(112,128);
// mov w0,#7; ret — fixed inert owned return function, not application code.
bytes.set([0xe0,0x00,0x80,0x52,0xc0,0x03,0x5f,0xd6],codeOffset);
names.copy(bytes,namesOffset);strings.copy(bytes,stringsOffset);
u32(symbolsOffset+24,1);bytes[symbolsOffset+28]=0x12;u16(symbolsOffset+30,1);u64(symbolsOffset+32,0x1000);u64(symbolsOffset+40,8);
function section(i,n,t,f,a,o,s,link=0,info=0,align=1,entry=0) {
 const p=sectionsOffset+i*64;u32(p,n);u32(p+4,t);u64(p+8,f);u64(p+16,a);u64(p+24,o);u64(p+32,s);u32(p+40,link);u32(p+44,info);u64(p+48,align);u64(p+56,entry);
}
section(1,1,1,6,0x1000,codeOffset,8,0,0,4);
section(2,7,3,0,0,namesOffset,names.length);
section(3,17,3,0,0,stringsOffset,strings.length);
section(4,25,2,0,0,symbolsOffset,48,3,1,8,24);
const fixture={schemaVersion:1,architecture:"arm64",functionAddress:"0x1000",functionSymbol:name,sha256:createHash("sha256").update(bytes).digest("hex"),base64:bytes.toString("base64"),scope:"Fixed project-owned ARM64 return-7 ELF; static decompilation only, never target execution"};
const output=new URL("./fixtures/owned-arm64-elf.json",import.meta.url);
const text=JSON.stringify(fixture,null,2)+"\n";
if(process.argv.includes("--check")) {
 if(readFileSync(output,"utf8")!==text) throw new Error("Owned ARM64 fixture differs from deterministic source");
} else writeFileSync(output,text);
