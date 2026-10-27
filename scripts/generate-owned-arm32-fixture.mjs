// Deterministic project-owned ARM EABI5 ELF. Static bytes only; never executed.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
const names=Buffer.from("\0.text\0.shstrtab\0.strtab\0.symtab\0"), strings=Buffer.from("\0owned_cline_fixture\0");
const codeOffset=128,namesOffset=136,stringsOffset=namesOffset+names.length;
const symbolsOffset=Math.ceil((stringsOffset+strings.length)/4)*4,sectionsOffset=symbolsOffset+32;
const bytes=Buffer.alloc(sectionsOffset+5*40);
const u16=(o,v)=>bytes.writeUInt16LE(v,o),u32=(o,v)=>bytes.writeUInt32LE(v,o);
bytes.set([0x7f,69,76,70,1,1,1],0);
u16(16,3);u16(18,40);u32(20,1);u32(24,0x1000);u32(28,52);u32(32,sectionsOffset);u32(36,0x05000000);
u16(40,52);u16(42,32);u16(44,1);u16(46,40);u16(48,5);u16(50,2);
u32(52,1);u32(56,0);u32(60,0xf80);u32(64,0xf80);u32(68,136);u32(72,136);u32(76,5);u32(80,128);
// mov r0,#7; bx lr (ARM mode, not Thumb).
bytes.set([7,0,0xa0,0xe3,0x1e,0xff,0x2f,0xe1],codeOffset);names.copy(bytes,namesOffset);strings.copy(bytes,stringsOffset);
u32(symbolsOffset+16,1);u32(symbolsOffset+20,0x1000);u32(symbolsOffset+24,8);bytes[symbolsOffset+28]=0x12;u16(symbolsOffset+30,1);
function section(i,n,t,f,a,o,s,link=0,info=0,align=1,entry=0){const p=sectionsOffset+i*40;[n,t,f,a,o,s,link,info,align,entry].forEach((v,j)=>u32(p+j*4,v));}
section(1,1,1,6,0x1000,codeOffset,8,0,0,4);section(2,7,3,0,0,namesOffset,names.length);section(3,17,3,0,0,stringsOffset,strings.length);section(4,25,2,0,0,symbolsOffset,32,3,1,4,16);
const fixture={schemaVersion:1,architecture:"arm32",functionAddress:"0x1000",functionSymbol:"owned_cline_fixture",sha256:createHash("sha256").update(bytes).digest("hex"),base64:bytes.toString("base64"),scope:"Fixed project-owned ARM32 return-7 ELF; static decompilation only, never target execution"};
const output=new URL("./fixtures/owned-arm32-elf.json",import.meta.url),text=JSON.stringify(fixture,null,2)+"\n";
if(process.argv.includes("--check")){if(readFileSync(output,"utf8")!==text)throw new Error("Owned ARM32 fixture differs from deterministic source");}else writeFileSync(output,text);
