import { createHash } from "node:crypto";
import type { SourceArtifact } from "../parser";
export function ownedSource(path: string, source: string): SourceArtifact {
	return {
		path,
		source,
		bytes: Buffer.byteLength(source),
		sha256: createHash("sha256").update(source).digest("hex"),
	};
}
export function ownedApplication(version = 1): SourceArtifact[] {
	return [
		ownedSource(
			"package.json",
			JSON.stringify({
				name: "owned-application",
				main: "main.cjs",
				version: "1.0.0",
			}),
		),
		ownedSource(
			"main.cjs",
			`const {BrowserWindow,ipcMain}=require('electron');const {add}=require('./api.cjs');const win=new BrowserWindow({webPreferences:{preload:__dirname+'/preload.cjs'}});win.loadFile('index.html');ipcMain.handle('owned:add',(_event,value)=>add(value));throw new Error('MUST_NOT_EXECUTE');`,
		),
		ownedSource(
			"api.cjs",
			`exports.add=function(value){return {count:value+${version}}};`,
		),
		ownedSource(
			"preload.cjs",
			`const {contextBridge,ipcRenderer}=require('electron');contextBridge.exposeInMainWorld('owned',{add:(value)=>ipcRenderer.invoke('owned:add',value)});`,
		),
		ownedSource(
			"index.html",
			`<!doctype html><script src="renderer.js"></script>`,
		),
		ownedSource(
			"renderer.js",
			`window.owned.add(41);fetch('https://owned.invalid/api');`,
		),
	];
}
