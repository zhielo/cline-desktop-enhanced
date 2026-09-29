"use client";

import { desktopClient, isTauriAvailable } from "./desktop-client";

type BrowserRequest = {
	requestId: string;
	browserSessionId: string;
	operation: string;
	payload?: Record<string, unknown>;
};

type CdpResponse = {
	result?: { value?: unknown; description?: string };
	data?: string;
};

async function nativeInvoke<T>(
	command: string,
	args: Record<string, unknown>,
): Promise<T> {
	const { invoke } = await import("@tauri-apps/api/core");
	return invoke<T>(command, args);
}

async function cdp(
	sessionId: string,
	method: string,
	params: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
	return nativeInvoke("built_in_browser_cdp", {
		sessionId,
		method,
		params,
	});
}

function targetExpression(target: unknown): string {
	const encoded = JSON.stringify(target ?? {});
	return `(() => {
		const target = ${encoded};
		const visible = (el) => { const r = el.getBoundingClientRect(); const s = getComputedStyle(el); return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; };
		const nameOf = (el) => (el.getAttribute('aria-label') || el.getAttribute('title') || el.innerText || el.textContent || '').trim();
		let candidates = [];
		if (target.css) candidates = [...document.querySelectorAll(target.css)];
		else if (target.test_id) candidates = [...document.querySelectorAll('[data-testid]')].filter((el) => el.getAttribute('data-testid') === target.test_id);
		else candidates = [...document.querySelectorAll('a,button,input,textarea,select,[role],[contenteditable="true"],summary,label')];
		return candidates.find((el) => {
			if (!visible(el)) return false;
			const role = (el.getAttribute('role') || ({A:'link',BUTTON:'button',INPUT:el.type === 'checkbox' ? 'checkbox' : 'textbox',TEXTAREA:'textbox',SELECT:'combobox'}[el.tagName]) || '').toLowerCase();
			const name = nameOf(el);
			return (!target.role || role === String(target.role).toLowerCase()) && (!target.name || name === target.name || name.includes(target.name)) && (!target.text || name.includes(target.text));
		});
	})()`;
}

async function evaluate(
	sessionId: string,
	expression: string,
	awaitPromise = false,
): Promise<unknown> {
	const response = (await cdp(sessionId, "Runtime.evaluate", {
		expression,
		awaitPromise,
		returnByValue: true,
	})) as CdpResponse;
	if (response.result?.description?.startsWith("Error:")) {
		throw new Error(response.result.description);
	}
	return response.result?.value;
}

function requireTarget(payload: Record<string, unknown>): string {
	return targetExpression(payload.target);
}

async function execute(request: BrowserRequest): Promise<unknown> {
	if (!isTauriAvailable())
		throw new Error("Built-in browser requires the native desktop app");
	const payload = request.payload ?? {};
	const id = request.browserSessionId;
	switch (request.operation) {
		case "start":
			return nativeInvoke("built_in_browser_start", {
				sessionId: id,
				url: String(payload.url ?? "about:blank"),
			});
		case "stop":
			return nativeInvoke("built_in_browser_stop", { sessionId: id });
		case "navigate": {
			const navigation = await cdp(id, "Page.navigate", {
				url: String(payload.url ?? ""),
			});
			await evaluate(
				id,
				"new Promise((resolve) => { if (document.readyState === 'complete') resolve(true); else addEventListener('load', () => resolve(true), {once:true}); setTimeout(() => resolve(false), 15000); })",
				true,
			);
			return navigation;
		}
		case "back":
			return evaluate(id, "history.back(); ({ok:true})");
		case "forward":
			return evaluate(id, "history.forward(); ({ok:true})");
		case "reload":
			return cdp(id, "Page.reload", {});
		case "page_info":
			return evaluate(
				id,
				`(() => {
					const navigation = performance.getEntriesByType('navigation')[0];
					return {
						url: location.href,
						origin: location.origin,
						title: document.title,
						readyState: document.readyState,
						language: document.documentElement.lang || null,
						frames: document.querySelectorAll('iframe').length,
						forms: document.forms.length,
						links: document.links.length,
						resources: performance.getEntriesByType('resource').length,
						loadDurationMs: navigation ? Math.round(navigation.duration) : null,
						storage: {
							localKeys: (() => { try { return localStorage.length; } catch { return null; } })(),
							sessionKeys: (() => { try { return sessionStorage.length; } catch { return null; } })(),
						},
					};
				})()`,
			);
		case "inspect":
			return evaluate(
				id,
				`(() => {
				const limit = ${Math.max(1, Math.min(300, Number(payload.max_nodes ?? 120)))};
				const visible = (el) => { const r=el.getBoundingClientRect(); const s=getComputedStyle(el); return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none'; };
				return {url:location.href,title:document.title,elements:[...document.querySelectorAll('a,button,input,textarea,select,[role],[contenteditable="true"],summary')].filter(visible).slice(0,limit).map((el,index)=>({index,tag:el.tagName.toLowerCase(),role:el.getAttribute('role')||undefined,name:(el.getAttribute('aria-label')||el.getAttribute('title')||el.innerText||el.textContent||'').trim().slice(0,300),type:el.getAttribute('type')||undefined,testId:el.getAttribute('data-testid')||undefined,disabled:el.matches(':disabled,[aria-disabled="true"]')}))};
			})()`,
			);
		case "click":
			return evaluate(
				id,
				`(() => { const el=${requireTarget(payload)}; if(!el) throw new Error('browser target not found'); if(el.matches('input[type="password"]')) throw new Error('password fields cannot be targeted'); const label=(el.innerText||el.textContent||el.getAttribute('aria-label')||'').trim(); if(/purchase|buy|pay|submit|send|publish|delete|remove|confirm|accept|book/i.test(label) && ${payload.confirm_consequential === true ? "false" : "true"}) throw new Error('consequential browser action requires confirm_consequential=true'); el.click(); return {ok:true,label}; })()`,
			);
		case "type":
			return evaluate(
				id,
				`(() => { const el=${requireTarget(payload)}; if(!el) throw new Error('browser target not found'); if(el.matches('input[type="password"]')) throw new Error('password fields cannot be targeted'); el.focus(); ${payload.clear === false ? "" : "if ('value' in el) el.value=''; else el.textContent='';"} const text=${JSON.stringify(String(payload.text ?? ""))}; if('value' in el) el.value += text; else el.textContent += text; el.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText',data:text})); el.dispatchEvent(new Event('change',{bubbles:true})); return {ok:true}; })()`,
			);
		case "select":
			return evaluate(
				id,
				`(() => { const el=${requireTarget(payload)}; if(!el || el.tagName !== 'SELECT') throw new Error('select target not found'); const values=${JSON.stringify(payload.values ?? [])}; [...el.options].forEach((o)=>o.selected=values.includes(o.value)); el.dispatchEvent(new Event('change',{bubbles:true})); return {ok:true,values:[...el.selectedOptions].map(o=>o.value)}; })()`,
			);
		case "check":
			return evaluate(
				id,
				`(() => { const el=${requireTarget(payload)}; if(!el || !('checked' in el)) throw new Error('checkable target not found'); el.checked=${payload.checked === true}; el.dispatchEvent(new Event('input',{bubbles:true})); el.dispatchEvent(new Event('change',{bubbles:true})); return {ok:true,checked:el.checked}; })()`,
			);
		case "wait":
			return evaluate(
				id,
				`new Promise((resolve,reject)=>{ const deadline=Date.now()+${Number(payload.timeout_ms ?? 5000)}; const expected=${JSON.stringify(payload.state ?? "exists")}; const tick=()=>{ const found=Boolean(${requireTarget(payload)}); if((expected==='exists'&&found)||(expected==='gone'&&!found)) return resolve({ok:true,state:expected}); if(Date.now()>deadline) return reject(new Error('browser wait timed out')); setTimeout(tick,100); }; tick(); })`,
				true,
			);
		case "screenshot": {
			const response = (await cdp(id, "Page.captureScreenshot", {
				format: "png",
				fromSurface: true,
			})) as CdpResponse;
			return { mediaType: "image/png", dataBase64: response.data };
		}
		default:
			throw new Error(
				`Unsupported built-in browser operation: ${request.operation}`,
			);
	}
}

export function watchBuiltInBrowser(): () => void {
	return desktopClient.subscribe("browser_command_requested", (payload) => {
		const request = payload as BrowserRequest;
		void execute(request)
			.then((result) =>
				desktopClient.invoke("browser_command_result", {
					request_id: request.requestId,
					result,
				}),
			)
			.catch((error) =>
				desktopClient.invoke("browser_command_result", {
					request_id: request.requestId,
					error: error instanceof Error ? error.message : String(error),
				}),
			);
	});
}
