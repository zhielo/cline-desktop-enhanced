import { expect, it } from "vitest";
import { startOwnedTriageModel } from "../../../vscode/scripts/owned-triage-model";

it("owned model exercises standard chat completions and refuses fake engine success", async () => {
	const model = await startOwnedTriageModel();
	try {
		const response = await fetch(model.baseUrl + "/chat/completions", {
			method: "POST",
			body: JSON.stringify({ model: "owned", messages: [], stream: false }),
		});
		const result = (await response.json()) as {
			choices: Array<{
				message: {
					tool_calls: Array<{ function: { name: string; arguments: string } }>;
				};
			}>;
		};
		const tool = result.choices[0].message.tool_calls[0];
		expect(tool.function.name).toBe("reverse_engineer");
		expect(JSON.parse(tool.function.arguments).target).toBe(
			"owned-ai-triage.exe",
		);
		expect(
			JSON.parse(tool.function.arguments).advanced_options.binary_triage
				.operation,
		).toBe("inspect_binary");
		const stream = await fetch(model.baseUrl + "/chat/completions", {
			method: "POST",
			body: JSON.stringify({ model: "owned", messages: [], stream: true }),
		});
		expect(await stream.text()).toContain('"finish_reason":"tool_calls"');
		const failed = await fetch(model.baseUrl + "/chat/completions", {
			method: "POST",
			body: JSON.stringify({
				model: "owned",
				messages: [
					{
						role: "tool",
						content: JSON.stringify({
							status: "failed",
							operation: "inspect_binary",
							diagnostic: "r2-inspect:ValueError",
						}),
					},
				],
			}),
		});
		expect(failed.status).toBe(500);
		expect(model.error?.message).toContain("failed or incomplete");
		expect(model.error?.message).toContain("r2-inspect:ValueError");
	} finally {
		await model.close();
	}
});

it("real provider adapter parses the owned SSE tool call and serializes saved tool results", async () => {
	const { createGateway } = await import("@cline/llms");
	const { createReverseEngineeringTool } = await import("@cline/core");
	const model = await startOwnedTriageModel();
	try {
		const config = {
			providerId: "openai-compatible",
			apiKey: "owned",
			baseUrl: model.baseUrl,
		};
		const provider = createGateway({ providerConfigs: [config] });
		const info = {
			id: "gpt-4o",
			providerId: "openai-compatible",
			name: "gpt-4o",
		};
		const tool = createReverseEngineeringTool(async () => "not executed");
		const messages: any[] = [
			{
				id: "user",
				role: "user",
				content: [{ type: "text", text: "Owned triage" }],
				createdAt: new Date(),
			},
		];
		async function turn() {
			const events: any[] = [];
			for await (const e of await provider.stream({
				providerId: config.providerId,
				modelId: info.id,
				messages,
				tools: [tool],
			} as never))
				events.push(e);
			return events;
		}
		const first = await turn();
		const call = first.find((e) => e.type === "tool-call-delta" && e.input);
		expect(call?.toolName).toBe("reverse_engineer");
		expect(call?.input.advanced_options.binary_triage.operation).toBe(
			"inspect_binary",
		);
		messages.push({
			id: "assistant",
			role: "assistant",
			createdAt: new Date(),
			content: [
				{
					type: "tool-call",
					toolCallId: call.toolCallId,
					toolName: call.toolName,
					input: call.input,
				},
			],
		});
		messages.push({
			id: "tool",
			role: "tool",
			createdAt: new Date(),
			content: [
				{
					type: "tool-result",
					toolCallId: call.toolCallId,
					toolName: call.toolName,
					output: JSON.stringify({
						status: "completed",
						receiptId: "owned",
						targetSha256: "a".repeat(64),
						operation: "inspect_binary",
						text: "{}",
					}),
				},
			],
		});
		const second = await turn();
		expect(
			second.find((e) => e.type === "tool-call-delta" && e.input)?.input
				.advanced_options.binary_triage.operation,
		).toBe("list_functions");
		expect(model.error).toBeUndefined();
	} finally {
		await model.close();
	}
});

it("queues the installed AI turn without waiting for approvals and rejects missing acknowledgement", async () => {
	const { enqueueOwnedTriageTurn } = await import(
		"../../../vscode/scripts/owned-triage-model"
	);
	const requests: unknown[] = [];
	await enqueueOwnedTriageTurn(async (request) => {
		requests.push(request);
		return { queued: true };
	}, "owned-session");
	expect(requests).toEqual([
		expect.objectContaining({
			action: "send",
			sessionId: "owned-session",
			delivery: "queue",
		}),
	]);
	await expect(
		enqueueOwnedTriageTurn(async () => ({}), "owned-session"),
	).rejects.toThrow("not acknowledged");
});

it.each([
	"addr",
	"offset",
])("uses saved radare2 %s for exact selected disassembly without rerunning listing", async (field) => {
	const model = await startOwnedTriageModel();
	try {
		const messages = ["inspect_binary", "list_functions"].map(
			(operation, i) => ({
				role: "tool",
				content: JSON.stringify({
					status: "completed",
					receiptId: `owned-${i}`,
					targetSha256: "a".repeat(64),
					operation,
					text:
						operation === "list_functions"
							? `{"engine":"radare2","data":[{"${field}":5368713216,"name":"entry0"}]}`
							: "{}",
				}),
			}),
		);
		const response = await fetch(`${model.baseUrl}/chat/completions`, {
			method: "POST",
			body: JSON.stringify({ model: "owned", messages, stream: false }),
		});
		expect(response.status).toBe(200);
		const result = (await response.json()) as {
			choices: Array<{
				message: { tool_calls: Array<{ function: { arguments: string } }> };
			}>;
		};
		const call = JSON.parse(
			result.choices[0].message.tool_calls[0].function.arguments,
		);
		expect(call.advanced_options.binary_triage).toMatchObject({
			action: "run",
			operation: "get_function_disassembly",
			address: "0x140001000",
		});
		expect(model.results).toHaveLength(2);
		expect(model.error).toBeUndefined();
	} finally {
		await model.close();
	}
});

it("captures only declared HTTP function names while allowing the optional tools field to be absent", async () => {
 const model=await startOwnedTriageModel();
 try {
  const response=await fetch(`${model.baseUrl}/chat/completions`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({model:'owned',messages:[],stream:false,tools:[{type:'function',function:{name:'reverse_engineer',description:'PRIVATE',parameters:{private:'SECRET'}}}]})});
  expect(response.status).toBe(200);expect(model.lastToolNames).toEqual(['reverse_engineer']);
  const names=model.lastToolNames;names.push('forged');expect(model.lastToolNames).toEqual(['reverse_engineer']);
  const ordinary=await fetch(`${model.baseUrl}/chat/completions`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({model:'owned',messages:[],stream:false})});
  expect(ordinary.status).toBe(200);expect(model.lastToolNames).toEqual([]);expect(model.providerRequests).toBe(2);
 }finally{await model.close();}
});
