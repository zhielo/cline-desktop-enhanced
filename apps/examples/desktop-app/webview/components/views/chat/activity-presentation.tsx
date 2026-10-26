"use client";
import {
	createContext,
	useCallback,
	useContext,
	useState,
	type ReactNode,
} from "react";

type DisclosureStore = {
	values: ReadonlyMap<string, boolean>;
	set: (key: string, value: boolean) => void;
};
const Context = createContext<DisclosureStore | null>(null);
/** Ephemeral, bounded, session-owned presentation only. Never persist transcript/credentials. */
export function ActivityPresentationProvider({
	children,
}: {
	children: ReactNode;
}) {
	const [values, setValues] = useState<ReadonlyMap<string, boolean>>(
		() => new Map(),
	);
	const set = useCallback(
		(key: string, value: boolean) =>
			setValues((previous) => {
				const next = new Map(previous);
				next.delete(key);
				next.set(key, value);
				while (next.size > 512) next.delete(next.keys().next().value!);
				return next;
			}),
		[],
	);
	return (
		<Context.Provider value={{ values, set }}>{children}</Context.Provider>
	);
}
export function useActivityDisclosure(
	session: string | null | undefined,
	id: string,
	defaultOpen = false,
) {
	const store = useContext(Context);
	const [local, setLocal] = useState<boolean | undefined>();
	const key = JSON.stringify([session ?? "draft", id]);
	const explicit = store ? store.values.get(key) : local;
	const set = useCallback(
		(value: boolean) => {
			if (store) store.set(key, value);
			else setLocal(value);
		},
		[store, key],
	);
	return [explicit ?? defaultOpen, set, explicit !== undefined] as const;
}
